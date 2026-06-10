#include "rmtls_threshold_mlkem/sharing.hpp"

#include <array>
#include <cerrno>
#include <cstddef>
#include <limits>
#include <set>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#elif defined(__linux__)
#include <sys/random.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <cstdlib>
#else
#error "Shamir23 secure sharing requires an operating-system CSPRNG implementation"
#endif

namespace rmtls {
namespace {

template <class T>
class ScopedErase {
public:
    T value{};
    ~ScopedErase() { detail::erase_value(value); }
};

void require_party_id(PartyId party) {
    if (party.value < 1 || party.value > 3) {
        throw PrototypeError("party identifier outside fixed profile");
    }
}

void require_canonical_coefficients(const CoeffVector& coeffs) {
    for (Coeff coeff : coeffs) {
        if (coeff >= Q) {
            throw PrototypeError("coefficient outside Z_q");
        }
    }
}

void require_mlkem512_key_state(const CoeffVector& coeffs) {
    if (coeffs.size() != MLKEM512_S_HAT_COEFFICIENTS) {
        throw PrototypeError("key state shape mismatch");
    }
    require_canonical_coefficients(coeffs);
}

void require_share_context(const ShareContext& context) {
    if (context.service_kem_fingerprint.empty() ||
        context.threshold_key_id.empty() ||
        context.assistant_epoch.empty() ||
        context.adapter_profile_id.empty()) {
        throw PrototypeError("share context is incomplete");
    }
}

void fill_secure_random(std::uint8_t* output, std::size_t length) {
#if defined(_WIN32)
    if (length > static_cast<std::size_t>(std::numeric_limits<ULONG>::max())) {
        throw PrototypeError("secure random request is too large");
    }
    const NTSTATUS status = BCryptGenRandom(
        nullptr, output, static_cast<ULONG>(length), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) {
        throw PrototypeError("operating-system random generation failed");
    }
#elif defined(__linux__)
    std::size_t offset = 0;
    while (offset < length) {
        const ssize_t received = getrandom(output + offset, length - offset, 0);
        if (received > 0) {
            offset += static_cast<std::size_t>(received);
            continue;
        }
        if (received < 0 && errno == EINTR) {
            continue;
        }
        throw PrototypeError("operating-system random generation failed");
    }
#else
    arc4random_buf(output, length);
#endif
}

Coeff secure_random_coeff() {
    constexpr std::uint32_t range = std::uint32_t{1} << 16;
    constexpr std::uint32_t accepted = (range / Q) * Q;

    for (;;) {
        ScopedErase<std::array<std::uint8_t, 2>> bytes;
        fill_secure_random(bytes.value.data(), bytes.value.size());
        ScopedErase<std::uint32_t> candidate;
        candidate.value =
            static_cast<std::uint32_t>(bytes.value[0]) |
            (static_cast<std::uint32_t>(bytes.value[1]) << 8);
        if (candidate.value < accepted) {
            return static_cast<Coeff>(candidate.value % Q);
        }
    }
}

ShareSetId secure_random_share_set_id() {
    ShareSetId id{};
    fill_secure_random(id.data(), id.size());
    return id;
}

} // namespace

Coeff add_q(Coeff a, Coeff b) { return mod_q(static_cast<int>(a) + static_cast<int>(b)); }
Coeff sub_q(Coeff a, Coeff b) { return mod_q(static_cast<int>(a) - static_cast<int>(b)); }
Coeff mul_q(Coeff a, Coeff b) { return static_cast<Coeff>((static_cast<std::uint32_t>(a) * b) % Q); }

Coeff inv_q(Coeff a) {
    if (a == 0) throw PrototypeError("inverse of zero mod q");
    int t = 0, new_t = 1;
    int r = Q, new_r = a;
    while (new_r != 0) {
        int quotient = r / new_r;
        int tmp_t = t - quotient * new_t;
        t = new_t;
        new_t = tmp_t;
        int tmp_r = r - quotient * new_r;
        r = new_r;
        new_r = tmp_r;
    }
    if (r > 1) throw PrototypeError("element not invertible mod q");
    return mod_q(t);
}

Coeff lagrange_at_zero(PartyId i, const std::vector<PartyId>& active) {
    require_party_id(i);
    if (active.size() != 2) {
        throw PrototypeError("fixed profile requires exactly two parties");
    }

    std::set<int> unique_parties;
    for (PartyId party : active) {
        require_party_id(party);
        unique_parties.insert(party.value);
    }
    if (unique_parties.size() != active.size() || !unique_parties.contains(i.value)) {
        throw PrototypeError("party set is inconsistent");
    }

    Coeff num = 1;
    Coeff den = 1;
    for (auto j : active) {
        if (j == i) continue;
        num = mul_q(num, mod_q(-j.value));
        den = mul_q(den, mod_q(i.value - j.value));
    }
    return mul_q(num, inv_q(den));
}

ShareMap Shamir23::share(const CoeffVector& secret,
                         const ShareContext& context) {
    require_mlkem512_key_state(secret);
    require_share_context(context);
    const ShareSetId share_set_id = secure_random_share_set_id();

    ShareMap out;
    for (int party = 1; party <= 3; ++party) {
        out.shares_.emplace(
            PartyId{party},
            ShareVector{
                PartyId{party},
                context,
                share_set_id,
                CoeffVector(secret.size(), 0),
            });
    }
    for (std::size_t idx = 0; idx < secret.size(); ++idx) {
        ScopedErase<Coeff> slope;
        slope.value = secure_random_coeff();
        for (int party = 1; party <= 3; ++party) {
            out.shares_.at({party}).coeffs_.value_[idx] =
                add_q(
                    secret[idx],
                    mul_q(slope.value, static_cast<Coeff>(party)));
        }
    }
    return out;
}

ShareMap Shamir23::share_and_erase(Secret<CoeffVector>& secret,
                                   const ShareContext& context) {
    try {
        ShareMap shares = share(secret.value_, context);
        secret.erase_internal();
        return shares;
    } catch (...) {
        secret.erase_internal();
        throw;
    }
}

Secret<CoeffVector> Shamir23::reconstruct_values(
    const std::array<PartyId, 2>& parties,
    const std::array<ShareSetId, 2>& share_set_ids,
    const std::array<
        std::reference_wrapper<const Secret<CoeffVector>>,
        2>& values) {
    for (PartyId party : parties) {
        require_party_id(party);
    }
    if (parties[0] == parties[1]) {
        throw PrototypeError("duplicate party identifier");
    }
    if (share_set_ids[0] != share_set_ids[1]) {
        throw PrototypeError("share generation mismatch");
    }

    const CoeffVector& first = values[0].get().value_;
    const CoeffVector& second = values[1].get().value_;
    require_canonical_coefficients(first);
    require_canonical_coefficients(second);
    if (first.empty() || first.size() != second.size()) {
        throw PrototypeError("inconsistent vector lengths");
    }

    const std::vector<PartyId> active{parties[0], parties[1]};
    const std::array<Coeff, 2> lambdas{
        lagrange_at_zero(parties[0], active),
        lagrange_at_zero(parties[1], active),
    };
    Secret<CoeffVector> result(CoeffVector(first.size(), 0));
    for (std::size_t idx = 0; idx < first.size(); ++idx) {
        ScopedErase<Coeff> first_term;
        ScopedErase<Coeff> second_term;
        ScopedErase<Coeff> reconstructed;
        first_term.value = mul_q(lambdas[0], first[idx]);
        second_term.value = mul_q(lambdas[1], second[idx]);
        reconstructed.value =
            add_q(first_term.value, second_term.value);
        result.value_[idx] = reconstructed.value;
    }
    return result;
}

} // namespace rmtls
