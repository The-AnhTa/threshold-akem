#include "rmtls_threshold_mlkem/sharing.hpp"

#include <array>
#include <iostream>
#include <stdexcept>
#include <type_traits>

using namespace rmtls;

namespace {

template <class T>
concept HasPublicSecretGetter = requires(T& value) {
    value.get_internal_for_front_service_only();
};

template <class T>
concept HasPublicSecretEquality = requires(const T& left, const T& right) {
    left == right;
};

template <class T>
concept HasPublicDealerLookup = requires(T& value) {
    value.at(PartyId{1});
};

template <class T>
concept HasPublicDealerExtraction = requires(T& value) {
    value.extract(PartyId{1});
};

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

} // namespace

int main() try {
    static_assert(!std::is_copy_constructible_v<Secret<Bytes>>);
    static_assert(!std::is_copy_assignable_v<Secret<Bytes>>);
    static_assert(!HasPublicSecretGetter<Secret<Bytes>>);
    static_assert(!HasPublicSecretEquality<Secret<Bytes>>);
    static_assert(!std::is_copy_constructible_v<ShareVector>);
    static_assert(!std::is_copy_assignable_v<ShareVector>);
    static_assert(!std::is_copy_constructible_v<ShareMap>);
    static_assert(!std::is_copy_assignable_v<ShareMap>);
    static_assert(!HasPublicDealerLookup<ShareMap>);
    static_assert(!HasPublicDealerExtraction<ShareMap>);

    Bytes reserved_secret;
    reserved_secret.reserve(64);
    reserved_secret.resize(32, 0xa5);
    require(reserved_secret.capacity() > reserved_secret.size(),
            "secret erasure test did not reserve spare capacity");
    Secret<Bytes> capacity_test_secret(std::move(reserved_secret));
    capacity_test_secret.erase_internal();
    require(capacity_test_secret.is_erased_internal(),
            "secret erasure retained allocated capacity");

    CoeffVector secret(512, 0);
    for (std::size_t i = 0; i < secret.size(); ++i) {
        secret[i] = static_cast<Coeff>(i % Q);
    }
    require(add_q(Q - 1, 1) == 0, "field addition did not wrap");
    require(sub_q(0, 1) == Q - 1, "field subtraction did not wrap");
    require(mul_q(17, inv_q(17)) == 1, "field inverse was incorrect");

    struct PairLambdas {
        std::array<PartyId, 2> parties;
        std::array<Coeff, 2> expected;
    };
    constexpr std::array<PairLambdas, 3> pair_lambdas{{
        PairLambdas{{PartyId{1}, PartyId{2}}, {2, Q - 1}},
        PairLambdas{{PartyId{1}, PartyId{3}}, {1666, 1664}},
        PairLambdas{{PartyId{2}, PartyId{3}}, {3, Q - 2}},
    }};
    for (const auto& pair : pair_lambdas) {
        const std::vector<PartyId> active{
            pair.parties[0],
            pair.parties[1],
        };
        require(lagrange_at_zero(pair.parties[0], active) == pair.expected[0] &&
                    lagrange_at_zero(pair.parties[1], active) == pair.expected[1],
                "Lagrange coefficient mismatch");
    }

    const ShareContext context{
        "kem-fingerprint",
        "thkey-1",
        "epoch-1",
        "toy-mlkem512-inner-v1",
    };
    Secret<CoeffVector> dealer_secret{CoeffVector(secret)};
    ShareMap shares = Shamir23::share_and_erase(dealer_secret, context);
    require(dealer_secret.is_erased_internal(),
            "dealer retained key material after sharing");
    require(shares.size() == 3, "dealer did not create three shares");

    CoeffVector malformed_coefficients(512, 0);
    malformed_coefficients[0] = Q;
    Secret<CoeffVector> malformed(std::move(malformed_coefficients));
    bool malformed_rejected = false;
    try {
        (void)Shamir23::share_and_erase(malformed, context);
    } catch (const PrototypeError&) {
        malformed_rejected = true;
    }
    require(malformed_rejected, "malformed dealer key material was accepted");
    require(malformed.is_erased_internal(),
            "dealer key material survived failed provisioning");

    Secret<CoeffVector> unbound(CoeffVector(512, 1));
    bool unbound_rejected = false;
    try {
        (void)Shamir23::share_and_erase(unbound, ShareContext{});
    } catch (const PrototypeError&) {
        unbound_rejected = true;
    }
    require(unbound_rejected, "incomplete share context was accepted");
    require(unbound.is_erased_internal(),
            "dealer key material survived failed context validation");

    for (std::size_t length : {std::size_t{0}, std::size_t{511}, std::size_t{513}}) {
        Secret<CoeffVector> wrong_shape(CoeffVector(length, 1));
        bool wrong_shape_rejected = false;
        try {
            (void)Shamir23::share_and_erase(wrong_shape, context);
        } catch (const PrototypeError&) {
            wrong_shape_rejected = true;
        }
        require(wrong_shape_rejected, "malformed key-state length was accepted");
        require(wrong_shape.is_erased_internal(),
                "malformed key state survived failed provisioning");
    }

    std::cout << "test_sharing passed: field arithmetic and wiping OS-random (2,3) provisioning over Z_q=3329\n";
    return 0;
} catch (const std::exception& error) {
    std::cerr << "test_sharing failed: " << error.what() << '\n';
    return 1;
}
