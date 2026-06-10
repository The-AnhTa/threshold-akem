#include "rmtls_threshold_mlkem/mlkem_adapter.hpp"
#include "rmtls_threshold_mlkem/sharing.hpp"
#include "mlkem_native_bridge.h"
#include "public_output_safety.hpp"

#include <array>
#include <iomanip>
#include <random>
#include <sstream>
#include <utility>

namespace rmtls {
namespace {

template <class T>
class ScopedErase {
public:
    explicit ScopedErase(T& value) : value_(value) {}
    ~ScopedErase() { detail::erase_value(value_); }

private:
    T& value_;
};

std::string toy_hash_hex(const Bytes& b) {
    std::uint64_t h = 1469598103934665603ull;
    for (auto x : b) {
        h ^= x;
        h *= 1099511628211ull;
    }
    std::ostringstream oss;
    oss << std::hex << h;
    return oss.str();
}

Bytes toy_expand_bytes(std::uint64_t seed, std::size_t len) {
    std::mt19937_64 rng(seed);
    Bytes out(len);
    for (auto& x : out) x = static_cast<std::uint8_t>(rng() & 0xff);
    return out;
}

void toy_absorb(std::uint64_t& state,
                const Bytes& input,
                std::size_t length) {
    state ^= static_cast<std::uint64_t>(length);
    state *= 1099511628211ull;
    for (std::size_t i = 0; i < length; ++i) {
        state ^= input[i];
        state *= 1099511628211ull;
    }
}

Bytes toy_expand_material(std::uint64_t domain,
                          const Bytes& first,
                          const Bytes& second,
                          const Bytes& third = {}) {
    std::uint64_t state = 1469598103934665603ull ^ domain;
    toy_absorb(state, first, first.size());
    toy_absorb(state, second, second.size());
    toy_absorb(state, third, third.size());

    Bytes output(MLKEM512_SHARED_SECRET_BYTES);
    for (std::size_t i = 0; i < output.size(); ++i) {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state *= 2685821657736338717ull;
        output[i] = static_cast<std::uint8_t>(state >> 56);
    }
    return output;
}

CoeffVector toy_s_hat_from_public_key_bytes(const Bytes& public_key) {
    CoeffVector result(MLKEM512_S_HAT_COEFFICIENTS);
    for (std::size_t i = 0; i < result.size(); ++i) {
        const std::uint32_t first =
            public_key[(2 * i) % public_key.size()];
        const std::uint32_t second =
            public_key[(2 * i + 1) % public_key.size()];
        result[i] = static_cast<Coeff>(
            (first + 257u * second + i) % Q);
    }
    return result;
}

constexpr std::size_t TOY_CIPHERTEXT_BODY_BYTES =
    MLKEM512_CIPHERTEXT_BYTES - MLKEM512_SHARED_SECRET_BYTES;

Bytes toy_ciphertext_tag(const MLKEMPublicKey& pk,
                         const Bytes& ciphertext,
                         const Bytes& m_prime) {
    std::uint64_t state =
        1469598103934665603ull ^ 0x746f792d74616731ull;
    toy_absorb(state, pk.bytes(), pk.bytes().size());
    toy_absorb(state, ciphertext, TOY_CIPHERTEXT_BODY_BYTES);
    toy_absorb(state, m_prime, m_prime.size());

    Bytes empty;
    Bytes seed_material(sizeof(state));
    for (std::size_t i = 0; i < seed_material.size(); ++i) {
        seed_material[i] =
            static_cast<std::uint8_t>(state >> (8 * i));
    }
    return toy_expand_material(
        0x746f792d74616732ull, seed_material, empty);
}

Bytes toy_success_secret(const Bytes& m_prime,
                         const Bytes& ciphertext,
                         const MLKEMPublicKey& pk) {
    return toy_expand_material(
        0x746f792d73756363ull,
        m_prime,
        ciphertext,
        pk.bytes());
}

Bytes toy_fallback_secret(const Bytes& z,
                          const Bytes& ciphertext) {
    Bytes empty;
    return toy_expand_material(
        0x746f792d6661696cull, z, ciphertext, empty);
}

Bytes schedule_session_key(const Bytes& kem_secret,
                           const std::string& context) {
    static constexpr std::string_view domain =
        "rMTLS-AuthKEM-v1-key-schedule";
    Bytes input;
    input.reserve(domain.size() + kem_secret.size() + context.size());
    input.insert(input.end(), domain.begin(), domain.end());
    input.insert(input.end(), kem_secret.begin(), kem_secret.end());
    input.insert(input.end(), context.begin(), context.end());
    Bytes output(MLKEM512_SHARED_SECRET_BYTES);
    rmtls_shake256(
        output.data(), output.size(), input.data(), input.size());
    detail::erase_value(input);
    return output;
}

std::string hex_encode(const std::uint8_t* data, std::size_t size) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (std::size_t index = 0; index < size; ++index) {
        output << std::setw(2)
               << static_cast<unsigned int>(data[index]);
    }
    return output.str();
}

std::uint64_t toy_random_seed() {
    std::random_device source;
    const std::uint64_t high = static_cast<std::uint64_t>(source());
    const std::uint64_t low = static_cast<std::uint64_t>(source());
    return (high << 32) ^ low;
}

void require_bytes_size(const Bytes& value, std::size_t expected) {
    if (value.size() != expected) {
        throw PrototypeError("adapter byte-string shape mismatch");
    }
}

void require_coefficients(const CoeffVector& value, std::size_t expected) {
    if (value.size() != expected) {
        throw PrototypeError("adapter coefficient-vector shape mismatch");
    }
    for (Coeff coefficient : value) {
        if (coefficient >= Q) {
            throw PrototypeError("adapter coefficient outside Z_q");
        }
    }
}

void require_public_request_id(const std::string& request_id) {
    if (request_id.empty() || request_id.size() > 128) {
        throw PrototypeError("request identifier rejected");
    }
    for (unsigned char character : request_id) {
        const bool allowed =
            (character >= 'a' && character <= 'z') ||
            (character >= 'A' && character <= 'Z') ||
            (character >= '0' && character <= '9') ||
            character == '-' ||
            character == '_' ||
            character == '.';
        if (!allowed) {
            throw PrototypeError("request identifier rejected");
        }
    }
    if (detail::contains_forbidden_public_token(request_id)) {
        throw PrototypeError("request identifier rejected");
    }
}

CoeffVector toy_inner(const CoeffVector& left, const CoeffVector& right) {
    if (left.size() != right.size()) {
        throw PrototypeError("inner computation length mismatch");
    }

    // Toy output length 256, accumulating two ML-KEM-512-like components.
    CoeffVector result(256, 0);
    for (std::size_t i = 0; i < left.size(); ++i) {
        result[i % 256] = add_q(result[i % 256], mul_q(left[i], right[i]));
    }
    return result;
}

Bytes toy_decode(const CoeffVector& combined, const Bytes& ciphertext) {
    if (combined.size() != 256) {
        throw PrototypeError("combined inner value has unexpected length");
    }

    Bytes out(32, 0);
    for (std::size_t i = 0; i < out.size(); ++i) {
        std::uint32_t v =
            ciphertext.empty() ? 0 : ciphertext[i % ciphertext.size()];
        for (std::size_t j = i; j < combined.size(); j += out.size()) {
            v += static_cast<std::uint32_t>(j + 1) * combined[j];
        }
        out[i] = static_cast<std::uint8_t>(v & 0xff);
    }
    return out;
}

} // namespace

MLKEMKeyPair MLKEMAdapter::keygen() const {
    try {
        return finish_keygen(keygen_impl());
    } catch (...) {
        throw PrototypeError("ML-KEM adapter operation failed");
    }
}

Encapsulation MLKEMAdapter::encapsulate(const MLKEMPublicKey& pk) const {
    try {
        validate_public_key(pk);
        EncapsulationMaterial material = encapsulate_impl(pk);
        return finish_encapsulation(pk, std::move(material));
    } catch (...) {
        throw PrototypeError("ML-KEM adapter operation failed");
    }
}

Secret<Bytes> MLKEMAdapter::decapsulate_reference(
    Secret<Bytes>& reference_decapsulation_key,
    const Bytes& ciphertext) const {
    try {
        require_bytes_size(
            reference_decapsulation_key.value_,
            MLKEM512_SECRET_KEY_BYTES);
        require_bytes_size(ciphertext, MLKEM512_CIPHERTEXT_BYTES);
        Secret<Bytes> result(decapsulate_reference_impl(
            reference_decapsulation_key.value_, ciphertext));
        reference_decapsulation_key.erase_internal();
        require_bytes_size(result.value_, MLKEM512_SHARED_SECRET_BYTES);
#if defined(RMTLS_ENABLE_TEST_OBSERVERS)
        observe_reference_kem_secret_for_test(result.value_);
#endif
        return result;
    } catch (...) {
        reference_decapsulation_key.erase_internal();
        throw PrototypeError("ML-KEM adapter operation failed");
    }
}

#if defined(RMTLS_ENABLE_TEST_OBSERVERS)
void MLKEMAdapter::prepare_peer_session_for_test(
    const Secret<Bytes>& peer_kem_secret,
    const std::string& key_schedule_context) const {
    try {
        require_bytes_size(
            peer_kem_secret.value_, MLKEM512_SHARED_SECRET_BYTES);
        if (key_schedule_context.empty()) {
            throw PrototypeError("key schedule context is unavailable");
        }
        Secret<Bytes> session_key(schedule_session_key(
            peer_kem_secret.value_, key_schedule_context));
        observe_peer_session_key_for_test(session_key.value_);
    } catch (...) {
        throw PrototypeError("ML-KEM adapter operation failed");
    }
}
#endif

void MLKEMAdapter::validate_public_key(const MLKEMPublicKey& pk) const {
    try {
        const std::string_view profile = profile_id();
        if (profile.empty() ||
            pk.bytes_.size() != MLKEM512_PUBLIC_KEY_BYTES ||
            pk.adapter_profile_id_ != profile ||
            pk.fingerprint_.empty() ||
            pk.fingerprint_ != public_key_fingerprint_impl(pk.bytes_)) {
            throw PrototypeError("public key validation failed");
        }
    } catch (...) {
        throw PrototypeError("ML-KEM adapter operation failed");
    }
}

MLKEMKeyPair MLKEMAdapter::finish_keygen(
    GeneratedKeyMaterial material) const {
    const std::string_view profile = profile_id();
    if (profile.empty()) {
        throw PrototypeError("generated key material is incomplete");
    }
    require_bytes_size(material.public_key, MLKEM512_PUBLIC_KEY_BYTES);
    require_coefficients(
        material.s_hat.value_, MLKEM512_S_HAT_COEFFICIENTS);
    require_bytes_size(material.z.value_, MLKEM512_SHARED_SECRET_BYTES);
    require_bytes_size(
        material.reference_decapsulation_key.value_,
        MLKEM512_SECRET_KEY_BYTES);
    std::string fingerprint =
        public_key_fingerprint_impl(material.public_key);
    if (fingerprint.empty()) {
        throw PrototypeError("generated public-key fingerprint is unavailable");
    }
    MLKEMPublicKey public_key{
        std::move(material.public_key),
        std::move(fingerprint),
        std::string(profile),
    };
    return MLKEMKeyPair{
        std::move(public_key),
        MLKEMSecretState{
            std::move(material.s_hat),
            std::move(material.z),
            std::move(material.reference_decapsulation_key),
        },
    };
}

Encapsulation MLKEMAdapter::finish_encapsulation(
    const MLKEMPublicKey& pk,
    EncapsulationMaterial material) const {
    validate_public_key(pk);
    require_bytes_size(material.ciphertext, MLKEM512_CIPHERTEXT_BYTES);
    require_bytes_size(
        material.peer_kem_secret.value_, MLKEM512_SHARED_SECRET_BYTES);
#if defined(RMTLS_ENABLE_TEST_OBSERVERS)
    observe_peer_kem_secret_for_test(material.peer_kem_secret.value_);
#endif
    return Encapsulation{
        std::move(material.ciphertext),
        std::move(material.peer_kem_secret),
    };
}

#if defined(RMTLS_ENABLE_TEST_OBSERVERS)
void MLKEMAdapter::observe_peer_kem_secret_for_test(
    const Bytes&) const {}

void MLKEMAdapter::observe_reference_kem_secret_for_test(
    const Bytes&) const {}

void MLKEMAdapter::observe_peer_session_key_for_test(
    const Bytes&) const {}

void MLKEMAdapter::observe_service_session_key_for_test(
    const Bytes&) const {}
#endif

MLKEMKeyPair MLKEMAdapter::finish_test_keygen(
    GeneratedKeyMaterialForBackend material) const {
    try {
        return finish_keygen(std::move(material));
    } catch (...) {
        throw PrototypeError("ML-KEM adapter operation failed");
    }
}

Encapsulation MLKEMAdapter::finish_test_encapsulation(
    const MLKEMPublicKey& pk,
    EncapsulationMaterialForBackend material) const {
    try {
        return finish_encapsulation(pk, std::move(material));
    } catch (...) {
        throw PrototypeError("ML-KEM adapter operation failed");
    }
}

CoeffVector MLKEMAdapter::public_u_hat_from_ciphertext(
    const Bytes& ciphertext) const {
    try {
        require_bytes_size(ciphertext, MLKEM512_CIPHERTEXT_BYTES);
        CoeffVector result =
            public_u_hat_from_ciphertext_impl(ciphertext);
        require_coefficients(result, MLKEM512_S_HAT_COEFFICIENTS);
        return result;
    } catch (...) {
        throw PrototypeError("ML-KEM adapter operation failed");
    }
}

Secret<Bytes> MLKEMAdapter::dec_msg_local(
    const Secret<CoeffVector>& s_hat,
    const Bytes& ciphertext) const {
    try {
        require_coefficients(
            s_hat.value_, MLKEM512_S_HAT_COEFFICIENTS);
        require_bytes_size(ciphertext, MLKEM512_CIPHERTEXT_BYTES);
        Secret<Bytes> result(
            dec_msg_local_impl(s_hat.value_, ciphertext));
        require_bytes_size(result.value_, MLKEM512_MESSAGE_BYTES);
        return result;
    } catch (...) {
        throw PrototypeError("ML-KEM adapter operation failed");
    }
}

Secret<CoeffVector> MLKEMAdapter::assistant_inner(
    const Secret<CoeffVector>& share,
    const Bytes& ciphertext) const {
    try {
        require_coefficients(
            share.value_, MLKEM512_S_HAT_COEFFICIENTS);
        require_bytes_size(ciphertext, MLKEM512_CIPHERTEXT_BYTES);
        Secret<CoeffVector> result(
            assistant_inner_impl(share.value_, ciphertext));
        require_coefficients(
            result.value_, MLKEM512_INNER_COEFFICIENTS);
        return result;
    } catch (...) {
        throw PrototypeError("ML-KEM adapter operation failed");
    }
}

Secret<Bytes> MLKEMAdapter::dec_msg_from_combined_inner(
    const Secret<CoeffVector>& combined,
    const Bytes& ciphertext) const {
    try {
        require_coefficients(
            combined.value_, MLKEM512_INNER_COEFFICIENTS);
        require_bytes_size(ciphertext, MLKEM512_CIPHERTEXT_BYTES);
        Secret<Bytes> result(
            dec_msg_from_combined_inner_impl(combined.value_, ciphertext));
        require_bytes_size(result.value_, MLKEM512_MESSAGE_BYTES);
        return result;
    } catch (...) {
        throw PrototypeError("ML-KEM adapter operation failed");
    }
}

PublicResult MLKEMAdapter::fo_validate_and_schedule(
    const Secret<Bytes>& m_prime,
    const Bytes& ciphertext,
                                          const MLKEMPublicKey& pk,
                                          const Secret<Bytes>& z,
                                          const std::string& request_id,
                                          const std::string&
                                              key_schedule_context) const {
    return fo_validate_and_schedule_internal(
               m_prime,
               ciphertext,
               pk,
               z,
               request_id,
               key_schedule_context)
        .public_result;
}

MLKEMAdapter::FOProcessingOutcome
MLKEMAdapter::fo_validate_and_schedule_internal(
    const Secret<Bytes>& m_prime,
    const Bytes& ciphertext,
    const MLKEMPublicKey& pk,
    const Secret<Bytes>& z,
    const std::string& request_id,
    const std::string& key_schedule_context) const {
    try {
        validate_public_key(pk);
        require_bytes_size(m_prime.value_, MLKEM512_MESSAGE_BYTES);
        require_bytes_size(ciphertext, MLKEM512_CIPHERTEXT_BYTES);
        require_bytes_size(z.value_, MLKEM512_SHARED_SECRET_BYTES);
        require_public_request_id(request_id);
        if (key_schedule_context.empty()) {
            throw PrototypeError("key schedule context is unavailable");
        }
    } catch (...) {
        throw PrototypeError("ML-KEM adapter operation failed");
    }
    bool backend_completed = false;
    try {
        Secret<Bytes> scheduled_secret(
            fo_validate_and_schedule_impl(
                m_prime.value_, ciphertext, pk, z.value_));
        require_bytes_size(
            scheduled_secret.value_, MLKEM512_SHARED_SECRET_BYTES);
        Secret<Bytes> session_key(schedule_session_key(
            scheduled_secret.value_, key_schedule_context));
#if defined(RMTLS_ENABLE_TEST_OBSERVERS)
        observe_service_session_key_for_test(session_key.value_);
#endif
        backend_completed = true;
    } catch (...) {
        // Public behavior must not reveal whether local FO processing selected
        // a branch or encountered an internal backend failure.
    }
    return FOProcessingOutcome{
        PublicResult{request_id, "processed"},
        backend_completed,
    };
}

MLKEMAdapter::GeneratedKeyMaterialForBackend
ToyMLKEMAdapter::keygen_impl() const {
    return keygen_material_for_test(toy_random_seed());
}

MLKEMAdapter::EncapsulationMaterialForBackend
ToyMLKEMAdapter::encapsulate_impl(const MLKEMPublicKey& pk) const {
    return encapsulation_material_for_test(pk, toy_random_seed());
}

MLKEMKeyPair ToyMLKEMAdapter::keygen_deterministic_for_test(
    std::uint64_t seed) const {
    try {
        return finish_test_keygen(keygen_material_for_test(seed));
    } catch (...) {
        throw PrototypeError("ML-KEM adapter operation failed");
    }
}

Encapsulation ToyMLKEMAdapter::encapsulate_deterministic_for_test(
    const MLKEMPublicKey& pk,
    std::uint64_t seed) const {
    try {
        return finish_test_encapsulation(
            pk, encapsulation_material_for_test(pk, seed));
    } catch (...) {
        throw PrototypeError("ML-KEM adapter operation failed");
    }
}

MLKEMAdapter::GeneratedKeyMaterialForBackend
ToyMLKEMAdapter::keygen_material_for_test(std::uint64_t seed) const {
    Bytes public_key =
        toy_expand_bytes(seed ^ 0xA5A5u, MLKEM512_PUBLIC_KEY_BYTES);
    CoeffVector s_hat =
        toy_s_hat_from_public_key_bytes(public_key);
    ScopedErase<CoeffVector> erase_s_hat(s_hat);
    Bytes z = toy_expand_bytes(
        seed ^ 0x5A5Au, MLKEM512_SHARED_SECRET_BYTES);
    Bytes reference_key =
        toy_expand_bytes(seed ^ 0xD3C4u, MLKEM512_SECRET_KEY_BYTES);
    std::copy(
        public_key.begin(),
        public_key.end(),
        reference_key.begin() + 768);
    std::copy(
        z.begin(),
        z.end(),
        reference_key.end() -
            static_cast<std::ptrdiff_t>(z.size()));
    return GeneratedKeyMaterialForBackend{
        std::move(public_key),
        Secret<CoeffVector>(std::move(s_hat)),
        Secret<Bytes>(std::move(z)),
        Secret<Bytes>(std::move(reference_key)),
    };
}

MLKEMAdapter::EncapsulationMaterialForBackend
ToyMLKEMAdapter::encapsulation_material_for_test(
    const MLKEMPublicKey& pk,
    std::uint64_t seed) const {
    validate_public_key(pk);
    Bytes ct =
        toy_expand_bytes(seed ^ 0xC71u, MLKEM512_CIPHERTEXT_BYTES);
    CoeffVector s_hat =
        toy_s_hat_from_public_key_bytes(pk.bytes());
    ScopedErase<CoeffVector> erase_s_hat(s_hat);
    Bytes m_prime = dec_msg_local_impl(s_hat, ct);
    ScopedErase<Bytes> erase_m_prime(m_prime);
    Bytes tag = toy_ciphertext_tag(pk, ct, m_prime);
    ScopedErase<Bytes> erase_tag(tag);
    for (std::size_t i = 0; i < tag.size(); ++i) {
        ct[TOY_CIPHERTEXT_BODY_BYTES + i] = tag[i];
    }
    Bytes peer_secret =
        derive_honest_peer_secret_for_test(pk, ct);
    return EncapsulationMaterialForBackend{
        std::move(ct),
        Secret<Bytes>(std::move(peer_secret)),
    };
}

Bytes ToyMLKEMAdapter::decapsulate_reference_impl(
    const Bytes& reference_decapsulation_key,
    const Bytes& ciphertext) const {
    Bytes public_key_bytes(
        reference_decapsulation_key.begin() + 768,
        reference_decapsulation_key.begin() +
            768 + MLKEM512_PUBLIC_KEY_BYTES);
    const std::string fingerprint =
        public_key_fingerprint_impl(public_key_bytes);
    MLKEMPublicKey public_key{
        std::move(public_key_bytes),
        fingerprint,
        std::string(profile_id()),
    };
    CoeffVector s_hat =
        toy_s_hat_from_public_key_bytes(public_key.bytes());
    ScopedErase<CoeffVector> erase_s_hat(s_hat);
    Bytes m_prime = dec_msg_local_impl(s_hat, ciphertext);
    ScopedErase<Bytes> erase_m_prime(m_prime);
    Bytes z(
        reference_decapsulation_key.end() -
            static_cast<std::ptrdiff_t>(MLKEM512_SHARED_SECRET_BYTES),
        reference_decapsulation_key.end());
    ScopedErase<Bytes> erase_z(z);
    return fo_validate_and_schedule_impl(
        m_prime, ciphertext, public_key, z);
}

std::string ToyMLKEMAdapter::public_key_fingerprint_impl(
    const Bytes& public_key) const {
    return toy_hash_hex(public_key);
}

CoeffVector ToyMLKEMAdapter::public_u_hat_from_ciphertext_impl(
    const Bytes& ciphertext) const {
    CoeffVector u(512);
    for (std::size_t i = 0; i < u.size(); ++i) {
        const std::uint32_t a =
            ciphertext.empty()
                ? 0
                : ciphertext[i % TOY_CIPHERTEXT_BODY_BYTES];
        const std::uint32_t b =
            ciphertext.empty()
                ? 0
                : ciphertext[
                      (i * 7 + 3) % TOY_CIPHERTEXT_BODY_BYTES];
        u[i] = static_cast<Coeff>((a + 257 * b + i) % Q);
    }
    return u;
}

Bytes ToyMLKEMAdapter::dec_msg_local_impl(const CoeffVector& s_hat,
                                          const Bytes& ciphertext) const {
    CoeffVector u = public_u_hat_from_ciphertext(ciphertext);
    CoeffVector combined = toy_inner(s_hat, u);
    ScopedErase<CoeffVector> erase_combined(combined);
    return toy_decode(combined, ciphertext);
}

CoeffVector ToyMLKEMAdapter::assistant_inner_impl(
    const CoeffVector& share,
    const Bytes& ciphertext) const {
    return toy_inner(share, public_u_hat_from_ciphertext(ciphertext));
}

Bytes ToyMLKEMAdapter::dec_msg_from_combined_inner_impl(
    const CoeffVector& combined,
    const Bytes& ciphertext) const {
    return toy_decode(combined, ciphertext);
}

Bytes ToyMLKEMAdapter::derive_honest_peer_secret_for_test(
    const MLKEMPublicKey& pk,
    const Bytes& ciphertext) const {
    validate_public_key(pk);
    require_bytes_size(ciphertext, MLKEM512_CIPHERTEXT_BYTES);
    CoeffVector s_hat =
        toy_s_hat_from_public_key_bytes(pk.bytes());
    ScopedErase<CoeffVector> erase_s_hat(s_hat);
    Bytes m_prime = dec_msg_local_impl(s_hat, ciphertext);
    ScopedErase<Bytes> erase_m_prime(m_prime);
    return toy_success_secret(m_prime, ciphertext, pk);
}

Bytes ToyMLKEMAdapter::fo_validate_and_schedule_impl(
    const Bytes& m_prime,
    const Bytes& ciphertext,
    const MLKEMPublicKey& pk,
    const Bytes& z) const {
    // Toy FO simulation: deterministically reconstruct ct' from the received
    // ciphertext body, the recipient public key, and recovered m_prime.
    Bytes expected_tag =
        toy_ciphertext_tag(pk, ciphertext, m_prime);
    ScopedErase<Bytes> erase_expected_tag(expected_tag);
    std::uint8_t difference = 0;
    for (std::size_t i = 0; i < expected_tag.size(); ++i) {
        difference |= static_cast<std::uint8_t>(
            expected_tag[i] ^
            ciphertext[TOY_CIPHERTEXT_BODY_BYTES + i]);
    }

    Bytes success =
        toy_success_secret(m_prime, ciphertext, pk);
    Bytes fallback =
        toy_fallback_secret(z, ciphertext);
    ScopedErase<Bytes> erase_success(success);
    ScopedErase<Bytes> erase_fallback(fallback);

    const std::uint8_t use_success =
        static_cast<std::uint8_t>(difference == 0);
    const std::uint8_t success_mask =
        static_cast<std::uint8_t>(0u - use_success);
    Bytes selected(MLKEM512_SHARED_SECRET_BYTES);
    for (std::size_t i = 0; i < selected.size(); ++i) {
        selected[i] = static_cast<std::uint8_t>(
            (success[i] & success_mask) |
            (fallback[i] & static_cast<std::uint8_t>(~success_mask)));
    }
    detail::erase_value(difference);
    return selected;
}

MLKEMAdapter::GeneratedKeyMaterialForBackend
RealMLKEM512Adapter::keygen_impl() const {
    Bytes public_key(MLKEM512_PUBLIC_KEY_BYTES);
    Bytes secret_key(MLKEM512_SECRET_KEY_BYTES);
    if (rmtls_mlkem512_keypair(
            public_key.data(), secret_key.data()) != 0) {
        throw PrototypeError("real ML-KEM key generation failed");
    }

    CoeffVector s_hat(MLKEM512_S_HAT_COEFFICIENTS);
    if (rmtls_mlkem512_extract_s_hat(
            s_hat.data(), secret_key.data()) != 0) {
        throw PrototypeError("real ML-KEM key extraction failed");
    }
    Bytes z(
        secret_key.end() -
            static_cast<std::ptrdiff_t>(
                MLKEM512_SHARED_SECRET_BYTES),
        secret_key.end());
    return GeneratedKeyMaterialForBackend{
        std::move(public_key),
        Secret<CoeffVector>(std::move(s_hat)),
        Secret<Bytes>(std::move(z)),
        Secret<Bytes>(std::move(secret_key)),
    };
}

MLKEMAdapter::EncapsulationMaterialForBackend
RealMLKEM512Adapter::encapsulate_impl(
    const MLKEMPublicKey& pk) const {
    Bytes ciphertext(MLKEM512_CIPHERTEXT_BYTES);
    Bytes shared_secret(MLKEM512_SHARED_SECRET_BYTES);
    if (rmtls_mlkem512_encapsulate(
            ciphertext.data(),
            shared_secret.data(),
            pk.bytes().data()) != 0) {
        throw PrototypeError("real ML-KEM encapsulation failed");
    }
    return EncapsulationMaterialForBackend{
        std::move(ciphertext),
        Secret<Bytes>(std::move(shared_secret)),
    };
}

Bytes RealMLKEM512Adapter::decapsulate_reference_impl(
    const Bytes& reference_decapsulation_key,
    const Bytes& ciphertext) const {
    Bytes shared_secret(MLKEM512_SHARED_SECRET_BYTES);
    if (rmtls_mlkem512_decapsulate(
            shared_secret.data(),
            ciphertext.data(),
            reference_decapsulation_key.data()) != 0) {
        throw PrototypeError("real ML-KEM decapsulation failed");
    }
    return shared_secret;
}

std::string RealMLKEM512Adapter::public_key_fingerprint_impl(
    const Bytes& public_key) const {
    std::array<std::uint8_t, 32> digest{};
    rmtls_sha3_256(
        digest.data(), public_key.data(), public_key.size());
    return hex_encode(digest.data(), digest.size());
}

CoeffVector RealMLKEM512Adapter::public_u_hat_from_ciphertext_impl(
    const Bytes& ciphertext) const {
    CoeffVector output(MLKEM512_S_HAT_COEFFICIENTS);
    if (rmtls_mlkem512_public_u_hat(
            output.data(), ciphertext.data()) != 0) {
        throw PrototypeError("real ML-KEM ciphertext parsing failed");
    }
    return output;
}

Bytes RealMLKEM512Adapter::dec_msg_local_impl(
    const CoeffVector& s_hat,
    const Bytes& ciphertext) const {
    Bytes message(MLKEM512_MESSAGE_BYTES);
    if (rmtls_mlkem512_dec_msg(
            message.data(), s_hat.data(), ciphertext.data()) != 0) {
        throw PrototypeError("real ML-KEM inner decryption failed");
    }
    return message;
}

CoeffVector RealMLKEM512Adapter::assistant_inner_impl(
    const CoeffVector& share,
    const Bytes& ciphertext) const {
    CoeffVector output(MLKEM512_INNER_COEFFICIENTS);
    if (rmtls_mlkem512_assistant_inner(
            output.data(), share.data(), ciphertext.data()) != 0) {
        throw PrototypeError("real ML-KEM assistant operation failed");
    }
    return output;
}

Bytes RealMLKEM512Adapter::dec_msg_from_combined_inner_impl(
    const CoeffVector& combined,
    const Bytes& ciphertext) const {
    Bytes message(MLKEM512_MESSAGE_BYTES);
    if (rmtls_mlkem512_dec_msg_from_combined(
            message.data(), combined.data(), ciphertext.data()) != 0) {
        throw PrototypeError("real ML-KEM reconstruction failed");
    }
    return message;
}

Bytes RealMLKEM512Adapter::fo_validate_and_schedule_impl(
    const Bytes& m_prime,
    const Bytes& ciphertext,
    const MLKEMPublicKey& pk,
    const Bytes& z) const {
    Bytes shared_secret(MLKEM512_SHARED_SECRET_BYTES);
    if (rmtls_mlkem512_fo_validate(
            shared_secret.data(),
            m_prime.data(),
            ciphertext.data(),
            pk.bytes().data(),
            z.data()) != 0) {
        throw PrototypeError("real ML-KEM FO validation failed");
    }
    return shared_secret;
}

} // namespace rmtls
