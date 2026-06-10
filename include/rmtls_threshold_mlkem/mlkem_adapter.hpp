#pragma once

#include "rmtls_threshold_mlkem/types.hpp"
#include <memory>
#include <string>
#include <string_view>

namespace rmtls {

class FrontService;

class MLKEMPublicKey {
public:
    const Bytes& bytes() const noexcept { return bytes_; }
    const std::string& fingerprint() const noexcept { return fingerprint_; }
    const std::string& adapter_profile_id() const noexcept {
        return adapter_profile_id_;
    }

private:
    friend class MLKEMAdapter;
    friend class ToyMLKEMAdapter;

    MLKEMPublicKey(Bytes bytes,
                   std::string fingerprint,
                   std::string adapter_profile_id)
        : bytes_(std::move(bytes)),
          fingerprint_(std::move(fingerprint)),
          adapter_profile_id_(std::move(adapter_profile_id)) {}

    Bytes bytes_;
    std::string fingerprint_;
    std::string adapter_profile_id_;
};

struct MLKEMSecretState {
    // For the real implementation this should represent the FIPS-compatible
    // NTT-domain K-PKE decryption key component s_hat. The toy adapter stores a
    // coefficient vector of length 512 for ML-KEM-512-like shape only.
    Secret<CoeffVector> s_hat;
    Secret<Bytes> z;
    // Dealer/reference-only full decapsulation key. Tests consume and erase
    // this before provisioning assistants; it is never given to FrontService.
    Secret<Bytes> reference_decapsulation_key;
};

struct MLKEMKeyPair {
    MLKEMPublicKey public_key;
    MLKEMSecretState secret_state;
};

struct Encapsulation {
    Bytes ciphertext;
    Secret<Bytes> peer_kem_secret;
};

class MLKEMAdapter {
public:
    virtual ~MLKEMAdapter() = default;
    virtual std::string name() const = 0;
    virtual bool is_real_mlkem() const = 0;
    virtual std::string_view profile_id() const noexcept = 0;

    MLKEMKeyPair keygen() const;
    Encapsulation encapsulate(const MLKEMPublicKey& pk) const;
    Secret<Bytes> decapsulate_reference(
        Secret<Bytes>& reference_decapsulation_key,
        const Bytes& ciphertext) const;
#if defined(RMTLS_ENABLE_TEST_OBSERVERS)
    void prepare_peer_session_for_test(
        const Secret<Bytes>& peer_kem_secret,
        const std::string& key_schedule_context) const;
#endif
    void validate_public_key(const MLKEMPublicKey& pk) const;

    // Local reference for PKE.DecMsg(s_hat, ct). Returns internal m'.
    Secret<Bytes> dec_msg_local(const Secret<CoeffVector>& s_hat,
                                const Bytes& ciphertext) const;

    // The public part extracted from ciphertext that is multiplied by shares of
    // s_hat. In real ML-KEM this corresponds to NTT(u').
    CoeffVector public_u_hat_from_ciphertext(const Bytes& ciphertext) const;

    // Research-only assistant path. The result is internal and non-serialisable.
    Secret<CoeffVector> assistant_inner(const Secret<CoeffVector>& share,
                                        const Bytes& ciphertext) const;

    // Combiner-side finalization from reconstructed linear product. In real
    // ML-KEM this corresponds to v' - NTT^{-1}(delta_hat), Compress_1,
    // ByteEncode_1.
    Secret<Bytes> dec_msg_from_combined_inner(
        const Secret<CoeffVector>& combined,
        const Bytes& ciphertext) const;

    // Front-service local FO validation / key scheduling simulation. Public
    // output shape must not reveal success or failure branch.
    PublicResult fo_validate_and_schedule(const Secret<Bytes>& m_prime,
                                          const Bytes& ciphertext,
                                          const MLKEMPublicKey& pk,
                                          const Secret<Bytes>& z,
                                          const std::string& request_id,
                                          const std::string&
                                              key_schedule_context =
                                                  "standalone-research") const;

private:
    friend class FrontService;

    struct GeneratedKeyMaterial {
        Bytes public_key;
        Secret<CoeffVector> s_hat;
        Secret<Bytes> z;
        Secret<Bytes> reference_decapsulation_key;
    };

    struct EncapsulationMaterial {
        Bytes ciphertext;
        Secret<Bytes> peer_kem_secret;
    };

    struct FOProcessingOutcome {
        PublicResult public_result;
        bool backend_completed;
    };

    MLKEMKeyPair finish_keygen(GeneratedKeyMaterial material) const;
    Encapsulation finish_encapsulation(
        const MLKEMPublicKey& pk,
        EncapsulationMaterial material) const;
    FOProcessingOutcome fo_validate_and_schedule_internal(
        const Secret<Bytes>& m_prime,
        const Bytes& ciphertext,
        const MLKEMPublicKey& pk,
        const Secret<Bytes>& z,
        const std::string& request_id,
        const std::string& key_schedule_context) const;

    virtual GeneratedKeyMaterial keygen_impl() const = 0;
    virtual EncapsulationMaterial encapsulate_impl(
        const MLKEMPublicKey& pk) const = 0;
    virtual Bytes decapsulate_reference_impl(
        const Bytes& reference_decapsulation_key,
        const Bytes& ciphertext) const = 0;
    virtual std::string public_key_fingerprint_impl(
        const Bytes& public_key) const = 0;
    virtual CoeffVector public_u_hat_from_ciphertext_impl(
        const Bytes& ciphertext) const = 0;
    virtual Bytes dec_msg_local_impl(const CoeffVector& s_hat,
                                     const Bytes& ciphertext) const = 0;
    virtual CoeffVector assistant_inner_impl(const CoeffVector& share,
                                             const Bytes& ciphertext) const = 0;
    virtual Bytes dec_msg_from_combined_inner_impl(
        const CoeffVector& combined,
        const Bytes& ciphertext) const = 0;
    virtual Bytes fo_validate_and_schedule_impl(
        const Bytes& m_prime,
        const Bytes& ciphertext,
        const MLKEMPublicKey& pk,
        const Bytes& z) const = 0;

protected:
    using GeneratedKeyMaterialForBackend = GeneratedKeyMaterial;
    using EncapsulationMaterialForBackend = EncapsulationMaterial;

    MLKEMKeyPair finish_test_keygen(
        GeneratedKeyMaterialForBackend material) const;
    Encapsulation finish_test_encapsulation(
        const MLKEMPublicKey& pk,
        EncapsulationMaterialForBackend material) const;

#if defined(RMTLS_ENABLE_TEST_OBSERVERS)
    // Compiled only into the dedicated test library variant.
    virtual void observe_peer_kem_secret_for_test(
        const Bytes& peer_kem_secret) const;
    virtual void observe_reference_kem_secret_for_test(
        const Bytes& reference_kem_secret) const;
    virtual void observe_peer_session_key_for_test(
        const Bytes& peer_session_key) const;
    virtual void observe_service_session_key_for_test(
        const Bytes& service_session_key) const;
#endif
};

using MLKEMAdapterPtr = std::shared_ptr<const MLKEMAdapter>;

// Toy-only adapter retained for deterministic architecture tests and the
// explicitly toy-only benchmark. Not cryptographic.
class ToyMLKEMAdapter : public MLKEMAdapter {
public:
    std::string name() const override { return "ToyMLKEMAdapter - not real ML-KEM"; }
    bool is_real_mlkem() const override { return false; }
    std::string_view profile_id() const noexcept override {
        return "toy-mlkem512-inner-v1";
    }

    MLKEMKeyPair keygen_deterministic_for_test(std::uint64_t seed) const;
    Encapsulation encapsulate_deterministic_for_test(
        const MLKEMPublicKey& pk,
        std::uint64_t seed) const;

protected:
    GeneratedKeyMaterialForBackend keygen_impl() const override;
    EncapsulationMaterialForBackend encapsulate_impl(
        const MLKEMPublicKey& pk) const override;
    Bytes decapsulate_reference_impl(
        const Bytes& reference_decapsulation_key,
        const Bytes& ciphertext) const override;
    std::string public_key_fingerprint_impl(
        const Bytes& public_key) const override;
    CoeffVector public_u_hat_from_ciphertext_impl(
        const Bytes& ciphertext) const override;
    Bytes dec_msg_local_impl(const CoeffVector& s_hat,
                             const Bytes& ciphertext) const override;
    CoeffVector assistant_inner_impl(const CoeffVector& share,
                                     const Bytes& ciphertext) const override;
    Bytes dec_msg_from_combined_inner_impl(
        const CoeffVector& combined,
        const Bytes& ciphertext) const override;
    Bytes fo_validate_and_schedule_impl(
        const Bytes& m_prime,
        const Bytes& ciphertext,
        const MLKEMPublicKey& pk,
        const Bytes& z) const override;

    // Test-only observation point for honest toy-session equality. This keeps
    // the derived secret inside trusted adapter subclasses.
    Bytes derive_honest_peer_secret_for_test(
        const MLKEMPublicKey& pk,
        const Bytes& ciphertext) const;

private:
    GeneratedKeyMaterialForBackend keygen_material_for_test(
        std::uint64_t seed) const;
    EncapsulationMaterialForBackend encapsulation_material_for_test(
        const MLKEMPublicKey& pk,
        std::uint64_t seed) const;
};

// FIPS 203 ML-KEM-512 research backend using mlkem-native v1.0.0. This
// intentionally exposes the K-PKE inner operations only through MLKEMAdapter.
class RealMLKEM512Adapter : public MLKEMAdapter {
public:
    std::string name() const override {
        return "mlkem-native v1.0.0 ML-KEM-512";
    }
    bool is_real_mlkem() const override { return true; }
    std::string_view profile_id() const noexcept override {
        return "fips203-mlkem512-ntt-v1";
    }

protected:
    GeneratedKeyMaterialForBackend keygen_impl() const override;
    EncapsulationMaterialForBackend encapsulate_impl(
        const MLKEMPublicKey& pk) const override;
    Bytes decapsulate_reference_impl(
        const Bytes& reference_decapsulation_key,
        const Bytes& ciphertext) const override;
    std::string public_key_fingerprint_impl(
        const Bytes& public_key) const override;
    CoeffVector public_u_hat_from_ciphertext_impl(
        const Bytes& ciphertext) const override;
    Bytes dec_msg_local_impl(const CoeffVector& s_hat,
                             const Bytes& ciphertext) const override;
    CoeffVector assistant_inner_impl(const CoeffVector& share,
                                     const Bytes& ciphertext) const override;
    Bytes dec_msg_from_combined_inner_impl(
        const CoeffVector& combined,
        const Bytes& ciphertext) const override;
    Bytes fo_validate_and_schedule_impl(
        const Bytes& m_prime,
        const Bytes& ciphertext,
        const MLKEMPublicKey& pk,
        const Bytes& z) const override;
};

} // namespace rmtls
