#pragma once

#include "rmtls_threshold_mlkem/assistant.hpp"
#include "rmtls_threshold_mlkem/combiner.hpp"
#include "rmtls_threshold_mlkem/mlkem_adapter.hpp"

namespace rmtls {

class FrontService {
public:
    FrontService(const MLKEMPublicKey& pk,
                 Secret<Bytes>&& z,
                 MLKEMAdapterPtr adapter);

    PublicResult finalize(ThresholdDecryptionResult result,
                          const std::string& request_id) const;

    // Internal operational state only. This reports backend completion, never
    // the FO branch selected for a ciphertext.
    bool last_finalize_completed_internal() const noexcept {
        return last_finalize_completed_;
    }
private:
    static MLKEMAdapterPtr require_adapter(MLKEMAdapterPtr adapter) {
        if (!adapter) {
            throw PrototypeError("trusted adapter is unavailable");
        }
        return adapter;
    }

    static std::string require_adapter_profile(const MLKEMAdapter& adapter);
    static MLKEMPublicKey require_public_key_profile(
        const MLKEMPublicKey& pk,
        const std::string& adapter_profile_id,
        const MLKEMAdapter& adapter);

    MLKEMAdapterPtr adapter_;
    std::string adapter_profile_id_;
    MLKEMPublicKey pk_;
    Secret<Bytes> z_;
    mutable bool last_finalize_completed_ = false;
};

} // namespace rmtls
