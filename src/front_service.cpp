#include "rmtls_threshold_mlkem/front_service.hpp"

namespace rmtls {

FrontService::FrontService(const MLKEMPublicKey& pk,
                           Secret<Bytes>&& z,
                           MLKEMAdapterPtr adapter)
    : adapter_(require_adapter(std::move(adapter))),
      adapter_profile_id_(require_adapter_profile(*adapter_)),
      pk_(require_public_key_profile(
          pk, adapter_profile_id_, *adapter_)),
      z_(std::move(z)) {}

std::string FrontService::require_adapter_profile(const MLKEMAdapter& adapter) {
    const std::string_view profile = adapter.profile_id();
    if (profile.empty()) {
        throw PrototypeError("trusted adapter profile is unavailable");
    }
    return std::string(profile);
}

MLKEMPublicKey FrontService::require_public_key_profile(
    const MLKEMPublicKey& pk,
    const std::string& adapter_profile_id,
    const MLKEMAdapter& adapter) {
    adapter.validate_public_key(pk);
    if (pk.adapter_profile_id() != adapter_profile_id) {
        throw PrototypeError("public key adapter profile mismatch");
    }
    return pk;
}

PublicResult FrontService::finalize(
    ThresholdDecryptionResult result,
    const std::string& request_id) const {
    last_finalize_completed_ = false;
    if (!result.valid_ ||
        result.service_kem_fingerprint_ != pk_.fingerprint() ||
        result.adapter_profile_id_ != adapter_profile_id_ ||
        result.transcript_hash_.empty() ||
        result.request_hash_.empty() ||
        result.key_schedule_context_.empty()) {
        throw PrototypeError("threshold result binding mismatch");
    }
    MLKEMAdapter::FOProcessingOutcome outcome =
        adapter_->fo_validate_and_schedule_internal(
        result.m_prime_,
        result.ciphertext_,
        pk_,
        z_,
        request_id,
        result.key_schedule_context_);
    last_finalize_completed_ = outcome.backend_completed;
    return std::move(outcome.public_result);
}

} // namespace rmtls
