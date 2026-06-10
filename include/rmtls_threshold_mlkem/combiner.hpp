#pragma once

#include "rmtls_threshold_mlkem/assistant.hpp"
#include <utility>

namespace rmtls {

class FrontService;

class ThresholdDecryptionResult {
public:
    ThresholdDecryptionResult(const ThresholdDecryptionResult&) = delete;
    ThresholdDecryptionResult& operator=(const ThresholdDecryptionResult&) = delete;
    ThresholdDecryptionResult(ThresholdDecryptionResult&& other) noexcept
        : m_prime_(std::move(other.m_prime_)),
          ciphertext_(std::move(other.ciphertext_)),
          service_kem_fingerprint_(
              std::move(other.service_kem_fingerprint_)),
          adapter_profile_id_(std::move(other.adapter_profile_id_)),
          transcript_hash_(std::move(other.transcript_hash_)),
          request_hash_(std::move(other.request_hash_)),
          key_schedule_context_(
              std::move(other.key_schedule_context_)),
          valid_(std::exchange(other.valid_, false)) {
        other.ciphertext_.clear();
        other.service_kem_fingerprint_.clear();
        other.adapter_profile_id_.clear();
        other.transcript_hash_.clear();
        other.request_hash_.clear();
        other.key_schedule_context_.clear();
    }
    ThresholdDecryptionResult& operator=(ThresholdDecryptionResult&&) = delete;

private:
    friend class Combiner;
    friend class FrontService;

    ThresholdDecryptionResult(Secret<Bytes> m_prime,
                              Bytes ciphertext,
                              std::string service_kem_fingerprint,
                              std::string adapter_profile_id,
                              std::string transcript_hash,
                              std::string request_hash,
                              std::string key_schedule_context)
        : m_prime_(std::move(m_prime)),
          ciphertext_(std::move(ciphertext)),
          service_kem_fingerprint_(std::move(service_kem_fingerprint)),
          adapter_profile_id_(std::move(adapter_profile_id)),
          transcript_hash_(std::move(transcript_hash)),
          request_hash_(std::move(request_hash)),
          key_schedule_context_(std::move(key_schedule_context)),
          valid_(true) {}

    Secret<Bytes> m_prime_;
    Bytes ciphertext_;
    std::string service_kem_fingerprint_;
    std::string adapter_profile_id_;
    std::string transcript_hash_;
    std::string request_hash_;
    std::string key_schedule_context_;
    bool valid_;
};

class Combiner {
public:
    explicit Combiner(MLKEMAdapterPtr trusted_adapter);

    ThresholdDecryptionResult combine(
        const std::vector<AssistantContribution>& contributions,
        const SignedTranscript& st,
        const std::string& caller_id) const;

private:
    static MLKEMAdapterPtr require_adapter(MLKEMAdapterPtr adapter) {
        if (!adapter) {
            throw PrototypeError("trusted adapter is unavailable");
        }
        return adapter;
    }

    static std::string require_adapter_profile(const MLKEMAdapter& adapter);

    MLKEMAdapterPtr trusted_adapter_;
    std::string adapter_profile_id_;
};

} // namespace rmtls
