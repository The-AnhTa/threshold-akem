#pragma once

#include "rmtls_threshold_mlkem/mlkem_adapter.hpp"
#include "rmtls_threshold_mlkem/sharing.hpp"
#include "rmtls_threshold_mlkem/transcript.hpp"

namespace rmtls {

class AssistantContribution {
public:
    AssistantContribution(const AssistantContribution&) = delete;
    AssistantContribution& operator=(const AssistantContribution&) = delete;
    AssistantContribution(AssistantContribution&&) noexcept = default;
    AssistantContribution& operator=(AssistantContribution&&) noexcept = default;

private:
    friend class Assistant;
    friend class Combiner;

    struct Binding {
        std::string canonical_transcript;
        std::string caller_id;
        std::string signature;
        std::string transcript_hash;
        std::string request_hash;
        std::string ciphertext_hash;
        std::string threshold_key_id;
        std::string assistant_epoch;
        std::string adapter_profile_id;

        friend bool operator==(const Binding&, const Binding&) = default;
    };

    AssistantContribution(PartyId party,
                          ShareSetId share_set_id,
                          Binding binding,
                          Secret<CoeffVector> value)
        : party_(party),
          share_set_id_(share_set_id),
          binding_(std::move(binding)),
          value_(std::move(value)) {}

    static Binding binding_for(const SignedTranscript& st,
                               const std::string& caller_id,
                               const std::string& adapter_profile_id);

    PartyId party_;
    ShareSetId share_set_id_;
    Binding binding_;
    Secret<CoeffVector> value_;
};

class Assistant {
public:
    Assistant(PartyId id,
              ShareMap& dealer_shares,
              AdmissionPolicy policy,
              MLKEMAdapterPtr trusted_adapter);

    std::optional<AssistantContribution> process(const SignedTranscript& st,
                                                 const std::string& caller_id);
private:
    static MLKEMAdapterPtr require_adapter(MLKEMAdapterPtr adapter) {
        if (!adapter) {
            throw PrototypeError("trusted adapter is unavailable");
        }
        return adapter;
    }

    static ShareVector take_dealer_share(ShareMap& dealer_shares,
                                         PartyId party,
                                         const std::string& adapter_profile_id);

    static std::string require_adapter_profile(const MLKEMAdapter& adapter);

    PartyId id_;
    MLKEMAdapterPtr trusted_adapter_;
    std::string adapter_profile_id_;
    ShareVector share_;
    AdmissionPolicy policy_;
    ReplayCache replay_cache_;
};

} // namespace rmtls
