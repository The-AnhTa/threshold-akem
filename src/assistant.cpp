#include "rmtls_threshold_mlkem/assistant.hpp"
#include "rmtls_threshold_mlkem/sharing.hpp"

namespace rmtls {

Assistant::Assistant(PartyId id,
                     ShareMap& dealer_shares,
                     AdmissionPolicy policy,
                     MLKEMAdapterPtr trusted_adapter)
    : id_(id),
      trusted_adapter_(require_adapter(std::move(trusted_adapter))),
      adapter_profile_id_(require_adapter_profile(*trusted_adapter_)),
      share_(take_dealer_share(dealer_shares, id, adapter_profile_id_)),
      policy_(std::move(policy)) {}

std::string Assistant::require_adapter_profile(const MLKEMAdapter& adapter) {
    const std::string_view profile = adapter.profile_id();
    if (profile.empty()) {
        throw PrototypeError("trusted adapter profile is unavailable");
    }
    return std::string(profile);
}

ShareVector Assistant::take_dealer_share(ShareMap& dealer_shares,
                                         PartyId party,
                                         const std::string& adapter_profile_id) {
    if (party.value < 1 || party.value > 3) {
        throw PrototypeError("party identifier outside fixed profile");
    }
    const auto found = dealer_shares.shares_.find(party);
    if (found == dealer_shares.shares_.end()) {
        throw PrototypeError("dealer share is unavailable");
    }
    if (found->second.context_.adapter_profile_id != adapter_profile_id) {
        throw PrototypeError("dealer share adapter profile mismatch");
    }
    auto node = dealer_shares.shares_.extract(found);
    return std::move(node.mapped());
}

AssistantContribution::Binding AssistantContribution::binding_for(
    const SignedTranscript& st,
    const std::string& caller_id,
    const std::string& adapter_profile_id) {
    return Binding{
        canonical_encode(st.transcript),
        caller_id,
        st.signature,
        st.transcript_hash,
        request_hash(st, caller_id),
        ciphertext_hash(st.transcript.ciphertext),
        st.transcript.threshold_key_id,
        st.transcript.assistant_epoch,
        adapter_profile_id,
    };
}

std::optional<AssistantContribution> Assistant::process(const SignedTranscript& st,
                                                        const std::string& caller_id) {
    const ShareContext request_context{
        st.transcript.service_kem_fingerprint,
        st.transcript.threshold_key_id,
        st.transcript.assistant_epoch,
        adapter_profile_id_,
    };
    if (!(share_.context_ == request_context)) {
        return std::nullopt;
    }
    if (policy_.admit(st, caller_id, replay_cache_) != AdmissionStatus::Accept) {
        return std::nullopt;
    }
    if (!(id_ == share_.party_)) {
        throw PrototypeError("assistant state identifier mismatch");
    }
    return AssistantContribution{
        id_,
        share_.share_set_id_,
        AssistantContribution::binding_for(
            st, caller_id, adapter_profile_id_),
        trusted_adapter_->assistant_inner(share_.coeffs_, st.transcript.ciphertext),
    };
}

} // namespace rmtls
