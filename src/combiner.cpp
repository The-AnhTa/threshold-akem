#include "rmtls_threshold_mlkem/combiner.hpp"
#include "rmtls_threshold_mlkem/sharing.hpp"

namespace rmtls {

Combiner::Combiner(MLKEMAdapterPtr trusted_adapter)
    : trusted_adapter_(require_adapter(std::move(trusted_adapter))),
      adapter_profile_id_(require_adapter_profile(*trusted_adapter_)) {}

std::string Combiner::require_adapter_profile(const MLKEMAdapter& adapter) {
    const std::string_view profile = adapter.profile_id();
    if (profile.empty()) {
        throw PrototypeError("trusted adapter profile is unavailable");
    }
    return std::string(profile);
}

ThresholdDecryptionResult Combiner::combine(
    const std::vector<AssistantContribution>& contributions,
    const SignedTranscript& st,
    const std::string& caller_id) const {
    if (contributions.size() != 2) {
        throw PrototypeError("fixed profile requires exactly two contributions");
    }

    const AssistantContribution::Binding expected =
        AssistantContribution::binding_for(
            st, caller_id, adapter_profile_id_);

    for (const auto& c : contributions) {
        if (!(c.binding_ == expected)) {
            throw PrototypeError("contribution request binding mismatch");
        }
    }
    const std::array<PartyId, 2> parties{
        contributions[0].party_,
        contributions[1].party_,
    };
    const std::array<ShareSetId, 2> share_set_ids{
        contributions[0].share_set_id_,
        contributions[1].share_set_id_,
    };
    const std::array<
        std::reference_wrapper<const Secret<CoeffVector>>,
        2> values{
        std::cref(contributions[0].value_),
        std::cref(contributions[1].value_),
    };
    Secret<CoeffVector> combined =
        Shamir23::reconstruct_values(parties, share_set_ids, values);
    Secret<Bytes> m_prime =
        trusted_adapter_->dec_msg_from_combined_inner(
            combined, st.transcript.ciphertext);
    return ThresholdDecryptionResult{
        std::move(m_prime),
        st.transcript.ciphertext,
        st.transcript.service_kem_fingerprint,
        adapter_profile_id_,
        st.transcript_hash,
        request_hash(st, caller_id),
        key_schedule_context(st),
    };
}

} // namespace rmtls
