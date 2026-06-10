#include "rmtls_threshold_mlkem/assistant.hpp"
#include "rmtls_threshold_mlkem/combiner.hpp"
#include "rmtls_threshold_mlkem/front_service.hpp"
#include "rmtls_threshold_mlkem/mlkem_adapter.hpp"
#include "rmtls_threshold_mlkem/sharing.hpp"

#include <array>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <vector>

using namespace rmtls;

namespace {

class ObservingRealMLKEM512Adapter final : public RealMLKEM512Adapter {
public:
    ~ObservingRealMLKEM512Adapter() override {
        detail::erase_value(peer_kem_secret_);
        detail::erase_value(peer_session_key_);
        detail::erase_value(local_message_);
    }

    bool reference_decapsulation_matched() const noexcept {
        return reference_decapsulation_matched_;
    }

    bool all_threshold_messages_matched() const noexcept {
        return all_threshold_messages_matched_;
    }

    bool session_keys_matched() const noexcept {
        return session_keys_matched_;
    }

    std::size_t threshold_message_count() const noexcept {
        return threshold_message_count_;
    }

protected:
    void observe_peer_kem_secret_for_test(
        const Bytes& value) const override {
        detail::erase_value(peer_kem_secret_);
        peer_kem_secret_ = value;
    }

    void observe_reference_kem_secret_for_test(
        const Bytes& value) const override {
        reference_decapsulation_matched_ =
            !peer_kem_secret_.empty() && value == peer_kem_secret_;
    }

    void observe_peer_session_key_for_test(
        const Bytes& value) const override {
        detail::erase_value(peer_session_key_);
        peer_session_key_ = value;
    }

    void observe_service_session_key_for_test(
        const Bytes& value) const override {
        session_keys_matched_ =
            !peer_session_key_.empty() && value == peer_session_key_;
    }

    Bytes dec_msg_local_impl(
        const CoeffVector& s_hat,
        const Bytes& ciphertext) const override {
        Bytes value =
            RealMLKEM512Adapter::dec_msg_local_impl(s_hat, ciphertext);
        detail::erase_value(local_message_);
        local_message_ = value;
        return value;
    }

    Bytes dec_msg_from_combined_inner_impl(
        const CoeffVector& combined,
        const Bytes& ciphertext) const override {
        Bytes value =
            RealMLKEM512Adapter::dec_msg_from_combined_inner_impl(
                combined, ciphertext);
        ++threshold_message_count_;
        if (local_message_.empty() || value != local_message_) {
            all_threshold_messages_matched_ = false;
        }
        return value;
    }

private:
    mutable Bytes peer_kem_secret_;
    mutable Bytes peer_session_key_;
    mutable Bytes local_message_;
    mutable bool reference_decapsulation_matched_ = false;
    mutable bool all_threshold_messages_matched_ = true;
    mutable bool session_keys_matched_ = false;
    mutable std::size_t threshold_message_count_ = 0;
};

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

SignedTranscript make_signed(const MLKEMPublicKey& pk,
                             Bytes ciphertext) {
    Transcript transcript;
    transcript.peer_id = "peer-A";
    transcript.service_id = "service-S";
    transcript.peer_sig_fingerprint =
        simulated_key_fingerprint(
            simulated_public_key("peer-A-signing-key"));
    transcript.service_kem_fingerprint = pk.fingerprint();
    transcript.policy_id = "policy-1";
    transcript.peer_graph_id = "graph-1";
    transcript.threshold_key_id = "thkey-1";
    transcript.assistant_epoch = "epoch-1";
    transcript.tls_binding = "tlsbind-real-mlkem";
    transcript.ciphertext = std::move(ciphertext);
    const std::string digest = transcript_hash(transcript);
    const std::string signature = simulated_sign(
        "peer-A-signing-key",
        transcript_signature_input(transcript));
    return SignedTranscript{
        std::move(transcript),
        digest,
        signature,
    };
}

AdmissionPolicy policy_for(const MLKEMPublicKey& pk) {
    AdmissionConfig config;
    config.service_id = "service-S";
    config.service_kem_fingerprint = pk.fingerprint();
    config.policy_id = "policy-1";
    config.peer_graph_id = "graph-1";
    config.threshold_key_id = "thkey-1";
    config.assistant_epoch = "epoch-1";
    config.tls_binding = "tlsbind-real-mlkem";
    config.authorised_peers = {"peer-A"};
    config.authorised_callers = {"front-service"};
    config.peer_verify_keys = {{
        "peer-A",
        simulated_public_key("peer-A-signing-key"),
    }};
    config.peer_sig_fingerprints = {{
        "peer-A",
        simulated_key_fingerprint(
            simulated_public_key("peer-A-signing-key")),
    }};
    return AdmissionPolicy(std::move(config));
}

ShareContext share_context_for(const MLKEMPublicKey& pk) {
    return ShareContext{
        pk.fingerprint(),
        "thkey-1",
        "epoch-1",
        pk.adapter_profile_id(),
    };
}

} // namespace

int main() try {
    auto adapter =
        std::make_shared<ObservingRealMLKEM512Adapter>();
    require(adapter->is_real_mlkem(),
            "real adapter did not identify itself as real ML-KEM");

    auto keypair = adapter->keygen();
    auto encapsulation = adapter->encapsulate(keypair.public_key);
    const SignedTranscript request =
        make_signed(keypair.public_key, encapsulation.ciphertext);

    (void)adapter->decapsulate_reference(
        keypair.secret_state.reference_decapsulation_key,
        encapsulation.ciphertext);
    require(
        keypair.secret_state.reference_decapsulation_key
            .is_erased_internal() &&
            adapter->reference_decapsulation_matched(),
        "ordinary ML-KEM decapsulation did not match encapsulation");

    (void)adapter->dec_msg_local(
        keypair.secret_state.s_hat, encapsulation.ciphertext);
    ShareMap shares = Shamir23::share_and_erase(
        keypair.secret_state.s_hat,
        share_context_for(keypair.public_key));
    std::array<Assistant, 3> assistants{{
        Assistant{{1}, shares, policy_for(keypair.public_key), adapter},
        Assistant{{2}, shares, policy_for(keypair.public_key), adapter},
        Assistant{{3}, shares, policy_for(keypair.public_key), adapter},
    }};
    require(shares.empty(), "dealer retained real ML-KEM shares");

    Combiner combiner(adapter);
    constexpr std::array<std::array<std::size_t, 2>, 3> pairs{{
        {{0, 1}},
        {{0, 2}},
        {{1, 2}},
    }};
    std::optional<ThresholdDecryptionResult> front_result;
    for (const auto& pair : pairs) {
        auto first = assistants[pair[0]].process(
            request, "front-service");
        auto second = assistants[pair[1]].process(
            request, "front-service");
        require(first.has_value() && second.has_value(),
                "real ML-KEM assistant admission failed");
        std::vector<AssistantContribution> contributions;
        contributions.push_back(std::move(*first));
        contributions.push_back(std::move(*second));
        ThresholdDecryptionResult result = combiner.combine(
            contributions, request, "front-service");
        if (!front_result.has_value()) {
            front_result.emplace(std::move(result));
        }
    }
    require(
        adapter->threshold_message_count() == pairs.size() &&
            adapter->all_threshold_messages_matched(),
        "real threshold PKE.DecMsg differed from local reference");

    const std::string context = key_schedule_context(request);
    adapter->prepare_peer_session_for_test(
        encapsulation.peer_kem_secret, context);
    FrontService front_service(
        keypair.public_key,
        std::move(keypair.secret_state.z),
        adapter);
    const PublicResult valid_public_result = front_service.finalize(
        std::move(*front_result), "real-request-1");
    require(
        valid_public_result.status_class() == "processed" &&
            front_service.last_finalize_completed_internal() &&
            adapter->session_keys_matched(),
        "peer and recipient session keys did not match");

    Bytes modified_ciphertext = encapsulation.ciphertext;
    modified_ciphertext.front() ^= 0x01;
    const SignedTranscript modified_request =
        make_signed(keypair.public_key, std::move(modified_ciphertext));
    auto modified_first = assistants[0].process(
        modified_request, "front-service");
    auto modified_second = assistants[1].process(
        modified_request, "front-service");
    require(modified_first.has_value() && modified_second.has_value(),
            "signed modified ciphertext was not admitted");
    std::vector<AssistantContribution> modified_contributions;
    modified_contributions.push_back(std::move(*modified_first));
    modified_contributions.push_back(std::move(*modified_second));
    ThresholdDecryptionResult modified_result = combiner.combine(
        modified_contributions, modified_request, "front-service");
    const PublicResult modified_public_result = front_service.finalize(
        std::move(modified_result), "real-request-2");
    require(
        modified_public_result.status_class() ==
                valid_public_result.status_class() &&
            modified_public_result.request_id().size() ==
                valid_public_result.request_id().size() &&
            front_service.last_finalize_completed_internal() &&
            !adapter->session_keys_matched(),
        "real ML-KEM FO branch was exposed or selected the honest key");

    std::cout
        << "test_real_mlkem512 passed: FIPS 203 round trip, all "
           "(2,3) pairs, session-key equality, and branch hiding\n";
    return 0;
} catch (const std::exception& error) {
    std::cerr << "test_real_mlkem512 failed: "
              << error.what() << '\n';
    return 1;
}
