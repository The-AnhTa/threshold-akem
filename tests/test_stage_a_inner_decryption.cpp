#include "rmtls_threshold_mlkem/assistant.hpp"
#include "rmtls_threshold_mlkem/combiner.hpp"
#include "rmtls_threshold_mlkem/front_service.hpp"
#include "rmtls_threshold_mlkem/mlkem_adapter.hpp"
#include "rmtls_threshold_mlkem/sharing.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <iostream>
#include <stdexcept>
#include <type_traits>

using namespace rmtls;

namespace {

class ObservingToyMLKEMAdapter final : public ToyMLKEMAdapter {
public:
    ~ObservingToyMLKEMAdapter() override {
        detail::erase_value(reference_);
        detail::erase_value(expected_peer_secret_);
        detail::erase_value(expected_peer_session_key_);
    }

    bool all_threshold_results_match_reference() const {
        return all_results_match_;
    }

    std::size_t threshold_result_count() const {
        return threshold_result_count_;
    }

    bool honest_session_matched() const {
        return last_session_matched_;
    }

    bool honest_kem_secret_matched() const {
        return last_kem_secret_matched_;
    }

    bool reference_decapsulation_matched() const {
        return reference_decapsulation_matched_;
    }

    std::size_t completed_session_count() const {
        return completed_session_count_;
    }

protected:
    void observe_peer_kem_secret_for_test(
        const Bytes& peer_kem_secret) const override {
        detail::erase_value(expected_peer_secret_);
        expected_peer_secret_ = peer_kem_secret;
    }

    void observe_reference_kem_secret_for_test(
        const Bytes& reference_kem_secret) const override {
        reference_decapsulation_matched_ =
            !expected_peer_secret_.empty() &&
            reference_kem_secret == expected_peer_secret_;
    }

    void observe_peer_session_key_for_test(
        const Bytes& peer_session_key) const override {
        detail::erase_value(expected_peer_session_key_);
        expected_peer_session_key_ = peer_session_key;
    }

    void observe_service_session_key_for_test(
        const Bytes& service_session_key) const override {
        last_session_matched_ =
            !expected_peer_session_key_.empty() &&
            service_session_key == expected_peer_session_key_;
    }

    Bytes dec_msg_local_impl(const CoeffVector& s_hat,
                             const Bytes& ciphertext) const override {
        Bytes result =
            ToyMLKEMAdapter::dec_msg_local_impl(s_hat, ciphertext);
        detail::erase_value(reference_);
        reference_ = result;
        has_reference_ = true;
        return result;
    }

    Bytes dec_msg_from_combined_inner_impl(
        const CoeffVector& combined,
        const Bytes& ciphertext) const override {
        Bytes result = ToyMLKEMAdapter::dec_msg_from_combined_inner_impl(
            combined, ciphertext);
        ++threshold_result_count_;
        if (!has_reference_ || result != reference_) {
            all_results_match_ = false;
        }
        return result;
    }

    Bytes fo_validate_and_schedule_impl(
        const Bytes& m_prime,
        const Bytes& ciphertext,
        const MLKEMPublicKey& pk,
        const Bytes& z) const override {
        Bytes service_secret =
            ToyMLKEMAdapter::fo_validate_and_schedule_impl(
                m_prime, ciphertext, pk, z);
        ++completed_session_count_;
        last_kem_secret_matched_ =
            !expected_peer_secret_.empty() &&
            service_secret == expected_peer_secret_;
        return service_secret;
    }

private:
    mutable Bytes reference_;
    mutable Bytes expected_peer_secret_;
    mutable Bytes expected_peer_session_key_;
    mutable bool has_reference_ = false;
    mutable bool all_results_match_ = true;
    mutable bool last_session_matched_ = false;
    mutable bool last_kem_secret_matched_ = false;
    mutable bool reference_decapsulation_matched_ = false;
    mutable std::size_t threshold_result_count_ = 0;
    mutable std::size_t completed_session_count_ = 0;
};

class AlternateProfileToyMLKEMAdapter final : public ToyMLKEMAdapter {
public:
    std::string_view profile_id() const noexcept override {
        return "toy-mlkem512-inner-alternate-test-profile";
    }
};

class ExactReconstructionToyMLKEMAdapter final : public ToyMLKEMAdapter {
public:
    ~ExactReconstructionToyMLKEMAdapter() override {
        detail::erase_value(expected_);
    }

    void bind_expected_key(const MLKEMPublicKey& pk) {
        expected_.resize(MLKEM512_S_HAT_COEFFICIENTS);
        for (std::size_t index = 0; index < expected_.size(); ++index) {
            const std::uint32_t first =
                pk.bytes()[(2 * index) % pk.bytes().size()];
            const std::uint32_t second =
                pk.bytes()[(2 * index + 1) % pk.bytes().size()];
            expected_[index] = static_cast<Coeff>(
                (first + 257u * second + index) % Q);
        }
    }

    bool all_reconstructions_match() const noexcept {
        return all_reconstructions_match_;
    }

    std::size_t reconstruction_count() const noexcept {
        return reconstruction_count_;
    }

protected:
    CoeffVector assistant_inner_impl(
        const CoeffVector& share,
        const Bytes& ciphertext) const override {
        const std::size_t half =
            static_cast<std::size_t>(ciphertext.at(0) & 1u);
        const std::size_t offset =
            half * MLKEM512_INNER_COEFFICIENTS;
        return CoeffVector(
            share.begin() + static_cast<std::ptrdiff_t>(offset),
            share.begin() + static_cast<std::ptrdiff_t>(
                offset + MLKEM512_INNER_COEFFICIENTS));
    }

    Bytes dec_msg_from_combined_inner_impl(
        const CoeffVector& combined,
        const Bytes& ciphertext) const override {
        const std::size_t half =
            static_cast<std::size_t>(ciphertext.at(0) & 1u);
        const std::size_t offset =
            half * MLKEM512_INNER_COEFFICIENTS;
        ++reconstruction_count_;
        if (expected_.size() != MLKEM512_S_HAT_COEFFICIENTS ||
            !std::equal(
                combined.begin(),
                combined.end(),
                expected_.begin() + static_cast<std::ptrdiff_t>(offset))) {
            all_reconstructions_match_ = false;
        }
        return Bytes(MLKEM512_MESSAGE_BYTES, 0);
    }

private:
    CoeffVector expected_;
    mutable bool all_reconstructions_match_ = true;
    mutable std::size_t reconstruction_count_ = 0;
};

class ThrowingToyMLKEMAdapter final : public ToyMLKEMAdapter {
protected:
    GeneratedKeyMaterialForBackend keygen_impl() const override {
        throw PrototypeError("backend generated-key diagnostic");
    }

    EncapsulationMaterialForBackend encapsulate_impl(
        const MLKEMPublicKey&) const override {
        throw PrototypeError("backend encapsulation diagnostic");
    }

    Bytes dec_msg_local_impl(const CoeffVector& s_hat,
                             const Bytes&) const override {
        throw PrototypeError(
            "backend diagnostic " + std::to_string(s_hat.at(0)));
    }

    CoeffVector assistant_inner_impl(const CoeffVector& share,
                                     const Bytes&) const override {
        throw PrototypeError(
            "backend diagnostic " + std::to_string(share.at(0)));
    }

    Bytes dec_msg_from_combined_inner_impl(
        const CoeffVector& combined,
        const Bytes&) const override {
        throw PrototypeError(
            "backend diagnostic " + std::to_string(combined.at(0)));
    }

    Bytes fo_validate_and_schedule_impl(
        const Bytes& m_prime,
        const Bytes&,
        const MLKEMPublicKey&,
        const Bytes& z) const override {
        throw PrototypeError(
            "backend diagnostic " +
            std::to_string(m_prime.at(0) ^ z.at(0)));
    }
};

class MalformedToyMLKEMAdapter final : public ToyMLKEMAdapter {
public:
    enum class Mode {
        PublicKeyShape,
        SecretKeyShape,
        SecretKeyCoefficient,
        FallbackSecretShape,
        CiphertextShape,
        PeerSecretShape,
        PublicUShape,
        PublicUCoefficient,
        LocalMessageShape,
        AssistantInnerShape,
        AssistantInnerCoefficient,
        CombinedMessageShape,
    };

    explicit MalformedToyMLKEMAdapter(Mode mode) : mode_(mode) {}

protected:
    GeneratedKeyMaterialForBackend keygen_impl() const override {
        Bytes public_key(800, 0x11);
        CoeffVector s_hat(512, 7);
        Bytes z(32, 0x22);
        Bytes reference_key(MLKEM512_SECRET_KEY_BYTES, 0x77);
        if (mode_ == Mode::PublicKeyShape) {
            public_key.pop_back();
        } else if (mode_ == Mode::SecretKeyShape) {
            s_hat.pop_back();
        } else if (mode_ == Mode::SecretKeyCoefficient) {
            s_hat[0] = Q;
        } else if (mode_ == Mode::FallbackSecretShape) {
            z.pop_back();
        }
        return GeneratedKeyMaterialForBackend{
            std::move(public_key),
            Secret<CoeffVector>(std::move(s_hat)),
            Secret<Bytes>(std::move(z)),
            Secret<Bytes>(std::move(reference_key)),
        };
    }

    EncapsulationMaterialForBackend encapsulate_impl(
        const MLKEMPublicKey&) const override {
        Bytes ciphertext(768, 0x33);
        Bytes peer_secret(32, 0x44);
        if (mode_ == Mode::CiphertextShape) {
            ciphertext.pop_back();
        } else if (mode_ == Mode::PeerSecretShape) {
            peer_secret.pop_back();
        }
        return EncapsulationMaterialForBackend{
            std::move(ciphertext),
            Secret<Bytes>(std::move(peer_secret)),
        };
    }

    CoeffVector public_u_hat_from_ciphertext_impl(
        const Bytes&) const override {
        CoeffVector result(512, 9);
        if (mode_ == Mode::PublicUShape) {
            result.pop_back();
        } else if (mode_ == Mode::PublicUCoefficient) {
            result[0] = Q;
        }
        return result;
    }

    Bytes dec_msg_local_impl(const CoeffVector&,
                             const Bytes&) const override {
        return Bytes(
            mode_ == Mode::LocalMessageShape ? 31 : 32,
            0x55);
    }

    CoeffVector assistant_inner_impl(const CoeffVector&,
                                     const Bytes&) const override {
        CoeffVector result(
            mode_ == Mode::AssistantInnerShape ? 255 : 256,
            11);
        if (mode_ == Mode::AssistantInnerCoefficient) {
            result[0] = Q;
        }
        return result;
    }

    Bytes dec_msg_from_combined_inner_impl(
        const CoeffVector&,
        const Bytes&) const override {
        return Bytes(
            mode_ == Mode::CombinedMessageShape ? 31 : 32,
            0x66);
    }

    Bytes fo_validate_and_schedule_impl(
        const Bytes&,
        const Bytes&,
        const MLKEMPublicKey&,
        const Bytes&) const override {
        return Bytes(MLKEM512_SHARED_SECRET_BYTES, 0);
    }

private:
    Mode mode_;
};

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

SignedTranscript make_signed(const MLKEMPublicKey& pk, Bytes ciphertext) {
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
    transcript.tls_binding = "tlsbind-ctx";
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
    config.tls_binding = "tlsbind-ctx";
    config.authorised_peers = {"peer-A"};
    config.authorised_callers = {"front-service", "alternate-front"};
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
    static_assert(!std::is_constructible_v<Assistant, PartyId, ShareVector>);
    static_assert(!std::is_constructible_v<
                  Assistant,
                  PartyId,
                  ShareMap&,
                  AdmissionPolicy>);
    static_assert(!std::is_constructible_v<
                  Assistant,
                  PartyId,
                  ShareMap&,
                  AdmissionPolicy,
                  ToyMLKEMAdapter&&>);
    static_assert(std::is_constructible_v<
                  Assistant,
                  PartyId,
                  ShareMap&,
                  AdmissionPolicy,
                  MLKEMAdapterPtr>);
    static_assert(!std::is_copy_constructible_v<AssistantContribution>);
    static_assert(!std::is_copy_assignable_v<AssistantContribution>);
    static_assert(!std::is_default_constructible_v<AssistantContribution>);
    static_assert(!std::is_aggregate_v<AssistantContribution>);
    static_assert(!std::is_default_constructible_v<MLKEMPublicKey>);
    static_assert(!std::is_aggregate_v<MLKEMPublicKey>);
    static_assert(!std::is_constructible_v<
                  MLKEMPublicKey,
                  Bytes,
                  std::string,
                  std::string>);
    static_assert(!std::is_copy_constructible_v<ThresholdDecryptionResult>);
    static_assert(!std::is_copy_assignable_v<ThresholdDecryptionResult>);
    static_assert(!std::is_move_assignable_v<ThresholdDecryptionResult>);
    static_assert(!std::is_default_constructible_v<ThresholdDecryptionResult>);
    static_assert(!std::is_aggregate_v<ThresholdDecryptionResult>);
    using KeygenMethod = decltype(&MLKEMAdapter::keygen);
    using EncapsulateMethod = decltype(&MLKEMAdapter::encapsulate);
    static_assert(std::is_invocable_v<KeygenMethod, const MLKEMAdapter&>);
    static_assert(!std::is_invocable_v<
                  KeygenMethod,
                  const MLKEMAdapter&,
                  std::uint64_t>);
    static_assert(std::is_invocable_v<
                  EncapsulateMethod,
                  const MLKEMAdapter&,
                  const MLKEMPublicKey&>);
    static_assert(!std::is_invocable_v<
                  EncapsulateMethod,
                  const MLKEMAdapter&,
                  const MLKEMPublicKey&,
                  std::uint64_t>);

    using ProcessMethod = decltype(&Assistant::process);
    static_assert(std::is_invocable_v<
                  ProcessMethod,
                  Assistant&,
                  const SignedTranscript&,
                  const std::string&>);
    static_assert(!std::is_invocable_v<
                  ProcessMethod,
                  Assistant&,
                  const SignedTranscript&,
                  const std::string&,
                  const MLKEMAdapter&>);
    static_assert(!std::is_default_constructible_v<Combiner>);
    static_assert(!std::is_constructible_v<Combiner, ToyMLKEMAdapter&&>);
    static_assert(std::is_constructible_v<Combiner, MLKEMAdapterPtr>);
    using CombineMethod = decltype(&Combiner::combine);
    static_assert(std::is_invocable_v<
                  CombineMethod,
                  const Combiner&,
                  const std::vector<AssistantContribution>&,
                  const SignedTranscript&,
                  const std::string&>);
    static_assert(!std::is_invocable_v<
                  CombineMethod,
                  const Combiner&,
                  const std::vector<AssistantContribution>&,
                  const SignedTranscript&,
                  const std::string&,
                  const MLKEMAdapter&>);

    auto adapter = std::make_shared<ObservingToyMLKEMAdapter>();
    require(!adapter->is_real_mlkem(), "toy adapter reported itself as real ML-KEM");
    std::cout << "TOY-ONLY backend: " << adapter->name() << '\n';

    MLKEMKeyPair seedless_keypair = adapter->keygen();
    Encapsulation seedless_encapsulation =
        adapter->encapsulate(seedless_keypair.public_key);
    require(seedless_keypair.public_key.adapter_profile_id() ==
                adapter->profile_id() &&
                !seedless_encapsulation.ciphertext.empty(),
            "seedless adapter operations did not preserve the profile");

    MLKEMKeyPair keypair =
        adapter->keygen_deterministic_for_test(123);
    Encapsulation encapsulation =
        adapter->encapsulate(keypair.public_key);
    const SignedTranscript signed_transcript =
        make_signed(keypair.public_key, encapsulation.ciphertext);
    (void)adapter->decapsulate_reference(
        keypair.secret_state.reference_decapsulation_key,
        encapsulation.ciphertext);
    require(adapter->reference_decapsulation_matched(),
            "ordinary toy decapsulation did not match encapsulation");
    (void)adapter->dec_msg_local(
        keypair.secret_state.s_hat, encapsulation.ciphertext);
    ShareMap shares = Shamir23::share_and_erase(
        keypair.secret_state.s_hat, share_context_for(keypair.public_key));
    require(keypair.secret_state.s_hat.is_erased_internal(),
            "dealer retained the inner decryption key after sharing");

    MLKEMKeyPair null_adapter_keypair =
        adapter->keygen_deterministic_for_test(122);
    ShareMap null_adapter_shares = Shamir23::share_and_erase(
        null_adapter_keypair.secret_state.s_hat,
        share_context_for(null_adapter_keypair.public_key));
    bool null_assistant_adapter_rejected = false;
    try {
        (void)Assistant{
            {1},
            null_adapter_shares,
            policy_for(null_adapter_keypair.public_key),
            MLKEMAdapterPtr{},
        };
    } catch (const PrototypeError&) {
        null_assistant_adapter_rejected = true;
    }
    require(null_assistant_adapter_rejected,
            "assistant accepted a null adapter handle");
    require(null_adapter_shares.size() == 3,
            "failed assistant construction consumed a dealer share");

    auto alternate_adapter =
        std::make_shared<AlternateProfileToyMLKEMAdapter>();
    bool mismatched_assistant_adapter_rejected = false;
    try {
        (void)Assistant{
            {1},
            null_adapter_shares,
            policy_for(null_adapter_keypair.public_key),
            alternate_adapter,
        };
    } catch (const PrototypeError&) {
        mismatched_assistant_adapter_rejected = true;
    }
    require(mismatched_assistant_adapter_rejected,
            "assistant accepted a dealer share from another adapter profile");
    require(null_adapter_shares.size() == 3,
            "adapter profile rejection consumed a dealer share");

    std::array<Assistant, 3> assistants{{
        Assistant{{1}, shares, policy_for(keypair.public_key), adapter},
        Assistant{{2}, shares, policy_for(keypair.public_key), adapter},
        Assistant{{3}, shares, policy_for(keypair.public_key), adapter},
    }};
    require(shares.empty(), "dealer retained shares after assistant provisioning");
    bool exhausted_dealer_rejected = false;
    try {
        (void)Assistant{
            {1},
            shares,
            policy_for(keypair.public_key),
            adapter,
        };
    } catch (const PrototypeError&) {
        exhausted_dealer_rejected = true;
    }
    require(exhausted_dealer_rejected,
            "assistant provisioning reused an extracted dealer share");
    require(shares.empty(),
            "failed provisioning changed the exhausted dealer collection");

    bool null_combiner_adapter_rejected = false;
    try {
        (void)Combiner{MLKEMAdapterPtr{}};
    } catch (const PrototypeError&) {
        null_combiner_adapter_rejected = true;
    }
    require(null_combiner_adapter_rejected,
            "combiner accepted a null adapter handle");
    Combiner combiner(adapter);
    constexpr std::array<std::array<std::size_t, 2>, 3> pairs{{
        {{0, 1}},
        {{0, 2}},
        {{1, 2}},
    }};

    for (const auto& pair : pairs) {
        auto first = assistants[pair[0]].process(
            signed_transcript, "front-service");
        auto second = assistants[pair[1]].process(
            signed_transcript, "front-service");
        require(first.has_value() && second.has_value(),
                "admitted assistant did not contribute");

        std::vector<AssistantContribution> contributions;
        contributions.push_back(std::move(*first));
        contributions.push_back(std::move(*second));
        (void)combiner.combine(
            contributions, signed_transcript, "front-service");
    }
    require(adapter->threshold_result_count() == pairs.size(),
            "toy adapter did not observe every threshold result");
    require(adapter->all_threshold_results_match_reference(),
            "threshold result differs from direct toy adapter");

    auto exact_adapter =
        std::make_shared<ExactReconstructionToyMLKEMAdapter>();
    MLKEMKeyPair exact_keypair =
        exact_adapter->keygen_deterministic_for_test(9123);
    exact_adapter->bind_expected_key(exact_keypair.public_key);
    Encapsulation exact_encapsulation =
        exact_adapter->encapsulate_deterministic_for_test(
            exact_keypair.public_key, 9124);
    ShareMap exact_shares = Shamir23::share_and_erase(
        exact_keypair.secret_state.s_hat,
        share_context_for(exact_keypair.public_key));
    std::array<Assistant, 3> exact_assistants{{
        Assistant{
            {1},
            exact_shares,
            policy_for(exact_keypair.public_key),
            exact_adapter,
        },
        Assistant{
            {2},
            exact_shares,
            policy_for(exact_keypair.public_key),
            exact_adapter,
        },
        Assistant{
            {3},
            exact_shares,
            policy_for(exact_keypair.public_key),
            exact_adapter,
        },
    }};
    require(exact_shares.empty(),
            "exact reconstruction test retained dealer shares");
    Combiner exact_combiner(exact_adapter);
    for (std::uint8_t half = 0; half < 2; ++half) {
        Bytes half_ciphertext = exact_encapsulation.ciphertext;
        half_ciphertext.at(0) = half;
        const SignedTranscript half_request = make_signed(
            exact_keypair.public_key, std::move(half_ciphertext));
        for (const auto& pair : pairs) {
            auto first = exact_assistants[pair[0]].process(
                half_request, "front-service");
            auto second = exact_assistants[pair[1]].process(
                half_request, "front-service");
            require(first.has_value() && second.has_value(),
                    "exact reconstruction contribution was not produced");
            std::vector<AssistantContribution> contributions;
            contributions.push_back(std::move(*first));
            contributions.push_back(std::move(*second));
            (void)exact_combiner.combine(
                contributions, half_request, "front-service");
        }
    }
    require(
        exact_adapter->reconstruction_count() == 2 * pairs.size() &&
            exact_adapter->all_reconstructions_match(),
        "Shamir reconstruction did not recover all 512 coefficients for every pair");

    auto session_first = assistants[0].process(
        signed_transcript, "front-service");
    auto session_second = assistants[1].process(
        signed_transcript, "front-service");
    require(session_first.has_value() && session_second.has_value(),
            "honest-session contributions were not produced");
    std::vector<AssistantContribution> session_contributions;
    session_contributions.push_back(std::move(*session_first));
    session_contributions.push_back(std::move(*session_second));
    ThresholdDecryptionResult session_result = combiner.combine(
        session_contributions, signed_transcript, "front-service");
    FrontService front_service(
        keypair.public_key,
        std::move(keypair.secret_state.z),
        adapter);
    adapter->prepare_peer_session_for_test(
        encapsulation.peer_kem_secret,
        key_schedule_context(signed_transcript));
    const PublicResult session_public_result =
        front_service.finalize(
            std::move(session_result), "honest-session");
    require(session_public_result.status_class() == "processed",
            "honest toy public result changed");
    require(front_service.last_finalize_completed_internal() &&
                adapter->completed_session_count() >= 2,
            "honest toy session did not complete");
    require(adapter->honest_kem_secret_matched(),
            "honest peer and front service derived different toy KEM secrets");
    require(adapter->honest_session_matched(),
            "honest peer and front service derived different toy session keys");

    Bytes modified_session_ciphertext = encapsulation.ciphertext;
    modified_session_ciphertext[0] ^= 1;
    const SignedTranscript modified_session_request =
        make_signed(
            keypair.public_key,
            std::move(modified_session_ciphertext));
    auto modified_session_first = assistants[0].process(
        modified_session_request, "front-service");
    auto modified_session_second = assistants[1].process(
        modified_session_request, "front-service");
    require(modified_session_first.has_value() &&
                modified_session_second.has_value(),
            "modified-session contributions were not produced");
    std::vector<AssistantContribution> modified_session_contributions;
    modified_session_contributions.push_back(
        std::move(*modified_session_first));
    modified_session_contributions.push_back(
        std::move(*modified_session_second));
    ThresholdDecryptionResult modified_session_result = combiner.combine(
        modified_session_contributions,
        modified_session_request,
        "front-service");
    const PublicResult modified_session_public_result =
        front_service.finalize(
            std::move(modified_session_result),
            "modified-session");
    require(modified_session_public_result.status_class() == "processed" &&
                front_service.last_finalize_completed_internal() &&
                adapter->completed_session_count() >= 3 &&
                !adapter->honest_session_matched(),
            "modified toy ciphertext did not select the fallback session secret");

    Bytes short_ciphertext = encapsulation.ciphertext;
    short_ciphertext.pop_back();
    const SignedTranscript malformed_request =
        make_signed(keypair.public_key, std::move(short_ciphertext));
    bool malformed_request_threw = false;
    std::optional<AssistantContribution> malformed_contribution;
    try {
        malformed_contribution = assistants[0].process(
            malformed_request, "front-service");
    } catch (...) {
        malformed_request_threw = true;
    }
    require(!malformed_request_threw &&
                !malformed_contribution.has_value(),
            "assistant did not reject malformed ciphertext at admission");

    auto profile_first = assistants[0].process(
        signed_transcript, "front-service");
    auto profile_second = assistants[1].process(
        signed_transcript, "front-service");
    require(profile_first.has_value() && profile_second.has_value(),
            "adapter-profile test contributions were not produced");
    std::vector<AssistantContribution> profile_contributions;
    profile_contributions.push_back(std::move(*profile_first));
    profile_contributions.push_back(std::move(*profile_second));
    Combiner alternate_combiner(alternate_adapter);
    bool mismatched_combiner_adapter_rejected = false;
    try {
        (void)alternate_combiner.combine(
            profile_contributions, signed_transcript, "front-service");
    } catch (const PrototypeError&) {
        mismatched_combiner_adapter_rejected = true;
    }
    require(mismatched_combiner_adapter_rejected,
            "combiner accepted contributions from another adapter profile");

    auto duplicate = assistants[0].process(
        signed_transcript, "front-service");
    require(duplicate.has_value(),
            "duplicate-party test contribution was not produced");
    std::vector<AssistantContribution> duplicate_contributions;
    duplicate_contributions.push_back(std::move(*duplicate));
    auto duplicate_again = assistants[0].process(
        signed_transcript, "front-service");
    require(duplicate_again.has_value(),
            "duplicate-party retry contribution was not produced");
    duplicate_contributions.push_back(std::move(*duplicate_again));
    bool duplicate_party_rejected = false;
    try {
        (void)combiner.combine(
            duplicate_contributions, signed_transcript, "front-service");
    } catch (const PrototypeError&) {
        duplicate_party_rejected = true;
    }
    require(duplicate_party_rejected,
            "combiner accepted two contributions from the same assistant");

    auto unauthorised = assistants[0].process(
        signed_transcript, "external-peer");
    require(!unauthorised.has_value(), "assistant bypassed transcript admission");

    auto replay_conflict = assistants[0].process(
        signed_transcript, "alternate-front");
    require(!replay_conflict.has_value(),
            "assistant accepted same session under a conflicting request hash");

    auto first = assistants[0].process(
        signed_transcript, "front-service");
    auto second = assistants[1].process(
        signed_transcript, "front-service");
    require(first.has_value() && second.has_value(),
            "binding test contributions were not produced");
    std::vector<AssistantContribution> old_contributions;
    old_contributions.push_back(std::move(*first));
    old_contributions.push_back(std::move(*second));

    Bytes modified_ciphertext = encapsulation.ciphertext;
    modified_ciphertext[0] ^= 1;
    const SignedTranscript modified_request =
        make_signed(keypair.public_key, std::move(modified_ciphertext));
    bool changed_request_rejected = false;
    try {
        (void)combiner.combine(
            old_contributions, modified_request, "front-service");
    } catch (const PrototypeError&) {
        changed_request_rejected = true;
    }
    require(changed_request_rejected,
            "combiner accepted contributions for a different ciphertext request");

    bool changed_caller_rejected = false;
    try {
        (void)combiner.combine(
            old_contributions, signed_transcript, "different-front");
    } catch (const PrototypeError&) {
        changed_caller_rejected = true;
    }
    require(changed_caller_rejected,
            "combiner accepted contributions under a different caller binding");

    auto require_context_mismatch_rejected =
        [&](std::uint64_t seed, int field) {
            MLKEMKeyPair mismatch_keypair =
                adapter->keygen_deterministic_for_test(seed);
            Encapsulation mismatch_encapsulation =
                adapter->encapsulate_deterministic_for_test(
                    mismatch_keypair.public_key, seed + 1);
            ShareContext mismatched_context =
                share_context_for(mismatch_keypair.public_key);
            if (field == 0) {
                mismatched_context.service_kem_fingerprint =
                    "different-service-kem-fingerprint";
            } else if (field == 1) {
                mismatched_context.threshold_key_id =
                    "different-threshold-key";
            } else {
                mismatched_context.assistant_epoch = "different-epoch";
            }
            ShareMap mismatched_shares = Shamir23::share_and_erase(
                mismatch_keypair.secret_state.s_hat, mismatched_context);
            Assistant mismatched_assistant{
                {1},
                mismatched_shares,
                policy_for(mismatch_keypair.public_key),
                adapter,
            };
            const SignedTranscript request = make_signed(
                mismatch_keypair.public_key, mismatch_encapsulation.ciphertext);
            auto contribution =
                mismatched_assistant.process(request, "front-service");
            require(!contribution.has_value(),
                    "assistant accepted mismatched provisioned share context");
        };
    for (int field = 0; field < 3; ++field) {
        require_context_mismatch_rejected(
            static_cast<std::uint64_t>(789 + field * 10), field);
    }

    MLKEMKeyPair generation_a_keypair =
        adapter->keygen_deterministic_for_test(321);
    MLKEMKeyPair generation_b_keypair =
        adapter->keygen_deterministic_for_test(321);
    Encapsulation generation_encapsulation =
        adapter->encapsulate_deterministic_for_test(
            generation_a_keypair.public_key, 654);
    const SignedTranscript generation_request = make_signed(
        generation_a_keypair.public_key, generation_encapsulation.ciphertext);
    ShareMap generation_a_shares = Shamir23::share_and_erase(
        generation_a_keypair.secret_state.s_hat,
        share_context_for(generation_a_keypair.public_key));
    ShareMap generation_b_shares = Shamir23::share_and_erase(
        generation_b_keypair.secret_state.s_hat,
        share_context_for(generation_b_keypair.public_key));
    Assistant generation_a_assistant{
        {1},
        generation_a_shares,
        policy_for(generation_a_keypair.public_key),
        adapter,
    };
    Assistant generation_b_assistant{
        {2},
        generation_b_shares,
        policy_for(generation_b_keypair.public_key),
        adapter,
    };
    auto generation_a_contribution =
        generation_a_assistant.process(generation_request, "front-service");
    auto generation_b_contribution =
        generation_b_assistant.process(generation_request, "front-service");
    require(generation_a_contribution.has_value() &&
                generation_b_contribution.has_value(),
            "generation-binding test contributions were not produced");
    std::vector<AssistantContribution> mixed_generation_contributions;
    mixed_generation_contributions.push_back(
        std::move(*generation_a_contribution));
    mixed_generation_contributions.push_back(
        std::move(*generation_b_contribution));
    bool mixed_generation_rejected = false;
    try {
        (void)combiner.combine(
            mixed_generation_contributions,
            generation_request,
            "front-service");
    } catch (const PrototypeError&) {
        mixed_generation_rejected = true;
    }
    require(mixed_generation_rejected,
            "combiner accepted contributions from different share generations");

    ThrowingToyMLKEMAdapter throwing_adapter;
    const std::string generic_adapter_error =
        "ML-KEM adapter operation failed";
    auto require_sanitized_adapter_error = [&](auto&& operation) {
        bool sanitized = false;
        try {
            operation();
        } catch (const PrototypeError& error) {
            sanitized = error.what() == generic_adapter_error;
        }
        require(sanitized,
                "secret-consuming adapter exception was not sanitized");
    };
    Secret<CoeffVector> diagnostic_coefficients(
        CoeffVector(512, 123));
    Secret<CoeffVector> diagnostic_combined(
        CoeffVector(256, 456));
    Secret<Bytes> diagnostic_m_prime(Bytes(32, 0x5a));
    Secret<Bytes> diagnostic_z(Bytes(32, 0xa5));
    require_sanitized_adapter_error([&] {
        (void)throwing_adapter.keygen();
    });
    require_sanitized_adapter_error([&] {
        (void)throwing_adapter.encapsulate(keypair.public_key);
    });
    require_sanitized_adapter_error([&] {
        (void)throwing_adapter.dec_msg_local(
            diagnostic_coefficients, encapsulation.ciphertext);
    });
    require_sanitized_adapter_error([&] {
        (void)throwing_adapter.assistant_inner(
            diagnostic_coefficients, encapsulation.ciphertext);
    });
    require_sanitized_adapter_error([&] {
        (void)throwing_adapter.dec_msg_from_combined_inner(
            diagnostic_combined, encapsulation.ciphertext);
    });
    const PublicResult backend_failure_result =
        throwing_adapter.fo_validate_and_schedule(
            diagnostic_m_prime,
            encapsulation.ciphertext,
            keypair.public_key,
            diagnostic_z,
            "diagnostic-request");
    require(backend_failure_result.request_id() == "diagnostic-request" &&
                backend_failure_result.status_class() == "processed",
            "backend FO exception changed the public result shape");

    MLKEMKeyPair failure_keypair =
        adapter->keygen_deterministic_for_test(4001);
    Encapsulation failure_encapsulation =
        adapter->encapsulate_deterministic_for_test(
            failure_keypair.public_key, 4002);
    const SignedTranscript failure_request = make_signed(
        failure_keypair.public_key, failure_encapsulation.ciphertext);
    ShareMap failure_shares = Shamir23::share_and_erase(
        failure_keypair.secret_state.s_hat,
        share_context_for(failure_keypair.public_key));
    std::array<Assistant, 2> failure_assistants{{
        Assistant{
            {1},
            failure_shares,
            policy_for(failure_keypair.public_key),
            adapter,
        },
        Assistant{
            {2},
            failure_shares,
            policy_for(failure_keypair.public_key),
            adapter,
        },
    }};
    auto failure_first = failure_assistants[0].process(
        failure_request, "front-service");
    auto failure_second = failure_assistants[1].process(
        failure_request, "front-service");
    require(failure_first.has_value() && failure_second.has_value(),
            "backend-failure test contributions were not produced");
    std::vector<AssistantContribution> failure_contributions;
    failure_contributions.push_back(std::move(*failure_first));
    failure_contributions.push_back(std::move(*failure_second));
    ThresholdDecryptionResult failure_result = combiner.combine(
        failure_contributions, failure_request, "front-service");
    auto throwing_adapter_handle =
        std::make_shared<ThrowingToyMLKEMAdapter>();
    FrontService failure_front_service(
        failure_keypair.public_key,
        std::move(failure_keypair.secret_state.z),
        throwing_adapter_handle);
    const PublicResult failure_public_result =
        failure_front_service.finalize(
            std::move(failure_result), "backend-failure");
    require(
        failure_public_result.request_id() == "backend-failure" &&
            failure_public_result.status_class() == "processed" &&
            !failure_front_service.last_finalize_completed_internal(),
        "front service did not retain the internal backend-failure signal");

    require_sanitized_adapter_error([&] {
        (void)throwing_adapter.fo_validate_and_schedule(
            diagnostic_m_prime,
            encapsulation.ciphertext,
            keypair.public_key,
            diagnostic_z,
            "FO-success");
    });

    using MalformedMode = MalformedToyMLKEMAdapter::Mode;
    for (MalformedMode mode : {
             MalformedMode::PublicKeyShape,
             MalformedMode::SecretKeyShape,
             MalformedMode::SecretKeyCoefficient,
             MalformedMode::FallbackSecretShape,
         }) {
        MalformedToyMLKEMAdapter malformed_adapter(mode);
        require_sanitized_adapter_error([&] {
            (void)malformed_adapter.keygen();
        });
    }
    for (MalformedMode mode : {
             MalformedMode::CiphertextShape,
             MalformedMode::PeerSecretShape,
         }) {
        MalformedToyMLKEMAdapter malformed_adapter(mode);
        require_sanitized_adapter_error([&] {
            (void)malformed_adapter.encapsulate(keypair.public_key);
        });
    }
    for (MalformedMode mode : {
             MalformedMode::PublicUShape,
             MalformedMode::PublicUCoefficient,
         }) {
        MalformedToyMLKEMAdapter malformed_adapter(mode);
        require_sanitized_adapter_error([&] {
            (void)malformed_adapter.public_u_hat_from_ciphertext(
                encapsulation.ciphertext);
        });
    }
    {
        MalformedToyMLKEMAdapter malformed_adapter(
            MalformedMode::LocalMessageShape);
        require_sanitized_adapter_error([&] {
            (void)malformed_adapter.dec_msg_local(
                diagnostic_coefficients, encapsulation.ciphertext);
        });
    }
    for (MalformedMode mode : {
             MalformedMode::AssistantInnerShape,
             MalformedMode::AssistantInnerCoefficient,
         }) {
        MalformedToyMLKEMAdapter malformed_adapter(mode);
        require_sanitized_adapter_error([&] {
            (void)malformed_adapter.assistant_inner(
                diagnostic_coefficients, encapsulation.ciphertext);
        });
    }
    {
        MalformedToyMLKEMAdapter malformed_adapter(
            MalformedMode::CombinedMessageShape);
        require_sanitized_adapter_error([&] {
            (void)malformed_adapter.dec_msg_from_combined_inner(
                diagnostic_combined, encapsulation.ciphertext);
        });
    }

    std::cout << "test_stage_a_inner_decryption passed: pairs {1,2}, {1,3}, {2,3}\n";
    return 0;
} catch (const std::exception& error) {
    std::cerr << "test_stage_a_inner_decryption failed: " << error.what() << '\n';
    return 1;
}
