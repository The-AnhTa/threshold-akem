#include "rmtls_threshold_mlkem/front_service.hpp"
#include "rmtls_threshold_mlkem/public_log.hpp"

#include <array>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <type_traits>

using namespace rmtls;

namespace {

std::string bytes_as_hex(const Bytes& bytes);

bool public_text_contains_bytes(
    const std::vector<std::string>& public_text,
    const Bytes& value);

bool public_text_contains_coefficients(
    const std::vector<std::string>& public_text,
    const CoeffVector& value);

class AlternateProfileToyMLKEMAdapter final : public ToyMLKEMAdapter {
public:
    std::string_view profile_id() const noexcept override {
        return "toy-mlkem512-inner-alternate-test-profile";
    }
};

class LeakageObservingToyMLKEMAdapter final : public ToyMLKEMAdapter {
public:
    ~LeakageObservingToyMLKEMAdapter() override {
        for (CoeffVector& contribution : contributions_) {
            detail::erase_value(contribution);
        }
        for (CoeffVector& combined : combined_values_) {
            detail::erase_value(combined);
        }
        for (Bytes& value : byte_values_) {
            detail::erase_value(value);
        }
        detail::erase_value(last_peer_secret_);
        detail::erase_value(reference_peer_secret_);
    }

    bool fo_hook_called() const noexcept {
        return fo_hook_called_;
    }

    bool observed_required_values() const noexcept {
        return observed_peer_secret_ &&
               observed_m_prime_ &&
               observed_z_ &&
               observed_selected_secret_ &&
               !byte_values_.empty() &&
               !contributions_.empty() &&
               !combined_values_.empty() &&
               fo_hook_called_;
    }

    bool public_text_contains_observed_secret(
        const std::vector<std::string>& public_text) const {
        for (const Bytes& value : byte_values_) {
            if (public_text_contains_bytes(public_text, value)) {
                return true;
            }
        }
        for (const CoeffVector& contribution : contributions_) {
            if (public_text_contains_coefficients(
                    public_text, contribution)) {
                return true;
            }
        }
        for (const CoeffVector& combined : combined_values_) {
            if (public_text_contains_coefficients(public_text, combined)) {
                return true;
            }
        }
        return false;
    }

    bool scanner_detects_observed_value() const {
        if (byte_values_.empty()) {
            return false;
        }
        const std::vector<std::string> negative_control{
            "opaque=" + bytes_as_hex(byte_values_.front()),
        };
        return public_text_contains_observed_secret(negative_control);
    }

    void begin_fo_selection_check() const {
        detail::erase_value(reference_peer_secret_);
        reference_peer_secret_ = last_peer_secret_;
        fo_selection_matches_.clear();
    }

    bool observed_expected_fo_selections() const noexcept {
        return fo_selection_matches_.size() == 2 &&
               fo_selection_matches_[0] &&
               !fo_selection_matches_[1];
    }

protected:
    void observe_peer_kem_secret_for_test(
        const Bytes& peer_kem_secret) const override {
        byte_values_.push_back(peer_kem_secret);
        detail::erase_value(last_peer_secret_);
        last_peer_secret_ = peer_kem_secret;
        observed_peer_secret_ = true;
    }

    CoeffVector assistant_inner_impl(
        const CoeffVector& share,
        const Bytes& ciphertext) const override {
        CoeffVector result =
            ToyMLKEMAdapter::assistant_inner_impl(share, ciphertext);
        contributions_.push_back(result);
        return result;
    }

    Bytes dec_msg_from_combined_inner_impl(
        const CoeffVector& combined,
        const Bytes& ciphertext) const override {
        combined_values_.push_back(combined);
        Bytes result =
            ToyMLKEMAdapter::dec_msg_from_combined_inner_impl(
                combined, ciphertext);
        byte_values_.push_back(result);
        observed_m_prime_ = true;
        return result;
    }

    Bytes fo_validate_and_schedule_impl(
        const Bytes& m_prime,
        const Bytes& ciphertext,
        const MLKEMPublicKey& pk,
        const Bytes& z) const override {
        byte_values_.push_back(m_prime);
        byte_values_.push_back(z);
        observed_m_prime_ = true;
        observed_z_ = true;
        Bytes selected =
            ToyMLKEMAdapter::fo_validate_and_schedule_impl(
                m_prime, ciphertext, pk, z);
        byte_values_.push_back(selected);
        if (!reference_peer_secret_.empty()) {
            fo_selection_matches_.push_back(
                selected == reference_peer_secret_);
        }
        observed_selected_secret_ = true;
        fo_hook_called_ = true;
        return selected;
    }

private:
    mutable std::vector<CoeffVector> contributions_;
    mutable std::vector<CoeffVector> combined_values_;
    mutable std::vector<Bytes> byte_values_;
    mutable Bytes last_peer_secret_;
    mutable Bytes reference_peer_secret_;
    mutable std::vector<bool> fo_selection_matches_;
    mutable bool observed_peer_secret_ = false;
    mutable bool observed_m_prime_ = false;
    mutable bool observed_z_ = false;
    mutable bool observed_selected_secret_ = false;
    mutable bool fo_hook_called_ = false;
};

template <class T>
concept HasMutablePublicKeyBytes = requires(T& value) {
    value.bytes().at(0) = std::uint8_t{0};
};

template <class T>
concept HasRawStringLogEmit = requires(T& value, std::string entry) {
    value.emit(std::move(entry));
};

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::string bytes_as_string(const Bytes& bytes) {
    return std::string(bytes.begin(), bytes.end());
}

std::string bytes_as_hex(const Bytes& bytes) {
    std::ostringstream encoded;
    encoded << std::hex << std::setfill('0');
    for (std::uint8_t byte : bytes) {
        encoded << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return encoded.str();
}

bool public_text_contains_bytes(
    const std::vector<std::string>& public_text,
    const Bytes& value) {
    const std::array<std::string, 2> encodings{
        bytes_as_string(value),
        bytes_as_hex(value),
    };
    for (const std::string& text : public_text) {
        for (const std::string& encoding : encodings) {
            if (!encoding.empty() &&
                text.find(encoding) != std::string::npos) {
                return true;
            }
        }
    }
    return false;
}

bool public_text_contains_coefficients(
    const std::vector<std::string>& public_text,
    const CoeffVector& value) {
    Bytes encoded;
    encoded.reserve(value.size() * 2);
    for (Coeff coefficient : value) {
        encoded.push_back(
            static_cast<std::uint8_t>(coefficient & 0xffu));
        encoded.push_back(
            static_cast<std::uint8_t>(coefficient >> 8));
    }
    return public_text_contains_bytes(public_text, encoded);
}

bool public_text_contains_secret(
    const std::vector<std::string>& public_text,
    const std::vector<Bytes>& protected_values) {
    for (const Bytes& value : protected_values) {
        if (public_text_contains_bytes(public_text, value)) {
            return true;
        }
    }
    return false;
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

ThresholdDecryptionResult combine_pair(
    std::array<Assistant, 3>& assistants,
    const Combiner& combiner,
    const SignedTranscript& transcript) {
    auto first = assistants[0].process(transcript, "front-service");
    auto second = assistants[1].process(transcript, "front-service");
    require(first.has_value() && second.has_value(),
            "admitted assistants did not contribute");
    std::vector<AssistantContribution> contributions;
    contributions.push_back(std::move(*first));
    contributions.push_back(std::move(*second));
    return combiner.combine(
        contributions, transcript, "front-service");
}

} // namespace

int main() try {
    static_assert(!std::is_constructible_v<
                  FrontService,
                  const MLKEMPublicKey&,
                  Secret<Bytes>,
                  ToyMLKEMAdapter&&>);
    static_assert(std::is_constructible_v<
                  FrontService,
                  const MLKEMPublicKey&,
                  Secret<Bytes>,
                  MLKEMAdapterPtr>);
    static_assert(!HasMutablePublicKeyBytes<MLKEMPublicKey>);
    static_assert(!std::is_constructible_v<
                  PublicResult,
                  std::string,
                  std::string>);
    static_assert(!HasRawStringLogEmit<PublicLog>);
    using FinalizeMethod = decltype(&FrontService::finalize);
    static_assert(std::is_invocable_v<
                  FinalizeMethod,
                  const FrontService&,
                  ThresholdDecryptionResult,
                  const std::string&>);
    static_assert(!std::is_invocable_v<
                  FinalizeMethod,
                  const FrontService&,
                  const Secret<Bytes>&,
                  const Bytes&,
                  const std::string&>);

    const Bytes m_prime_marker(32, 0x4d);
    const Bytes z_marker(32, 0xa5);
    const std::vector<Bytes> protected_values{
        m_prime_marker,
        z_marker,
    };

    auto adapter =
        std::make_shared<LeakageObservingToyMLKEMAdapter>();
    auto null_adapter_kp =
        adapter->keygen_deterministic_for_test(6);
    bool null_adapter_rejected = false;
    try {
        (void)FrontService{
            null_adapter_kp.public_key,
            std::move(null_adapter_kp.secret_state.z),
            MLKEMAdapterPtr{},
        };
    } catch (const PrototypeError&) {
        null_adapter_rejected = true;
    }
    require(null_adapter_rejected,
            "front service accepted a null adapter handle");
    require(!null_adapter_kp.secret_state.z.is_erased_internal(),
            "failed front-service construction consumed z");

    auto alternate_adapter =
        std::make_shared<AlternateProfileToyMLKEMAdapter>();
    bool mismatched_adapter_rejected = false;
    try {
        (void)FrontService{
            null_adapter_kp.public_key,
            std::move(null_adapter_kp.secret_state.z),
            alternate_adapter,
        };
    } catch (const PrototypeError&) {
        mismatched_adapter_rejected = true;
    }
    require(mismatched_adapter_rejected,
            "front service accepted a public key from another adapter profile");
    require(!null_adapter_kp.secret_state.z.is_erased_internal(),
            "adapter profile rejection consumed z");

    auto kp = adapter->keygen_deterministic_for_test(7);
    auto enc =
        adapter->encapsulate_deterministic_for_test(kp.public_key, 8);
    Secret<Bytes> request_filter_m_prime{Bytes(m_prime_marker)};
    Secret<Bytes> request_filter_z{Bytes(z_marker)};
    PublicLog request_filter_log;
    const std::array<std::string, 3> accepted_request_ids{
        "wrong-front",
        "task-run",
        "validation-run",
    };
    for (const std::string& request_id : accepted_request_ids) {
        const PublicResult accepted =
            adapter->fo_validate_and_schedule(
                request_filter_m_prime,
                enc.ciphertext,
                kp.public_key,
                request_filter_z,
                request_id);
        request_filter_log.emit(accepted);
    }
    require(!request_filter_log.contains_forbidden_token(),
            "public identifier filter disagreed with public-log scanning");

    const std::array<std::string, 9> rejected_request_ids{
        "DELTA_I",
        "W",
        "Sk",
        "Fo-SuCcEsS",
        "InVaLiD",
        "BRANCH",
        "prefix_W_suffix",
        "prefix_SK_suffix",
        "prefix_VALID_suffix",
    };
    for (const std::string& request_id : rejected_request_ids) {
        bool rejected = false;
        try {
            (void)adapter->fo_validate_and_schedule(
                request_filter_m_prime,
                enc.ciphertext,
                kp.public_key,
                request_filter_z,
                request_id);
        } catch (const PrototypeError& error) {
            rejected =
                std::string(error.what()) ==
                "ML-KEM adapter operation failed";
        }
        require(rejected,
                "case-variant protected public identifier was accepted");
    }

    Bytes modified_ciphertext = enc.ciphertext;
    modified_ciphertext.at(1) ^= 0x55;
    const SignedTranscript valid_request =
        make_signed(kp.public_key, enc.ciphertext);
    const SignedTranscript modified_request =
        make_signed(kp.public_key, std::move(modified_ciphertext));

    ShareMap shares = Shamir23::share_and_erase(
        kp.secret_state.s_hat, share_context_for(kp.public_key));
    std::array<Assistant, 3> assistants{{
        Assistant{{1}, shares, policy_for(kp.public_key), adapter},
        Assistant{{2}, shares, policy_for(kp.public_key), adapter},
        Assistant{{3}, shares, policy_for(kp.public_key), adapter},
    }};
    Combiner combiner(adapter);
    ThresholdDecryptionResult valid_result =
        combine_pair(assistants, combiner, valid_request);
    ThresholdDecryptionResult modified_result =
        combine_pair(assistants, combiner, modified_request);
    ThresholdDecryptionResult wrong_front_result =
        combine_pair(assistants, combiner, valid_request);

    auto other_keypair =
        adapter->keygen_deterministic_for_test(70);
    FrontService other_front_service(
        other_keypair.public_key,
        std::move(other_keypair.secret_state.z),
        adapter);
    bool wrong_front_rejected = false;
    try {
        (void)other_front_service.finalize(
            std::move(wrong_front_result), "wrong-front");
    } catch (const PrototypeError&) {
        wrong_front_rejected = true;
    }
    require(wrong_front_rejected,
            "front service accepted a threshold result for another key");

    FrontService front_service(
        kp.public_key, std::move(kp.secret_state.z), adapter);
    adapter->begin_fo_selection_check();
    const PublicResult out_valid =
        front_service.finalize(std::move(valid_result), "req-1");
    const PublicResult out_modified =
        front_service.finalize(std::move(modified_result), "req-2");
    require(front_service.last_finalize_completed_internal(),
            "successful backend processing was not recorded internally");
    bool consumed_result_rejected = false;
    try {
        (void)front_service.finalize(
            std::move(valid_result), "reused-request");
    } catch (const PrototypeError&) {
        consumed_result_rejected = true;
    }
    require(consumed_result_rejected,
            "front service accepted a consumed threshold result");
    require(adapter->fo_hook_called(),
            "front-service wrapper did not invoke the backend FO hook");
    require(adapter->observed_expected_fo_selections(),
            "toy FO validation did not distinguish matching and modified ciphertexts internally");

    require(out_valid.request_id() == "req-1" &&
                out_valid.status_class() == "processed",
            "honest ciphertext public result changed shape");
    require(out_modified.request_id() == "req-2" &&
                out_modified.status_class() == "processed",
            "modified ciphertext public result changed shape");
    require(out_valid.status_class() == out_modified.status_class(),
            "public status revealed the toy FO selection");

    PublicLog log;
    log.emit(out_valid);
    log.emit(out_modified);
    require(!log.contains_forbidden_token(),
            "public log contains a forbidden token");

    std::vector<std::string> public_text{
        out_valid.request_id(),
        out_valid.status_class(),
        out_modified.request_id(),
        out_modified.status_class(),
    };
    public_text.insert(
        public_text.end(), log.entries().begin(), log.entries().end());
    public_text.insert(
        public_text.end(),
        request_filter_log.entries().begin(),
        request_filter_log.entries().end());
    require(public_text.size() == 9,
            "public output shape differed from the fixed response schema");
    require(!public_text_contains_secret(public_text, protected_values),
            "public output contains an encoded protected value");
    require(adapter->observed_required_values(),
            "leakage observer did not capture every protected value class");
    require(!adapter->public_text_contains_observed_secret(public_text),
            "public output contains an actual protected intermediate value");
    require(adapter->scanner_detects_observed_value(),
            "leakage scanner missed an observed protected value");

    std::cout << "test_leakage_and_branch_hiding passed\n";
    return 0;
} catch (const std::exception& error) {
    std::cerr << "test_leakage_and_branch_hiding failed: "
              << error.what() << '\n';
    return 1;
}
