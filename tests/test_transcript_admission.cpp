#include "rmtls_threshold_mlkem/mlkem_adapter.hpp"
#include "rmtls_threshold_mlkem/transcript.hpp"
#include <iostream>
#include <stdexcept>

using namespace rmtls;

static void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

static AdmissionConfig make_config(
    const std::string& fp,
    std::string peer_sig_fingerprint =
        simulated_key_fingerprint(
            simulated_public_key("peer-A-signing-key"))) {
    AdmissionConfig cfg;
    cfg.service_id = "service-S";
    cfg.service_kem_fingerprint = fp;
    cfg.policy_id = "policy-1";
    cfg.peer_graph_id = "graph-1";
    cfg.threshold_key_id = "thkey-1";
    cfg.assistant_epoch = "epoch-1";
    cfg.tls_binding = "tlsbind";
    cfg.authorised_peers = {"peer-A"};
    cfg.authorised_callers = {"front-service", "alternate-front"};
    cfg.peer_verify_keys = {{
        "peer-A",
        simulated_public_key("peer-A-signing-key"),
    }};
    cfg.peer_sig_fingerprints = {{
        "peer-A",
        std::move(peer_sig_fingerprint),
    }};
    return cfg;
}

static AdmissionPolicy make_policy(
    const std::string& fp,
    std::string peer_sig_fingerprint =
        simulated_key_fingerprint(
            simulated_public_key("peer-A-signing-key"))) {
    return AdmissionPolicy(
        make_config(fp, std::move(peer_sig_fingerprint)));
}

static SignedTranscript sign_t(Transcript t) {
    auto h = transcript_hash(t);
    const std::string signature = simulated_sign(
        "peer-A-signing-key", transcript_signature_input(t));
    return SignedTranscript{std::move(t), h, signature};
}

int main() try {
    ToyMLKEMAdapter adapter;
    auto kp = adapter.keygen_deterministic_for_test(1);
    auto enc =
        adapter.encapsulate_deterministic_for_test(kp.public_key, 2);
    Transcript t{"peer-A", "service-S",
                 simulated_key_fingerprint(
                     simulated_public_key("peer-A-signing-key")),
                 kp.public_key.fingerprint(),
                 "policy-1", "graph-1", "thkey-1", "epoch-1", "tlsbind", enc.ciphertext};
    auto policy = make_policy(kp.public_key.fingerprint());
    ReplayCache replay;
    auto st = sign_t(t);

    const std::string canonical = canonical_encode(t);
    const std::string prefix = canonical_encode_prefix(t);
    const std::string kem_record = canonical_encode_kem_record(t);
    const std::string authorization =
        canonical_encode_authorization_block(t);
    require(canonical == canonical_encode(t),
            "canonical transcript encoding was not deterministic");
    require(
        canonical.find(prefix) != std::string::npos &&
            canonical.find(kem_record) != std::string::npos &&
            canonical.find(authorization) != std::string::npos &&
            canonical.find(prefix_hash(t)) != std::string::npos,
        "canonical transcript did not bind its structured subobjects");
    Transcript independently_initialized;
    require(
        t.peer_nonce.size() >= 16 &&
            t.service_nonce.size() >= 16 &&
            independently_initialized.peer_nonce.size() >= 16 &&
            independently_initialized.service_nonce.size() >= 16 &&
            (t.peer_nonce != independently_initialized.peer_nonce ||
             t.service_nonce != independently_initialized.service_nonce),
        "default transcript nonces were not freshly generated");
    Transcript boundary_left = t;
    boundary_left.peer_id = "peer:A;service_id";
    Transcript boundary_right = t;
    boundary_right.peer_id = "peer";
    boundary_right.service_id = "A;service_id:service-S";
    require(canonical_encode(boundary_left) !=
                canonical_encode(boundary_right),
            "canonical transcript encoding was field-boundary ambiguous");

    const std::string sid = session_id(t);
    const std::string reqhash =
        request_hash(st, "front-service");
    require(!sid.empty() && !reqhash.empty(),
            "session or request identifier was empty");
    require(sid == session_id(t) &&
                reqhash == request_hash(st, "front-service"),
            "session or request identifier was not deterministic");
    require(
        request_hash(st, "alternate-front") != reqhash,
        "request hash did not bind the authenticated caller");

    require(policy.admit(st, "front-service", replay) == AdmissionStatus::Accept,
            "honest transcript was rejected");

    // Reusing exactly the same request is idempotently accepted.
    require(policy.admit(st, "front-service", replay) == AdmissionStatus::Accept,
            "idempotent request was rejected");

    auto short_ciphertext = t;
    short_ciphertext.ciphertext.pop_back();
    ReplayCache short_ciphertext_replay;
    require(
        policy.admit(
            sign_t(std::move(short_ciphertext)),
            "front-service",
            short_ciphertext_replay) == AdmissionStatus::Reject,
        "short signed ciphertext was admitted");

    auto long_ciphertext = t;
    long_ciphertext.ciphertext.push_back(0);
    ReplayCache long_ciphertext_replay;
    require(
        policy.admit(
            sign_t(std::move(long_ciphertext)),
            "front-service",
            long_ciphertext_replay) == AdmissionStatus::Reject,
        "long signed ciphertext was admitted");

    auto require_old_signature_rejection =
        [&](auto mutate, const char* message) {
            SignedTranscript changed = st;
            mutate(changed.transcript);
            require(
                canonical_encode(changed.transcript) != canonical &&
                    transcript_hash(changed.transcript) !=
                        st.transcript_hash &&
                    session_id(changed.transcript) != sid,
                "transcript mutation did not change canonical identifiers");
            ReplayCache changed_replay;
            require(
                policy.admit(
                    changed, "front-service", changed_replay) ==
                    AdmissionStatus::Reject,
                message);
        };
    require_old_signature_rejection(
        [](Transcript& value) { value.peer_id = "peer-B"; },
        "post-signature peer identity mutation was accepted");
    require_old_signature_rejection(
        [](Transcript& value) { value.service_id = "service-T"; },
        "post-signature recipient identity mutation was accepted");
    require_old_signature_rejection(
        [](Transcript& value) { value.peer_sig_fingerprint = "other-peer-fp"; },
        "post-signature peer key fingerprint mutation was accepted");
    require_old_signature_rejection(
        [](Transcript& value) { value.service_kem_fingerprint = "other-kem-fp"; },
        "post-signature recipient KEM fingerprint mutation was accepted");
    require_old_signature_rejection(
        [](Transcript& value) { value.policy_id = "policy-2"; },
        "post-signature policy mutation was accepted");
    require_old_signature_rejection(
        [](Transcript& value) { value.peer_graph_id = "graph-2"; },
        "post-signature peer graph mutation was accepted");
    require_old_signature_rejection(
        [](Transcript& value) { value.threshold_key_id = "thkey-2"; },
        "post-signature threshold key mutation was accepted");
    require_old_signature_rejection(
        [](Transcript& value) { value.assistant_epoch = "epoch-2"; },
        "post-signature assistant epoch mutation was accepted");
    require_old_signature_rejection(
        [](Transcript& value) { value.tls_binding = "other-tls-binding"; },
        "post-signature TLS binding mutation was accepted");
    require_old_signature_rejection(
        [](Transcript& value) { value.ciphertext[0] ^= 1; },
        "post-signature ciphertext mutation was accepted");
    require_old_signature_rejection(
        [](Transcript& value) { value.protocol = "other-protocol"; },
        "post-signature protocol mutation was accepted");
    require_old_signature_rejection(
        [](Transcript& value) { value.protocol_version = "2"; },
        "post-signature protocol version mutation was accepted");
    require_old_signature_rejection(
        [](Transcript& value) { value.deployment = "other-deployment"; },
        "post-signature deployment mutation was accepted");
    require_old_signature_rejection(
        [](Transcript& value) { value.direction = "reverse"; },
        "post-signature direction mutation was accepted");
    require_old_signature_rejection(
        [](Transcript& value) { value.peer_role = "recipient-service"; },
        "post-signature peer role mutation was accepted");
    require_old_signature_rejection(
        [](Transcript& value) { value.service_role = "encapsulating-peer"; },
        "post-signature service role mutation was accepted");
    require_old_signature_rejection(
        [](Transcript& value) { value.suite = "other-suite"; },
        "post-signature suite mutation was accepted");
    require_old_signature_rejection(
        [](Transcript& value) { value.peer_nonce[0] ^= 1; },
        "post-signature peer nonce mutation was accepted");
    require_old_signature_rejection(
        [](Transcript& value) { value.service_nonce[0] ^= 1; },
        "post-signature service nonce mutation was accepted");
    require_old_signature_rejection(
        [](Transcript& value) {
            value.peer_sig_cert_fingerprint = "other-peer-cert";
        },
        "post-signature peer certificate mutation was accepted");
    require_old_signature_rejection(
        [](Transcript& value) {
            value.service_kem_cert_fingerprint = "other-service-cert";
        },
        "post-signature service certificate mutation was accepted");
    require_old_signature_rejection(
        [](Transcript& value) { value.policy_version = "2"; },
        "post-signature policy version mutation was accepted");
    require_old_signature_rejection(
        [](Transcript& value) { value.policy_digest = "other-digest"; },
        "post-signature policy digest mutation was accepted");
    require_old_signature_rejection(
        [](Transcript& value) { value.not_before = 2; },
        "post-signature not-before mutation was accepted");
    require_old_signature_rejection(
        [](Transcript& value) { value.not_after = 1; },
        "post-signature validity-window mutation was accepted");
    require_old_signature_rejection(
        [](Transcript& value) { value.replay_window = 301; },
        "post-signature replay-window mutation was accepted");
    require_old_signature_rejection(
        [](Transcript& value) { value.threshold_t = 3; },
        "post-signature threshold mutation was accepted");
    require_old_signature_rejection(
        [](Transcript& value) { value.threshold_n = 4; },
        "post-signature threshold size mutation was accepted");
    require_old_signature_rejection(
        [](Transcript& value) {
            value.share_scheme_id = "other-sharing";
        },
        "post-signature share-scheme mutation was accepted");

    auto bad_signature = st;
    bad_signature.signature[0] ^= 1;
    require(request_hash(bad_signature, "front-service") != reqhash,
            "request hash did not bind the peer signature");
    ReplayCache bad_signature_replay;
    require(
        policy.admit(
            bad_signature, "front-service", bad_signature_replay) ==
            AdmissionStatus::Reject,
        "modified signature was accepted");

    auto require_resigned_policy_rejection =
        [&](auto mutate, const char* message) {
            Transcript changed = t;
            mutate(changed);
            ReplayCache changed_replay;
            require(
                policy.admit(
                    sign_t(std::move(changed)),
                    "front-service",
                    changed_replay) == AdmissionStatus::Reject,
                message);
        };
    require_resigned_policy_rejection(
        [](Transcript& value) { value.peer_id = "peer-B"; },
        "resigned unauthorised peer identity was accepted");
    require_resigned_policy_rejection(
        [](Transcript& value) { value.service_id = "service-T"; },
        "resigned wrong recipient identity was accepted");
    require_resigned_policy_rejection(
        [](Transcript& value) { value.peer_sig_fingerprint = "other-peer-fp"; },
        "resigned wrong peer key fingerprint was accepted");
    require_resigned_policy_rejection(
        [](Transcript& value) { value.service_kem_fingerprint = "other-kem-fp"; },
        "resigned wrong recipient KEM fingerprint was accepted");
    require_resigned_policy_rejection(
        [](Transcript& value) { value.policy_id = "policy-2"; },
        "resigned wrong policy was accepted");
    require_resigned_policy_rejection(
        [](Transcript& value) { value.peer_graph_id = "graph-2"; },
        "resigned wrong peer graph was accepted");
    require_resigned_policy_rejection(
        [](Transcript& value) { value.threshold_key_id = "thkey-2"; },
        "resigned wrong threshold key was accepted");
    require_resigned_policy_rejection(
        [](Transcript& value) { value.assistant_epoch = "epoch-2"; },
        "resigned wrong assistant epoch was accepted");
    require_resigned_policy_rejection(
        [](Transcript& value) { value.tls_binding = "other-tls-binding"; },
        "resigned wrong TLS binding was accepted");
    require_resigned_policy_rejection(
        [](Transcript& value) { value.protocol = "other-protocol"; },
        "resigned wrong protocol was accepted");
    require_resigned_policy_rejection(
        [](Transcript& value) { value.protocol_version = "2"; },
        "resigned wrong protocol version was accepted");
    require_resigned_policy_rejection(
        [](Transcript& value) { value.deployment = "other-deployment"; },
        "resigned wrong deployment was accepted");
    require_resigned_policy_rejection(
        [](Transcript& value) { value.suite = "other-suite"; },
        "resigned disallowed suite was accepted");
    require_resigned_policy_rejection(
        [](Transcript& value) { value.direction = "reverse"; },
        "resigned wrong direction was accepted");
    require_resigned_policy_rejection(
        [](Transcript& value) { value.peer_role = "recipient-service"; },
        "resigned wrong peer role was accepted");
    require_resigned_policy_rejection(
        [](Transcript& value) { value.service_role = "encapsulating-peer"; },
        "resigned wrong service role was accepted");
    require_resigned_policy_rejection(
        [](Transcript& value) {
            value.peer_sig_cert_fingerprint = "other-peer-cert";
        },
        "resigned wrong peer certificate fingerprint was accepted");
    require_resigned_policy_rejection(
        [](Transcript& value) {
            value.service_kem_cert_fingerprint = "other-service-cert";
        },
        "resigned wrong service certificate fingerprint was accepted");
    require_resigned_policy_rejection(
        [](Transcript& value) { value.peer_nonce.resize(15); },
        "resigned short peer nonce was accepted");
    require_resigned_policy_rejection(
        [](Transcript& value) { value.service_nonce.resize(15); },
        "resigned short service nonce was accepted");
    require_resigned_policy_rejection(
        [](Transcript& value) { value.not_before = 3; },
        "resigned not-yet-valid request was accepted");
    require_resigned_policy_rejection(
        [](Transcript& value) { value.not_after = 1; },
        "resigned expired request was accepted");
    require_resigned_policy_rejection(
        [](Transcript& value) { value.replay_window = 0; },
        "resigned zero replay window was accepted");
    require_resigned_policy_rejection(
        [](Transcript& value) { value.replay_window = 301; },
        "resigned non-policy replay window was accepted");
    require_resigned_policy_rejection(
        [](Transcript& value) { value.policy_version = "2"; },
        "resigned wrong policy version was accepted");
    require_resigned_policy_rejection(
        [](Transcript& value) { value.policy_digest = "other-digest"; },
        "resigned wrong policy digest was accepted");
    require_resigned_policy_rejection(
        [](Transcript& value) { value.threshold_t = 3; },
        "resigned wrong threshold was accepted");
    require_resigned_policy_rejection(
        [](Transcript& value) { value.threshold_n = 4; },
        "resigned wrong threshold parameters were accepted");
    require_resigned_policy_rejection(
        [](Transcript& value) {
            value.share_scheme_id = "other-sharing";
        },
        "resigned wrong share scheme was accepted");

    bool inconsistent_policy_rejected = false;
    try {
        (void)make_policy(
            kp.public_key.fingerprint(), "independent-peer-fp");
    } catch (const PrototypeError&) {
        inconsistent_policy_rejected = true;
    }
    require(inconsistent_policy_rejected,
            "policy accepted a fingerprint unrelated to its verification key");

    // Unauthorised caller rejects.
    ReplayCache unauthorised_replay;
    require(
        policy.admit(st, "external-peer", unauthorised_replay) ==
            AdmissionStatus::Reject,
            "unauthorised caller was accepted");

    // The same session under another authorised caller has a different request
    // hash and must conflict with the existing replay entry.
    require(
        policy.admit(st, "alternate-front", replay) ==
            AdmissionStatus::Reject,
        "same session with a different request hash was accepted");

    ReplayCache direct_replay;
    require(
        direct_replay.check_and_record(
            "sid", "thkey-1", "epoch-1", "req-a", 2, 301) ==
            AdmissionStatus::Accept &&
            direct_replay.check_and_record(
                "sid", "thkey-1", "epoch-1", "req-a", 2, 301) ==
                AdmissionStatus::Accept &&
            direct_replay.check_and_record(
                "sid", "thkey-1", "epoch-1", "req-b", 2, 301) ==
                AdmissionStatus::Reject,
        "replay cache did not enforce sid/request-hash consistency");
    require(
        direct_replay.check_and_record(
            "", "thkey-1", "epoch-1", "req-a", 2, 301) ==
                AdmissionStatus::Reject &&
            direct_replay.check_and_record(
                "sid-2", "thkey-1", "epoch-1", "", 2, 301) ==
                AdmissionStatus::Reject,
        "replay cache accepted an empty session or request identifier");
    require(
        direct_replay.check_and_record(
            "sid", "thkey-2", "epoch-1", "req-b", 2, 301) ==
                AdmissionStatus::Accept &&
            direct_replay.check_and_record(
                "sid", "thkey-1", "epoch-2", "req-c", 2, 301) ==
                AdmissionStatus::Accept,
        "replay cache did not separate threshold keys and epochs");
    require(
        direct_replay.check_and_record(
            "stale-sid", "thkey-1", "epoch-1", "req-stale", 302, 301) ==
            AdmissionStatus::Reject,
        "replay cache accepted an expired request");
    ReplayCache expiry_cleanup_replay;
    require(
        expiry_cleanup_replay.check_and_record(
            "cleanup-sid", "thkey-1", "epoch-1", "req-old", 2, 3) ==
                AdmissionStatus::Accept &&
            expiry_cleanup_replay.check_and_record(
                "cleanup-sid", "thkey-1", "epoch-1", "req-old", 4, 3) ==
                AdmissionStatus::Reject &&
            expiry_cleanup_replay.check_and_record(
                "cleanup-sid", "thkey-1", "epoch-1", "req-new", 4, 10) ==
                AdmissionStatus::Accept,
        "replay cache did not remove an encountered expired entry");

    AdmissionConfig stale_config =
        make_config(kp.public_key.fingerprint());
    stale_config.evaluation_time = 302;
    AdmissionPolicy stale_policy(std::move(stale_config));
    ReplayCache stale_policy_replay;
    require(
        stale_policy.admit(
            st, "front-service", stale_policy_replay) ==
            AdmissionStatus::Reject,
        "admission accepted a transcript outside its replay window");

    const std::string generic_config_error =
        "admission configuration rejected";
    auto require_invalid_config = [&](AdmissionConfig config) {
        bool rejected_generically = false;
        try {
            (void)AdmissionPolicy(std::move(config));
        } catch (const PrototypeError& error) {
            rejected_generically =
                error.what() == generic_config_error;
        }
        require(rejected_generically,
                "bad admission configuration was accepted or leaked detail");
    };

    require_invalid_config(AdmissionConfig{});
    {
        AdmissionConfig config =
            make_config(kp.public_key.fingerprint());
        config.service_id.clear();
        require_invalid_config(std::move(config));
    }
    {
        AdmissionConfig config =
            make_config(kp.public_key.fingerprint());
        config.authorised_callers.clear();
        require_invalid_config(std::move(config));
    }
    {
        AdmissionConfig config =
            make_config(kp.public_key.fingerprint());
        config.replay_window = 0;
        require_invalid_config(std::move(config));
    }
    {
        AdmissionConfig config =
            make_config(kp.public_key.fingerprint());
        config.peer_verify_keys["peer-A"].clear();
        require_invalid_config(std::move(config));
    }
    {
        AdmissionConfig config =
            make_config(kp.public_key.fingerprint());
        config.peer_sig_fingerprints["peer-A"] =
            "mismatched-fingerprint";
        require_invalid_config(std::move(config));
    }
    {
        AdmissionConfig config =
            make_config(kp.public_key.fingerprint());
        config.peer_verify_keys.emplace(
            "peer-B", "unreferenced-verification-key");
        require_invalid_config(std::move(config));
    }

    std::cout << "test_transcript_admission passed\n";
    return 0;
} catch (const std::exception& error) {
    std::cerr << "test_transcript_admission failed: " << error.what() << '\n';
    return 1;
}
