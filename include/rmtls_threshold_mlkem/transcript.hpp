#pragma once

#include "rmtls_threshold_mlkem/types.hpp"
#include <map>
#include <limits>
#include <optional>
#include <set>
#include <tuple>

namespace rmtls {

Bytes fresh_transcript_nonce(std::size_t size = 16);

struct Transcript {
    std::string peer_id;
    std::string service_id;
    std::string peer_sig_fingerprint;
    std::string service_kem_fingerprint;
    std::string policy_id;
    std::string peer_graph_id;
    std::string threshold_key_id;
    std::string assistant_epoch;
    std::string tls_binding;
    Bytes ciphertext;
    std::string protocol = "rMTLS-AuthKEM";
    std::string protocol_version = "1";
    std::string deployment = "single-process-research";
    std::string direction = "peer-to-recipient-kem-auth";
    std::string peer_role = "encapsulating-peer";
    std::string service_role = "recipient-service";
    std::string suite =
        "ML-KEM-512+Ed25519+SHA3-256+SHAKE256";
    Bytes peer_nonce = fresh_transcript_nonce();
    Bytes service_nonce = fresh_transcript_nonce();
    std::string peer_sig_cert_fingerprint = "peer-A-signing-cert";
    std::string service_kem_cert_fingerprint = "service-S-kem-cert";
    std::string policy_version = "1";
    std::string policy_digest = "policy-1-sha3-256";
    std::uint64_t not_before = 1;
    std::uint64_t not_after =
        std::numeric_limits<std::uint64_t>::max() - 1;
    std::uint64_t replay_window = 300;
    int threshold_t = 2;
    int threshold_n = 3;
    std::string share_scheme_id = "shamir-zq-coefficient-v1";
};

struct SignedTranscript {
    Transcript transcript;
    std::string transcript_hash;
    std::string signature;
};

std::string canonical_encode(const Transcript& t);
std::string canonical_encode_prefix(const Transcript& t);
std::string canonical_encode_kem_record(const Transcript& t);
std::string canonical_encode_authorization_block(const Transcript& t);
std::string prefix_hash(const Transcript& t);
std::string cryptographic_hash(const std::string& data);
std::string transcript_hash(const Transcript& t);
std::string ciphertext_hash(const Bytes& ciphertext);
std::string transcript_signature_input(const Transcript& t);
std::string simulated_public_key(const std::string& signing_key);
std::string simulated_sign(const std::string& signing_key,
                           const std::string& signature_input);
bool simulated_verify(const std::string& verify_key,
                      const std::string& signature_input,
                      const std::string& signature);
std::string simulated_key_fingerprint(const std::string& verify_key);
std::string session_id(const Transcript& t);
std::string request_hash(const SignedTranscript& st, const std::string& caller_id);
std::string key_schedule_context(const SignedTranscript& st);
std::size_t assistant_request_encoded_size(
    const SignedTranscript& st,
    const std::string& caller_id);
std::size_t assistant_response_encoded_size(
    const SignedTranscript& st,
    const std::string& caller_id,
    std::size_t selected_assistants);

struct AdmissionConfig {
    std::string service_id;
    std::string service_kem_fingerprint;
    std::string policy_id;
    std::string peer_graph_id;
    std::string threshold_key_id;
    std::string assistant_epoch;
    std::string tls_binding;
    std::string protocol = "rMTLS-AuthKEM";
    std::string protocol_version = "1";
    std::string deployment = "single-process-research";
    std::string direction = "peer-to-recipient-kem-auth";
    std::string peer_role = "encapsulating-peer";
    std::string service_role = "recipient-service";
    std::set<std::string> allowed_suites{
        "ML-KEM-512+Ed25519+SHA3-256+SHAKE256",
    };
    std::string peer_sig_cert_fingerprint = "peer-A-signing-cert";
    std::string service_kem_cert_fingerprint = "service-S-kem-cert";
    std::string policy_version = "1";
    std::string policy_digest = "policy-1-sha3-256";
    std::uint64_t evaluation_time = 2;
    std::uint64_t replay_window = 300;
    std::size_t minimum_nonce_bytes = 16;
    int threshold_t = 2;
    int threshold_n = 3;
    std::string share_scheme_id = "shamir-zq-coefficient-v1";
    std::set<std::string> authorised_peers;
    std::set<std::string> authorised_callers;
    std::map<std::string, std::string> peer_verify_keys;
    std::map<std::string, std::string> peer_sig_fingerprints;
};

enum class AdmissionStatus {
    Accept,
    Reject
};

class ReplayCache {
public:
    AdmissionStatus check_and_record(
        const std::string& sid,
        const std::string& threshold_key_id,
        const std::string& assistant_epoch,
        const std::string& reqhash,
        std::uint64_t current_time,
        std::uint64_t expires_at);
private:
    using ReplayKey =
        std::tuple<std::string, std::string, std::string>;
    struct ReplayEntry {
        std::string request_hash;
        std::uint64_t expires_at;
    };
    std::map<ReplayKey, ReplayEntry> seen_;
};

class AdmissionPolicy {
public:
    explicit AdmissionPolicy(AdmissionConfig cfg);
    AdmissionStatus admit(const SignedTranscript& st,
                          const std::string& caller_id,
                          ReplayCache& replay_cache) const;
private:
    AdmissionConfig cfg_;
};

} // namespace rmtls
