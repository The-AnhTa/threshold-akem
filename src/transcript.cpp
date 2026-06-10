#include "rmtls_threshold_mlkem/transcript.hpp"
#include "mlkem_native_bridge.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sstream>
#include <string_view>

namespace rmtls {
namespace {

constexpr std::string_view TRANSCRIPT_LABEL =
    "rMTLS-AuthKEM-v1-transcript";
constexpr std::string_view PREFIX_LABEL =
    "rMTLS-AuthKEM-v1-prefix";
constexpr std::string_view KEM_RECORD_LABEL =
    "rMTLS-AuthKEM-v1-kem-record";
constexpr std::string_view CIPHERTEXT_LABEL =
    "rMTLS-AuthKEM-v1-ciphertext";
constexpr std::string_view SESSION_ID_LABEL =
    "rMTLS-AuthKEM-v1-session-id";
constexpr std::string_view REQUEST_HASH_LABEL =
    "rMTLS-AuthKEM-v1-assistant-request-hash";
constexpr std::string_view REQUEST_VERSION =
    "rMTLS-AuthKEM-Assistant-v1";
constexpr std::string_view SIGNATURE_LABEL =
    "rMTLS-AuthKEM-v1-peer-authz P-to-S";

[[noreturn]] void reject_invalid_config() {
    throw PrototypeError("admission configuration rejected");
}

void append_length(std::string& output, std::size_t length) {
    char buffer[32];
    const auto [end, error] =
        std::to_chars(std::begin(buffer), std::end(buffer), length);
    if (error != std::errc{}) {
        throw PrototypeError("canonical encoding failed");
    }
    output.append(buffer, end);
    output.push_back(':');
}

void append_component(std::string& output, std::string_view component) {
    append_length(output, component.size());
    output.append(component);
}

class CanonicalEncoder {
public:
    explicit CanonicalEncoder(std::string_view object_type) {
        append_component(output_, "rmtls-canonical-v1");
        append_component(output_, object_type);
    }

    void add_string(std::string_view name, std::string_view value) {
        add_field(name, "string", value);
    }

    void add_bytes(std::string_view name, const Bytes& value) {
        const char* data =
            value.empty()
                ? ""
                : reinterpret_cast<const char*>(value.data());
        add_field(
            name,
            "bytes",
            std::string_view(data, value.size()));
    }

    void add_unsigned(std::string_view name, std::uint64_t value) {
        char buffer[32];
        const auto [end, error] =
            std::to_chars(std::begin(buffer), std::end(buffer), value);
        if (error != std::errc{}) {
            throw PrototypeError("canonical encoding failed");
        }
        add_field(
            name,
            "unsigned",
            std::string_view(buffer, static_cast<std::size_t>(end - buffer)));
    }

    void add_signed(std::string_view name, int value) {
        char buffer[32];
        const auto [end, error] =
            std::to_chars(std::begin(buffer), std::end(buffer), value);
        if (error != std::errc{}) {
            throw PrototypeError("canonical encoding failed");
        }
        add_field(
            name,
            "signed",
            std::string_view(buffer, static_cast<std::size_t>(end - buffer)));
    }

    void add_encoded_object(std::string_view name, std::string_view value) {
        add_field(name, "encoded-object", value);
    }

    std::string finish() && {
        return std::move(output_);
    }

private:
    void add_field(std::string_view name,
                   std::string_view value_type,
                   std::string_view value) {
        append_component(output_, "field");
        append_component(output_, name);
        append_component(output_, value_type);
        append_component(output_, value);
    }

    std::string output_;
};

std::string canonical_encode_request_core(
    const SignedTranscript& st,
    const std::string& caller_id) {
    CanonicalEncoder encoder("assistant-request-core");
    encoder.add_string("request_version", REQUEST_VERSION);
    encoder.add_string("caller_id", caller_id);
    encoder.add_string("peer_id", st.transcript.peer_id);
    encoder.add_string("service_id", st.transcript.service_id);
    encoder.add_string("session_id", session_id(st.transcript));
    encoder.add_encoded_object(
        "transcript", canonical_encode(st.transcript));
    encoder.add_string("signature", st.signature);
    return std::move(encoder).finish();
}

std::string canonical_encode_bytes(std::string_view object_type,
                                   std::string_view name,
                                   const Bytes& value) {
    CanonicalEncoder encoder(object_type);
    encoder.add_bytes(name, value);
    return std::move(encoder).finish();
}

std::string hex_encode(const std::uint8_t* data, std::size_t size) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (std::size_t index = 0; index < size; ++index) {
        output << std::setw(2)
               << static_cast<unsigned int>(data[index]);
    }
    return output.str();
}

std::optional<std::vector<std::uint8_t>> hex_decode(
    std::string_view encoded,
    std::size_t expected_size) {
    if (encoded.size() != expected_size * 2) {
        return std::nullopt;
    }
    std::vector<std::uint8_t> output(expected_size);
    for (std::size_t index = 0; index < expected_size; ++index) {
        const auto decode_nibble = [](char value) -> int {
            if (value >= '0' && value <= '9') return value - '0';
            if (value >= 'a' && value <= 'f') return value - 'a' + 10;
            if (value >= 'A' && value <= 'F') return value - 'A' + 10;
            return -1;
        };
        const int high = decode_nibble(encoded[2 * index]);
        const int low = decode_nibble(encoded[2 * index + 1]);
        if (high < 0 || low < 0) {
            return std::nullopt;
        }
        output[index] =
            static_cast<std::uint8_t>((high << 4) | low);
    }
    return output;
}

std::array<std::uint8_t, 32> signing_seed(
    const std::string& signing_key) {
    std::array<std::uint8_t, 32> seed{};
    rmtls_sha3_256(
        seed.data(),
        reinterpret_cast<const std::uint8_t*>(signing_key.data()),
        signing_key.size());
    return seed;
}

std::string canonical_encode_response_shape(
    const SignedTranscript& st,
    const std::string& caller_id,
    std::size_t selected_assistants) {
    if (selected_assistants < 2 || selected_assistants > 3) {
        throw PrototypeError("response shape is unavailable");
    }
    std::string selected_party_ids;
    for (std::size_t party = 1; party <= selected_assistants; ++party) {
        if (!selected_party_ids.empty()) {
            selected_party_ids.push_back(',');
        }
        selected_party_ids.append(std::to_string(party));
    }

    CanonicalEncoder encoder("assistant-response");
    encoder.add_string(
        "response_version", "rMTLS-AuthKEM-AssistantResp-v1");
    encoder.add_string("service_id", st.transcript.service_id);
    encoder.add_string("peer_id", st.transcript.peer_id);
    encoder.add_string("session_id", session_id(st.transcript));
    encoder.add_string("request_hash", request_hash(st, caller_id));
    encoder.add_string(
        "threshold_key_id", st.transcript.threshold_key_id);
    encoder.add_string(
        "assistant_epoch", st.transcript.assistant_epoch);
    encoder.add_bytes(
        "internal_message",
        Bytes(MLKEM512_MESSAGE_BYTES, 0));
    encoder.add_string("selected_party_ids", selected_party_ids);
    encoder.add_signed("threshold_t", st.transcript.threshold_t);
    encoder.add_signed("threshold_n", st.transcript.threshold_n);
    encoder.add_string(
        "share_scheme_id", st.transcript.share_scheme_id);
    encoder.add_bytes("response_authentication_tag", Bytes{});
    return std::move(encoder).finish();
}

std::uint64_t replay_deadline(std::uint64_t not_before,
                              std::uint64_t replay_window) {
    if (replay_window >
        std::numeric_limits<std::uint64_t>::max() - not_before) {
        throw PrototypeError("replay window rejected");
    }
    return not_before + replay_window;
}
}

Bytes fresh_transcript_nonce(std::size_t size) {
    if (size < 16 ||
        size > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw PrototypeError("transcript nonce generation failed");
    }
    Bytes nonce(size);
    if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1) {
        throw PrototypeError("transcript nonce generation failed");
    }
    return nonce;
}

std::string canonical_encode_prefix(const Transcript& t) {
    CanonicalEncoder encoder("negotiation-prefix");
    encoder.add_string("prefix_label", PREFIX_LABEL);
    encoder.add_string("protocol", t.protocol);
    encoder.add_string("protocol_version", t.protocol_version);
    encoder.add_string("deployment", t.deployment);
    encoder.add_string("tls_binding", t.tls_binding);
    encoder.add_string("peer_id", t.peer_id);
    encoder.add_string("service_id", t.service_id);
    encoder.add_string("peer_role", t.peer_role);
    encoder.add_string("service_role", t.service_role);
    encoder.add_bytes("peer_nonce", t.peer_nonce);
    encoder.add_bytes("service_nonce", t.service_nonce);
    encoder.add_string("selected_suite", t.suite);
    encoder.add_string(
        "peer_sig_fingerprint", t.peer_sig_fingerprint);
    encoder.add_string(
        "peer_sig_cert_fingerprint",
        t.peer_sig_cert_fingerprint);
    encoder.add_string(
        "service_kem_fingerprint", t.service_kem_fingerprint);
    encoder.add_string(
        "service_kem_cert_fingerprint",
        t.service_kem_cert_fingerprint);
    encoder.add_string("policy_id", t.policy_id);
    encoder.add_string("policy_version", t.policy_version);
    encoder.add_string("policy_digest", t.policy_digest);
    encoder.add_string("peer_graph_id", t.peer_graph_id);
    encoder.add_string("threshold_key_id", t.threshold_key_id);
    encoder.add_string("assistant_epoch", t.assistant_epoch);
    encoder.add_signed("threshold_t", t.threshold_t);
    encoder.add_signed("threshold_n", t.threshold_n);
    encoder.add_string("share_scheme_id", t.share_scheme_id);
    return std::move(encoder).finish();
}

std::string prefix_hash(const Transcript& t) {
    return cryptographic_hash(
        std::string(PREFIX_LABEL) + canonical_encode_prefix(t));
}

std::string canonical_encode_kem_record(const Transcript& t) {
    CanonicalEncoder encoder("kem-authentication-record");
    encoder.add_string("kem_record_label", KEM_RECORD_LABEL);
    encoder.add_string("direction", t.direction);
    encoder.add_string("kem_id", t.suite);
    encoder.add_string(
        "service_kem_fingerprint", t.service_kem_fingerprint);
    encoder.add_string(
        "service_kem_cert_fingerprint",
        t.service_kem_cert_fingerprint);
    encoder.add_string("threshold_key_id", t.threshold_key_id);
    encoder.add_bytes("ciphertext", t.ciphertext);
    encoder.add_string(
        "ciphertext_hash", ciphertext_hash(t.ciphertext));
    encoder.add_string(
        "ciphertext_usage",
        "long-term-recipient-ML-KEM-authentication");
    return std::move(encoder).finish();
}

std::string canonical_encode_authorization_block(const Transcript& t) {
    CanonicalEncoder encoder("authorization-block");
    encoder.add_string("peer_id", t.peer_id);
    encoder.add_string("service_id", t.service_id);
    encoder.add_string(
        "peer_sig_fingerprint", t.peer_sig_fingerprint);
    encoder.add_string(
        "peer_sig_cert_fingerprint",
        t.peer_sig_cert_fingerprint);
    encoder.add_string("policy_id", t.policy_id);
    encoder.add_string("peer_graph_id", t.peer_graph_id);
    encoder.add_unsigned("not_before", t.not_before);
    encoder.add_unsigned("not_after", t.not_after);
    encoder.add_unsigned("replay_window", t.replay_window);
    return std::move(encoder).finish();
}

std::string canonical_encode(const Transcript& t) {
    const std::string prefix = canonical_encode_prefix(t);
    const std::string prefix_digest = prefix_hash(t);

    CanonicalEncoder prefix_info("prefix-digest-info");
    prefix_info.add_string("protocol", t.protocol);
    prefix_info.add_string("protocol_version", t.protocol_version);
    prefix_info.add_string("suite", t.suite);
    prefix_info.add_string("peer_id", t.peer_id);
    prefix_info.add_string("service_id", t.service_id);
    prefix_info.add_bytes("peer_nonce", t.peer_nonce);
    prefix_info.add_bytes("service_nonce", t.service_nonce);
    prefix_info.add_string("tls_binding", t.tls_binding);
    prefix_info.add_string("prefix_hash", prefix_digest);

    CanonicalEncoder encoder("transcript");
    encoder.add_string("transcript_label", TRANSCRIPT_LABEL);
    encoder.add_string("direction", t.direction);
    encoder.add_encoded_object("prefix", prefix);
    encoder.add_string("prefix_hash", prefix_digest);
    encoder.add_encoded_object(
        "prefix_digest_info", std::move(prefix_info).finish());
    encoder.add_encoded_object(
        "kem_record", canonical_encode_kem_record(t));
    encoder.add_encoded_object(
        "authorization_block",
        canonical_encode_authorization_block(t));
    return std::move(encoder).finish();
}

std::string cryptographic_hash(const std::string& data) {
    std::array<std::uint8_t, 32> digest{};
    rmtls_sha3_256(
        digest.data(),
        reinterpret_cast<const std::uint8_t*>(data.data()),
        data.size());
    return hex_encode(digest.data(), digest.size());
}

std::string transcript_hash(const Transcript& t) {
    return cryptographic_hash(
        std::string(TRANSCRIPT_LABEL) + canonical_encode(t));
}

std::string ciphertext_hash(const Bytes& ciphertext) {
    return cryptographic_hash(
        std::string(CIPHERTEXT_LABEL) +
        canonical_encode_bytes(
            "ciphertext", "ciphertext", ciphertext));
}

std::string transcript_signature_input(const Transcript& t) {
    const auto digest = hex_decode(transcript_hash(t), 32);
    if (!digest.has_value()) {
        throw PrototypeError("signature operation failed");
    }
    std::string input(64, ' ');
    input.append(SIGNATURE_LABEL);
    input.push_back('\0');
    input.append(
        reinterpret_cast<const char*>(digest->data()),
        digest->size());
    return input;
}

std::string simulated_public_key(const std::string& signing_key) {
    auto seed = signing_seed(signing_key);
    EVP_PKEY* key = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, seed.data(), seed.size());
    detail::erase_value(seed);
    if (key == nullptr) {
        throw PrototypeError("signature operation failed");
    }
    std::array<std::uint8_t, 32> public_key{};
    std::size_t public_key_size = public_key.size();
    const int status = EVP_PKEY_get_raw_public_key(
        key, public_key.data(), &public_key_size);
    EVP_PKEY_free(key);
    if (status != 1 || public_key_size != public_key.size()) {
        throw PrototypeError("signature operation failed");
    }
    return hex_encode(public_key.data(), public_key.size());
}

std::string simulated_sign(const std::string& signing_key,
                           const std::string& signature_input) {
    auto seed = signing_seed(signing_key);
    EVP_PKEY* key = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, seed.data(), seed.size());
    detail::erase_value(seed);
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (key == nullptr || context == nullptr) {
        EVP_PKEY_free(key);
        EVP_MD_CTX_free(context);
        throw PrototypeError("signature operation failed");
    }
    std::array<std::uint8_t, 64> signature{};
    std::size_t signature_size = signature.size();
    const int initialized =
        EVP_DigestSignInit(context, nullptr, nullptr, nullptr, key);
    const int signed_ok =
        initialized == 1
            ? EVP_DigestSign(
                  context,
                  signature.data(),
                  &signature_size,
                  reinterpret_cast<const std::uint8_t*>(
                      signature_input.data()),
                  signature_input.size())
            : 0;
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    if (signed_ok != 1 || signature_size != signature.size()) {
        throw PrototypeError("signature operation failed");
    }
    return hex_encode(signature.data(), signature.size());
}

bool simulated_verify(const std::string& verify_key,
                      const std::string& signature_input,
                      const std::string& signature) {
    const auto public_key = hex_decode(verify_key, 32);
    const auto signature_bytes = hex_decode(signature, 64);
    if (!public_key.has_value() || !signature_bytes.has_value()) {
        return false;
    }
    EVP_PKEY* key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519,
        nullptr,
        public_key->data(),
        public_key->size());
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (key == nullptr || context == nullptr) {
        EVP_PKEY_free(key);
        EVP_MD_CTX_free(context);
        return false;
    }
    const int initialized =
        EVP_DigestVerifyInit(context, nullptr, nullptr, nullptr, key);
    const int verified =
        initialized == 1
            ? EVP_DigestVerify(
                  context,
                  signature_bytes->data(),
                  signature_bytes->size(),
                  reinterpret_cast<const std::uint8_t*>(
                      signature_input.data()),
                  signature_input.size())
            : 0;
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    return verified == 1;
}

std::string simulated_key_fingerprint(const std::string& verify_key) {
    return cryptographic_hash(
        "peer-signature-key|" + verify_key);
}

std::string session_id(const Transcript& t) {
    return cryptographic_hash(
        std::string(SESSION_ID_LABEL) + canonical_encode(t));
}

std::string request_hash(const SignedTranscript& st, const std::string& caller_id) {
    return cryptographic_hash(
        std::string(REQUEST_HASH_LABEL) +
        canonical_encode_request_core(st, caller_id));
}

std::string key_schedule_context(const SignedTranscript& st) {
    CanonicalEncoder encoder("key-schedule-context");
    encoder.add_string("protocol", st.transcript.protocol);
    encoder.add_string(
        "protocol_version", st.transcript.protocol_version);
    encoder.add_string("suite", st.transcript.suite);
    encoder.add_string("peer_id", st.transcript.peer_id);
    encoder.add_string("service_id", st.transcript.service_id);
    encoder.add_string("direction", st.transcript.direction);
    encoder.add_string("peer_role", st.transcript.peer_role);
    encoder.add_string("service_role", st.transcript.service_role);
    encoder.add_string("tls_binding", st.transcript.tls_binding);
    encoder.add_string("transcript_hash", st.transcript_hash);
    encoder.add_string("post_admission_hash", "none");
    return std::move(encoder).finish();
}

std::size_t assistant_request_encoded_size(
    const SignedTranscript& st,
    const std::string& caller_id) {
    const std::string core =
        canonical_encode_request_core(st, caller_id);
    CanonicalEncoder encoder("assistant-request");
    encoder.add_encoded_object("request_core", core);
    encoder.add_string("request_hash", request_hash(st, caller_id));
    return std::move(encoder).finish().size();
}

std::size_t assistant_response_encoded_size(
    const SignedTranscript& st,
    const std::string& caller_id,
    std::size_t selected_assistants) {
    return canonical_encode_response_shape(
               st, caller_id, selected_assistants)
        .size();
}

AdmissionStatus ReplayCache::check_and_record(
    const std::string& sid,
    const std::string& threshold_key_id,
    const std::string& assistant_epoch,
    const std::string& reqhash,
    std::uint64_t current_time,
    std::uint64_t expires_at) {
    if (sid.empty() ||
        threshold_key_id.empty() ||
        assistant_epoch.empty() ||
        reqhash.empty()) {
        return AdmissionStatus::Reject;
    }
    ReplayKey key{
        sid,
        threshold_key_id,
        assistant_epoch,
    };
    auto it = seen_.find(key);
    if (it != seen_.end() && current_time > it->second.expires_at) {
        seen_.erase(it);
        it = seen_.end();
    }
    if (current_time > expires_at) {
        return AdmissionStatus::Reject;
    }
    if (it == seen_.end()) {
        seen_.emplace(
            std::move(key), ReplayEntry{reqhash, expires_at});
        return AdmissionStatus::Accept;
    }
    return it->second.request_hash == reqhash &&
                   it->second.expires_at == expires_at
               ? AdmissionStatus::Accept
               : AdmissionStatus::Reject;
}

AdmissionPolicy::AdmissionPolicy(AdmissionConfig cfg)
    : cfg_(std::move(cfg)) {
    if (cfg_.service_id.empty() ||
        cfg_.service_kem_fingerprint.empty() ||
        cfg_.policy_id.empty() ||
        cfg_.peer_graph_id.empty() ||
        cfg_.threshold_key_id.empty() ||
        cfg_.assistant_epoch.empty() ||
        cfg_.tls_binding.empty() ||
        cfg_.protocol.empty() ||
        cfg_.protocol_version.empty() ||
        cfg_.deployment.empty() ||
        cfg_.direction.empty() ||
        cfg_.peer_role.empty() ||
        cfg_.service_role.empty() ||
        cfg_.allowed_suites.empty() ||
        cfg_.peer_sig_cert_fingerprint.empty() ||
        cfg_.service_kem_cert_fingerprint.empty() ||
        cfg_.policy_version.empty() ||
        cfg_.policy_digest.empty() ||
        cfg_.replay_window == 0 ||
        cfg_.minimum_nonce_bytes < 16 ||
        cfg_.threshold_t != 2 ||
        cfg_.threshold_n != 3 ||
        cfg_.share_scheme_id.empty() ||
        cfg_.authorised_peers.empty() ||
        cfg_.authorised_callers.empty() ||
        cfg_.peer_verify_keys.size() != cfg_.authorised_peers.size() ||
        cfg_.peer_sig_fingerprints.size() != cfg_.authorised_peers.size()) {
        reject_invalid_config();
    }
    for (const std::string& caller : cfg_.authorised_callers) {
        if (caller.empty()) {
            reject_invalid_config();
        }
    }
    for (const std::string& peer : cfg_.authorised_peers) {
        if (peer.empty()) {
            reject_invalid_config();
        }
        const auto key = cfg_.peer_verify_keys.find(peer);
        const auto fingerprint = cfg_.peer_sig_fingerprints.find(peer);
        if (key == cfg_.peer_verify_keys.end() ||
            key->second.empty() ||
            fingerprint == cfg_.peer_sig_fingerprints.end() ||
            fingerprint->second.empty() ||
            fingerprint->second !=
                simulated_key_fingerprint(key->second)) {
            reject_invalid_config();
        }
    }
}

AdmissionStatus AdmissionPolicy::admit(const SignedTranscript& st,
                                       const std::string& caller_id,
                                       ReplayCache& replay_cache) const {
    const auto& t = st.transcript;
    if (!cfg_.authorised_callers.contains(caller_id)) return AdmissionStatus::Reject;
    if (!cfg_.authorised_peers.contains(t.peer_id)) return AdmissionStatus::Reject;
    if (t.service_id != cfg_.service_id) return AdmissionStatus::Reject;
    if (t.service_kem_fingerprint != cfg_.service_kem_fingerprint) return AdmissionStatus::Reject;
    if (t.policy_id != cfg_.policy_id) return AdmissionStatus::Reject;
    if (t.peer_graph_id != cfg_.peer_graph_id) return AdmissionStatus::Reject;
    if (t.threshold_key_id != cfg_.threshold_key_id) return AdmissionStatus::Reject;
    if (t.assistant_epoch != cfg_.assistant_epoch) return AdmissionStatus::Reject;
    if (t.tls_binding != cfg_.tls_binding) return AdmissionStatus::Reject;
    if (t.protocol != cfg_.protocol ||
        t.protocol_version != cfg_.protocol_version ||
        t.deployment != cfg_.deployment ||
        t.direction != cfg_.direction ||
        t.peer_role != cfg_.peer_role ||
        t.service_role != cfg_.service_role ||
        !cfg_.allowed_suites.contains(t.suite) ||
        t.peer_sig_cert_fingerprint !=
            cfg_.peer_sig_cert_fingerprint ||
        t.service_kem_cert_fingerprint !=
            cfg_.service_kem_cert_fingerprint ||
        t.policy_version != cfg_.policy_version ||
        t.policy_digest != cfg_.policy_digest ||
        t.peer_nonce.size() < cfg_.minimum_nonce_bytes ||
        t.service_nonce.size() < cfg_.minimum_nonce_bytes ||
        t.not_before > cfg_.evaluation_time ||
        t.not_after < cfg_.evaluation_time ||
        t.not_before > t.not_after ||
        t.replay_window != cfg_.replay_window ||
        t.threshold_t != cfg_.threshold_t ||
        t.threshold_n != cfg_.threshold_n ||
        t.share_scheme_id != cfg_.share_scheme_id) {
        return AdmissionStatus::Reject;
    }
    std::uint64_t expires_at = 0;
    try {
        expires_at = replay_deadline(t.not_before, t.replay_window);
    } catch (const PrototypeError&) {
        return AdmissionStatus::Reject;
    }
    if (cfg_.evaluation_time > expires_at) {
        return AdmissionStatus::Reject;
    }
    if (t.ciphertext.size() != MLKEM512_CIPHERTEXT_BYTES) return AdmissionStatus::Reject;
    if (st.transcript_hash != transcript_hash(t)) return AdmissionStatus::Reject;
    auto key_it = cfg_.peer_verify_keys.find(t.peer_id);
    if (key_it == cfg_.peer_verify_keys.end()) return AdmissionStatus::Reject;
    auto fingerprint_it = cfg_.peer_sig_fingerprints.find(t.peer_id);
    if (fingerprint_it == cfg_.peer_sig_fingerprints.end() ||
        t.peer_sig_fingerprint != fingerprint_it->second ||
        fingerprint_it->second !=
            simulated_key_fingerprint(key_it->second)) {
        return AdmissionStatus::Reject;
    }
    if (!simulated_verify(
            key_it->second,
            transcript_signature_input(t),
            st.signature)) {
        return AdmissionStatus::Reject;
    }
    return replay_cache.check_and_record(
        session_id(t),
        t.threshold_key_id,
        t.assistant_epoch,
        request_hash(st, caller_id),
        cfg_.evaluation_time,
        expires_at);
}

} // namespace rmtls
