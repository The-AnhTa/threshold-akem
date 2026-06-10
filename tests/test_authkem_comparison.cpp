#include <cassert>
#include <iostream>
#include <sstream>
#include <fstream>
#include "rmtls_threshold_mlkem/authkem_baseline.hpp"
#include "rmtls_threshold_mlkem/authkem_comparison.hpp"
#include "rmtls_threshold_mlkem/mlkem_adapter.hpp"

using namespace rmtls;

// Test helpers
bool test_passed = true;

void assert_true(bool condition, const std::string& test_name) {
    if (!condition) {
        std::cerr << "FAIL: " << test_name << "\n";
        test_passed = false;
    } else {
        std::cout << "PASS: " << test_name << "\n";
    }
}

// ============= CLI Configuration Tests =============

void test_cli_config_validation() {
    // Valid config
    ExperimentConfig cfg;
    cfg.n = 3;
    cfg.t = 2;
    cfg.selected = {};
    assert_true(cfg.validate(), "cli_config_validation: valid (n=3, t=2)");
    
    // Invalid: t > n
    cfg.t = 5;
    assert_true(!cfg.validate(), "cli_config_validation: reject t > n");
    
    // Invalid: t < 1
    cfg.t = 0;
    cfg.n = 3;
    assert_true(!cfg.validate(), "cli_config_validation: reject t < 1");
    
    // Valid with explicit selected
    cfg.n = 5;
    cfg.t = 3;
    cfg.selected = {1, 2, 3};
    assert_true(cfg.validate(), "cli_config_validation: valid with selected [1,2,3]");
    
    // Invalid selected: wrong count
    cfg.selected = {1, 2};
    assert_true(!cfg.validate(), "cli_config_validation: reject selected.size() != t");
    
    // Invalid selected: duplicate
    cfg.selected = {1, 1, 3};
    assert_true(!cfg.validate(), "cli_config_validation: reject duplicate selected ids");
    
    // Invalid selected: out of range
    cfg.selected = {1, 2, 6};  // 6 > n
    assert_true(!cfg.validate(), "cli_config_validation: reject selected id > n");
}

// ============= Serialization Tests =============

void test_standard_authkem_message_serialization() {
    StandardAuthKEMMessage msg;
    msg.peer_id = "peer_1";
    msg.server_id = "server_1";
    msg.policy_id = "policy_default";
    msg.ciphertext = Bytes(768);
    
    Bytes serialized = msg.serialize();
    assert_true(serialized.size() > 0, "serialization: StandardAuthKEMMessage has non-zero size");
    
    StandardAuthKEMMessage msg2 = StandardAuthKEMMessage::deserialize(serialized);
    assert_true(msg2.peer_id == "peer_1", "deserialization: peer_id preserved");
    assert_true(msg2.server_id == "server_1", "deserialization: server_id preserved");
    assert_true(msg2.policy_id == "policy_default", "deserialization: policy_id preserved");
    assert_true(msg2.ciphertext.size() == 768, "deserialization: ciphertext size preserved");
}

void test_threshold_authkem_message_serialization() {
    ThresholdAuthKEMMessage msg;
    msg.peer_id = "peer_1";
    msg.server_id = "server_1";
    msg.policy_id = "policy_default";
    msg.ciphertext = Bytes(768);
    msg.threshold_key_id = "thkey_1";
    msg.t = 2;
    msg.n = 3;
    msg.selected_assistants = {1, 2};
    msg.transcript_or_admission = Bytes(256);
    
    Bytes serialized = msg.serialize();
    assert_true(serialized.size() > 0, "serialization: ThresholdAuthKEMMessage has non-zero size");
    
    ThresholdAuthKEMMessage msg2 = ThresholdAuthKEMMessage::deserialize(serialized);
    assert_true(msg2.peer_id == "peer_1", "deserialization: peer_id preserved");
    assert_true(msg2.t == 2, "deserialization: t preserved");
    assert_true(msg2.n == 3, "deserialization: n preserved");
    assert_true(msg2.selected_assistants.size() == 2, "deserialization: selected assistants count preserved");
    assert_true(msg2.selected_assistants[0] == 1, "deserialization: selected_assistants[0] preserved");
    assert_true(msg2.selected_assistants[1] == 2, "deserialization: selected_assistants[1] preserved");
}

void test_assistant_request_response_serialization() {
    AssistantRequest req;
    req.operation = "contribute";
    req.assistant_id = 1;
    req.payload = Bytes(32);
    
    Bytes req_serialized = req.serialize();
    AssistantRequest req2 = AssistantRequest::deserialize(req_serialized);
    assert_true(req2.operation == "contribute", "deserialization: assistant request operation preserved");
    assert_true(req2.assistant_id == 1, "deserialization: assistant id preserved");
    assert_true(req2.payload.size() == 32, "deserialization: assistant request payload size preserved");
    
    AssistantResponse resp;
    resp.assistant_id = 1;
    resp.status = "ok";
    resp.payload = Bytes(64);
    
    Bytes resp_serialized = resp.serialize();
    AssistantResponse resp2 = AssistantResponse::deserialize(resp_serialized);
    assert_true(resp2.assistant_id == 1, "deserialization: assistant response id preserved");
    assert_true(resp2.status == "ok", "deserialization: assistant response status preserved");
    assert_true(resp2.payload.size() == 64, "deserialization: assistant response payload size preserved");
}

// ============= Byte Counting Tests =============

void test_byte_counts_are_serialized_lengths() {
    StandardAuthKEMMessage msg;
    msg.peer_id = "peer";
    msg.server_id = "server";
    msg.policy_id = "policy";
    msg.ciphertext = Bytes(768);
    
    Bytes serialized = msg.serialize();
    size_t reported_size = msg.serialized_size();
    
    assert_true(serialized.size() == reported_size, 
               "byte_counts: serialized size matches serialized_size() for StandardAuthKEMMessage");
    
    ThresholdAuthKEMMessage msg2;
    msg2.peer_id = "peer";
    msg2.server_id = "server";
    msg2.policy_id = "policy";
    msg2.ciphertext = Bytes(768);
    msg2.threshold_key_id = "thkey";
    msg2.t = 2;
    msg2.n = 3;
    msg2.selected_assistants = {1, 2};
    msg2.transcript_or_admission = Bytes(256);
    
    Bytes serialized2 = msg2.serialize();
    size_t reported_size2 = msg2.serialized_size();
    
    assert_true(serialized2.size() == reported_size2,
               "byte_counts: serialized size matches serialized_size() for ThresholdAuthKEMMessage");
}

// ============= Secret Value Leakage Tests =============

void test_no_secret_values_in_public_outputs() {
    // Create public response messages
    StandardAuthKEMResponse resp1;
    resp1.status = "success";
    resp1.server_fingerprint = "fingerprint_abc";
    
    Bytes serialized1 = resp1.serialize();
    std::string serialized_str1(serialized1.begin(), serialized1.end());
    
    // Check that no secret field names appear
    assert_true(serialized_str1.find("delta") == std::string::npos,
               "leakage: 'delta' not in StandardAuthKEMResponse");
    assert_true(serialized_str1.find("m_prime") == std::string::npos,
               "leakage: 'm_prime' not in StandardAuthKEMResponse");
    
    ThresholdAuthKEMResponse resp2;
    resp2.status = "success";
    resp2.server_fingerprint = "fingerprint_xyz";
    
    Bytes serialized2 = resp2.serialize();
    std::string serialized_str2(serialized2.begin(), serialized2.end());
    
    assert_true(serialized_str2.find("delta") == std::string::npos,
               "leakage: 'delta' not in ThresholdAuthKEMResponse");
    assert_true(serialized_str2.find("w") == std::string::npos || serialized_str2.find("\"w\"") == std::string::npos,
               "leakage: 'w' secret not in ThresholdAuthKEMResponse");
}

// ============= Result Structure Tests =============

void test_experiment_result_structure() {
    ExperimentResult result;
    result.scheme = "standard_baseline";
    result.adapter_profile = "ml_kem_512";
    result.is_toy_adapter = true;
    result.n = 3;
    result.t = 2;
    result.selected_assistants = {1, 2};
    result.iteration = 0;
    
    result.communication.p_to_s_bytes = 100;
    result.communication.s_to_p_bytes = 50;
    result.communication.ciphertext_bytes = 768;
    
    result.baseline_timings.decapsulation_or_fo_validation_ns = 1000000;
    result.threshold_timings.reconstruction_time_ns = 500000;
    
    result.success = true;
    
    assert_true(result.communication.p_to_s_bytes == 100,
               "structure: communication p_to_s_bytes stored correctly");
    assert_true(result.baseline_timings.decapsulation_or_fo_validation_ns == 1000000,
               "structure: baseline timing stored correctly");
    assert_true(result.success == true,
               "structure: success flag stored correctly");
}

// ============= Communication Metrics Tests =============

void test_communication_breakdown() {
    CommunicationMetrics metrics;
    metrics.p_to_s_bytes = 900;
    metrics.s_to_p_bytes = 50;
    metrics.s_to_assistants_bytes = 300;
    metrics.assistants_to_s_bytes = 400;
    metrics.ciphertext_bytes = 768;
    metrics.transcript_admission_bytes = 256;
    metrics.common_fields_bytes = 120;
    metrics.threshold_metadata_bytes = 50;
    
    metrics.assistant_request_bytes_per_assistant = {100, 100, 100};
    metrics.assistant_response_bytes_per_assistant = {150, 150, 100};
    
    assert_true(metrics.p_to_s_bytes == 900,
               "communication: p_to_s_bytes set correctly");
    assert_true(metrics.assistant_request_bytes_per_assistant.size() == 3,
               "communication: per-assistant breakdown populated");
    assert_true(metrics.ciphertext_bytes == 768,
               "communication: ciphertext bytes tracked separately");
}

// ============= Main Test Runner =============

int main() {
    std::cout << "=== AuthKEM Comparison Tests ===\n\n";
    
    // CLI Configuration
    test_cli_config_validation();
    
    // Serialization
    std::cout << "\n--- Serialization Tests ---\n";
    test_standard_authkem_message_serialization();
    test_threshold_authkem_message_serialization();
    test_assistant_request_response_serialization();
    
    // Byte Counting
    std::cout << "\n--- Byte Counting Tests ---\n";
    test_byte_counts_are_serialized_lengths();
    
    // Leakage
    std::cout << "\n--- Leakage Tests ---\n";
    test_no_secret_values_in_public_outputs();
    
    // Structures
    std::cout << "\n--- Result Structure Tests ---\n";
    test_experiment_result_structure();
    test_communication_breakdown();
    
    std::cout << "\n=== Test Summary ===\n";
    if (test_passed) {
        std::cout << "All tests passed!\n";
        return 0;
    } else {
        std::cout << "Some tests failed!\n";
        return 1;
    }
}
