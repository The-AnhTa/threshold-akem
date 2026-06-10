#pragma once

#include "rmtls_threshold_mlkem/types.hpp"
#include "rmtls_threshold_mlkem/mlkem_adapter.hpp"
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace rmtls {

// Standard mTLS/AuthKEM baseline (no threshold, no assistants)
// Server S directly runs decapsulation/FO-validation using its local secret key
// This provides a simple comparison point for our threshold scheme

struct StandardAuthKEMMessage {
    // Common fields
    std::string peer_id;
    std::string server_id;
    std::string policy_id;
    
    // Baseline-specific
    Bytes ciphertext;
    // Optional: signature or certificate (omitted for toy adapter)
    
    Bytes serialize() const;
    static StandardAuthKEMMessage deserialize(const Bytes& data);
    std::size_t serialized_size() const { return serialize().size(); }
};

struct StandardAuthKEMResponse {
    // Public response fields (no secrets)
    std::string status;  // "success" or generic "failure"
    std::string server_fingerprint;
    
    Bytes serialize() const;
    static StandardAuthKEMResponse deserialize(const Bytes& data);
    std::size_t serialized_size() const { return serialize().size(); }
};

struct StandardAuthKEMTimings {
    std::uint64_t decapsulation_or_fo_validation_ns = 0;
};

struct ThresholdAuthKEMMessage {
    // Common fields
    std::string peer_id;
    std::string server_id;
    std::string policy_id;
    
    // Threshold-specific
    Bytes ciphertext;
    std::string threshold_key_id;
    int t = 2;
    int n = 3;
    std::vector<int> selected_assistants;  // which assistants to use
    
    // Transcript/admission
    Bytes transcript_or_admission;
    // Optional: signature or admission credential
    
    Bytes serialize() const;
    static ThresholdAuthKEMMessage deserialize(const Bytes& data);
    std::size_t serialized_size() const { return serialize().size(); }
};

struct ThresholdAuthKEMResponse {
    // Public response fields (no secrets)
    std::string status;  // "success" or generic "failure"
    std::string server_fingerprint;
    
    Bytes serialize() const;
    static ThresholdAuthKEMResponse deserialize(const Bytes& data);
    std::size_t serialized_size() const { return serialize().size(); }
};

struct AssistantRequest {
    std::string operation;  // "contribute", "admit", etc.
    int assistant_id = 0;
    Bytes payload;
    
    Bytes serialize() const;
    static AssistantRequest deserialize(const Bytes& data);
    std::size_t serialized_size() const { return serialize().size(); }
};

struct AssistantResponse {
    int assistant_id = 0;
    std::string status;  // "ok" or "error"
    Bytes payload;  // contribution or validation result
    
    Bytes serialize() const;
    static AssistantResponse deserialize(const Bytes& data);
    std::size_t serialized_size() const { return serialize().size(); }
};

struct CommunicationMetrics {
    // External P-S communication
    std::size_t p_to_s_bytes = 0;
    std::size_t s_to_p_bytes = 0;
    
    // Internal S-assistant communication (for threshold scheme only)
    std::size_t s_to_assistants_bytes = 0;
    std::size_t assistants_to_s_bytes = 0;
    
    // Message breakdown (threshold scheme)
    std::size_t ciphertext_bytes = 0;
    std::size_t transcript_admission_bytes = 0;
    std::size_t common_fields_bytes = 0;
    std::size_t threshold_metadata_bytes = 0;
    
    // Per-assistant breakdown
    std::vector<std::size_t> assistant_request_bytes_per_assistant;
    std::vector<std::size_t> assistant_response_bytes_per_assistant;
};

struct ThresholdAuthKEMTimings {
    std::uint64_t assistant_admission_time_ns = 0;
    std::uint64_t assistant_contribution_time_ns = 0;
    std::uint64_t reconstruction_time_ns = 0;
    std::uint64_t front_service_fo_validation_time_ns = 0;
    
    std::uint64_t total_server_side_threshold_flow_ns() const {
        return assistant_admission_time_ns + 
               assistant_contribution_time_ns + 
               reconstruction_time_ns + 
               front_service_fo_validation_time_ns;
    }
};

struct ExperimentResult {
    std::string scheme;  // "standard_baseline" or "threshold_scheme"
    std::string adapter_profile;
    bool is_toy_adapter = false;
    
    int n = 3;
    int t = 2;
    std::vector<int> selected_assistants;
    
    uint64_t iteration = 0;
    
    CommunicationMetrics communication;
    
    // Timings (baseline only uses decapsulation_time)
    StandardAuthKEMTimings baseline_timings;
    ThresholdAuthKEMTimings threshold_timings;
    
    bool success = false;
    std::string error_message;
};

}  // namespace rmtls
