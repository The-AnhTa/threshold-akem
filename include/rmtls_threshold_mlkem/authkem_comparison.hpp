#pragma once

#include "rmtls_threshold_mlkem/authkem_baseline.hpp"
#include "rmtls_threshold_mlkem/mlkem_adapter.hpp"
#include <algorithm>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace rmtls {

struct ExperimentConfig {
    int n = 3;
    int t = 2;
    std::vector<int> selected;
    int iterations = 1000;
    uint64_t seed = 0;
    std::string adapter = "toy";
    std::string output_csv;
    std::string output_json;
    bool verbose = false;

    bool validate() const {
        if (t < 1 || t > n) {
            std::cerr << "Error: require 1 <= t <= n\n";
            return false;
        }
        if (n < 2) {
            std::cerr << "Error: require n >= 2\n";
            return false;
        }
        if (!selected.empty()) {
            if (selected.size() != static_cast<size_t>(t)) {
                std::cerr << "Error: selected.size() must equal t\n";
                return false;
            }
            for (int id : selected) {
                if (id < 1 || id > n) {
                    std::cerr << "Error: selected ids must be in [1, n]\n";
                    return false;
                }
            }
            auto sorted = selected;
            std::sort(sorted.begin(), sorted.end());
            if (std::adjacent_find(sorted.begin(), sorted.end()) != sorted.end()) {
                std::cerr << "Error: duplicate selected ids\n";
                return false;
            }
        }
        return true;
    }
};

// Simulated protocol harness for comparing standard baseline vs threshold scheme
// No actual networking - all communication simulated in-process with byte counting

class AuthKEMComparisonProtocol {
public:
    explicit AuthKEMComparisonProtocol(std::shared_ptr<MLKEMAdapter> adapter);
    
    // Standard AuthKEM baseline protocol
    // Returns: (server response, communication metrics, timing)
    std::tuple<StandardAuthKEMResponse, CommunicationMetrics, StandardAuthKEMTimings>
    run_standard_baseline(
        const MLKEMPublicKey& server_public_key,
        const Secret<MLKEMSecretState>& server_secret,
        int iterations = 1,
        uint64_t seed = 0);
    
    // Threshold AuthKEM protocol (simplified for experiment)
    // For simplicity in this experimental harness, we don't invoke real distributed assistants
    // Instead, we measure the communication and computation as if they were present
    std::tuple<ThresholdAuthKEMResponse, CommunicationMetrics, ThresholdAuthKEMTimings>
    run_threshold_scheme(
        const MLKEMPublicKey& server_public_key,
        const Secret<MLKEMSecretState>& server_secret,
        int n = 3,
        int t = 2,
        const std::vector<int>& selected_assistants = {},
        int iterations = 1,
        uint64_t seed = 0);
    
private:
    std::shared_ptr<MLKEMAdapter> adapter_;
    
    // Helper to validate parameters
    void validate_threshold_params(int n, int t, const std::vector<int>& selected);
};

}  // namespace rmtls
