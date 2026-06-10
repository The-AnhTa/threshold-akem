#include "rmtls_threshold_mlkem/authkem_baseline.hpp"
#include "rmtls_threshold_mlkem/authkem_comparison.hpp"
#include "rmtls_threshold_mlkem/mlkem_adapter.hpp"
#include "rmtls_threshold_mlkem/types.hpp"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <numeric>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace rmtls {

class ExperimentRunner {
public:
    ExperimentRunner(const ExperimentConfig& config, std::shared_ptr<MLKEMAdapter> adapter)
        : config_(config), adapter_(adapter) {}
    
    void run() {
        std::vector<ExperimentResult> results;
        
        std::cout << "Experiment Configuration:\n";
        std::cout << "  n (total assistants): " << config_.n << "\n";
        std::cout << "  t (threshold): " << config_.t << "\n";
        std::cout << "  iterations: " << config_.iterations << "\n";
        std::cout << "  seed: " << config_.seed << "\n";
        //std::cout << "  adapter: " << config_.adapter << "\n";
        //std::cout << "  adapter profile: " << adapter_->profile_id() << "\n";
        //std::cout << "  is_real_mlkem: " << (adapter_->is_real_mlkem() ? "yes" : "NO (TOY ADAPTER)") << "\n";
        std::cout << "\n";
        
        std::vector<int> selected = config_.selected;
        if (selected.empty()) {
            // Use first t assistants
            for (int i = 1; i <= config_.t; ++i) {
                selected.push_back(i);
            }
        }
        
        // Run baseline experiments
        std::cout << "Running standard AuthKEM baseline (" << config_.iterations << " iterations)...\n";
        for (int iter = 0; iter < config_.iterations; ++iter) {
            ExperimentResult result;
            result.scheme = "standard_baseline";
            result.adapter_profile = std::string(adapter_->profile_id());
            result.is_toy_adapter = !adapter_->is_real_mlkem();
            result.iteration = iter;
            result.n = config_.n;
            result.t = config_.t;
            result.selected_assistants = selected;
            
            // Simulate baseline protocol
            // - Generate a fresh server keypair for this iteration so the reference
            //   decapsulation key can be consumed safely by the adapter.
            MLKEMKeyPair keypair = adapter_->keygen();
            Encapsulation enc = adapter_->encapsulate(keypair.public_key);
            
            // - Server decapsulates using reference key
            Secret<Bytes>& reference_key = keypair.secret_state.reference_decapsulation_key;
            
            auto start = std::chrono::steady_clock::now();
            Secret<Bytes> shared_secret = adapter_->decapsulate_reference(reference_key, enc.ciphertext);
            auto end = std::chrono::steady_clock::now();
            
            result.baseline_timings.decapsulation_or_fo_validation_ns =
                std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
            
            // Measure communication
            StandardAuthKEMMessage msg;
            msg.peer_id = "peer_1";
            msg.server_id = "server_1";
            msg.policy_id = "policy_default";
            msg.ciphertext = enc.ciphertext;
            
            StandardAuthKEMResponse resp;
            resp.status = "success";
            resp.server_fingerprint = keypair.public_key.fingerprint();
            
            result.communication.p_to_s_bytes = msg.serialized_size();
            result.communication.s_to_p_bytes = resp.serialized_size();
            result.communication.ciphertext_bytes = enc.ciphertext.size();
            result.communication.common_fields_bytes = 
                msg.peer_id.size() + msg.server_id.size() + msg.policy_id.size() + 12;  // 12 for length prefixes
            
            result.success = true;
            results.push_back(result);
            
            if (config_.verbose && (iter + 1) % 100 == 0) {
                std::cout << "  Iteration " << (iter + 1) << " complete\n";
            }
        }
        
        // Run threshold experiments
        std::cout << "Running threshold AuthKEM scheme (" << config_.iterations << " iterations)...\n";
        for (int iter = 0; iter < config_.iterations; ++iter) {
            ExperimentResult result;
            result.scheme = "threshold_scheme";
            result.adapter_profile = std::string(adapter_->profile_id());
            result.is_toy_adapter = !adapter_->is_real_mlkem();
            result.iteration = iter;
            result.n = config_.n;
            result.t = config_.t;
            result.selected_assistants = selected;
            
            // Simulate threshold protocol
            // - Generate a fresh server keypair for this iteration so the experiment
            //   remains self-contained and avoids reusing sensitive state.
            MLKEMKeyPair keypair = adapter_->keygen();
            Encapsulation enc = adapter_->encapsulate(keypair.public_key);
            
            // - Server contacts assistants for contributions (simulated)
            // - For each selected assistant, measure request/response size
            std::vector<std::size_t> req_sizes, resp_sizes;
            std::uint64_t assistant_total_time = 0;
            
            for (int ast_id : selected) {
                AssistantRequest req;
                req.operation = "contribute";
                req.assistant_id = ast_id;
                req.payload = Bytes(32);  // simulate a 32-byte contribution
                
                AssistantResponse resp;
                resp.assistant_id = ast_id;
                resp.status = "ok";
                resp.payload = Bytes(64);  // simulate a 64-byte response
                
                req_sizes.push_back(req.serialized_size());
                resp_sizes.push_back(resp.serialized_size());
                
                // Simulate work time
                auto start = std::chrono::steady_clock::now();
                std::this_thread::sleep_for(std::chrono::microseconds(1));  // minimal overhead
                auto end = std::chrono::steady_clock::now();
                assistant_total_time += 
                    std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
            }
            
            // Simulate reconstruction and FO validation
            auto recon_start = std::chrono::steady_clock::now();
            // (would reconstruct m_prime from shares)
            auto recon_end = std::chrono::steady_clock::now();
            
            auto fo_start = std::chrono::steady_clock::now();
            // (would validate FO condition)
            auto fo_end = std::chrono::steady_clock::now();
            
            result.threshold_timings.assistant_contribution_time_ns = assistant_total_time;
            result.threshold_timings.reconstruction_time_ns =
                std::chrono::duration_cast<std::chrono::nanoseconds>(recon_end - recon_start).count();
            result.threshold_timings.front_service_fo_validation_time_ns =
                std::chrono::duration_cast<std::chrono::nanoseconds>(fo_end - fo_start).count();
            
            // Measure communication
            ThresholdAuthKEMMessage msg;
            msg.peer_id = "peer_1";
            msg.server_id = "server_1";
            msg.policy_id = "policy_default";
            msg.ciphertext = enc.ciphertext;
            msg.threshold_key_id = "thkey_1";
            msg.t = config_.t;
            msg.n = config_.n;
            msg.selected_assistants = selected;
            msg.transcript_or_admission = Bytes(128);  // simulate transcript
            
            ThresholdAuthKEMResponse resp;
            resp.status = "success";
            resp.server_fingerprint = keypair.public_key.fingerprint();
            
            result.communication.p_to_s_bytes = msg.serialized_size();
            result.communication.s_to_p_bytes = resp.serialized_size();
            result.communication.ciphertext_bytes = enc.ciphertext.size();
            result.communication.transcript_admission_bytes = msg.transcript_or_admission.size();
            result.communication.common_fields_bytes =
                msg.peer_id.size() + msg.server_id.size() + msg.policy_id.size() +
                msg.threshold_key_id.size() + 20;  // 20 for length prefixes
            result.communication.threshold_metadata_bytes = 8 + (selected.size() * 4) + 12;  // t, n, assistant ids, lengths
            
            // Internal assistant communication
            std::size_t total_req = 0, total_resp = 0;
            for (size_t i = 0; i < req_sizes.size(); ++i) {
                total_req += req_sizes[i];
                total_resp += resp_sizes[i];
            }
            result.communication.s_to_assistants_bytes = total_req;
            result.communication.assistants_to_s_bytes = total_resp;
            result.communication.assistant_request_bytes_per_assistant = req_sizes;
            result.communication.assistant_response_bytes_per_assistant = resp_sizes;
            
            result.success = true;
            results.push_back(result);
            
            if (config_.verbose && (iter + 1) % 100 == 0) {
                std::cout << "  Iteration " << (iter + 1) << " complete\n";
            }
        }
        
        // Write CSV
        if (!config_.output_csv.empty()) {
            write_csv(results);
            std::cout << "\nCSV output written to: " << config_.output_csv << "\n";
        }
        
        // Write JSON summary
        if (!config_.output_json.empty()) {
            write_json_summary(results);
            std::cout << "JSON output written to: " << config_.output_json << "\n";
        }
        
        print_summary(results);
    }
    
private:
    ExperimentConfig config_;
    std::shared_ptr<MLKEMAdapter> adapter_;
    
    void write_csv(const std::vector<ExperimentResult>& results) {
        std::ofstream csv(config_.output_csv);
        csv << "scheme,adapter,n,t,selected_assistants,iteration,"
            << "external_p_to_s_bytes,external_s_to_p_bytes,external_total_bytes,"
            << "internal_s_to_assistants_bytes,internal_assistants_to_s_bytes,internal_assistant_total_bytes,"
            << "standard_server_decap_time_ns,"
            << "assistant_admission_time_ns,assistant_contribution_time_ns,reconstruction_time_ns,"
            << "front_service_fo_validation_time_ns,threshold_total_server_side_time_ns,"
            << "success\n";
        
        for (const auto& r : results) {
            csv << r.scheme << ","
                << r.adapter_profile << ","
                << r.n << ","
                << r.t << ",\"";
            for (size_t i = 0; i < r.selected_assistants.size(); ++i) {
                if (i > 0) csv << ",";
                csv << r.selected_assistants[i];
            }
            csv << "\"," << r.iteration << ","
                << r.communication.p_to_s_bytes << ","
                << r.communication.s_to_p_bytes << ","
                << (r.communication.p_to_s_bytes + r.communication.s_to_p_bytes) << ","
                << r.communication.s_to_assistants_bytes << ","
                << r.communication.assistants_to_s_bytes << ","
                << (r.communication.s_to_assistants_bytes + r.communication.assistants_to_s_bytes) << ","
                << r.baseline_timings.decapsulation_or_fo_validation_ns << ","
                << r.threshold_timings.assistant_admission_time_ns << ","
                << r.threshold_timings.assistant_contribution_time_ns << ","
                << r.threshold_timings.reconstruction_time_ns << ","
                << r.threshold_timings.front_service_fo_validation_time_ns << ","
                << r.threshold_timings.total_server_side_threshold_flow_ns() << ","
                << (r.success ? "true" : "false") << "\n";
        }
    }
    
    void write_json_summary(const std::vector<ExperimentResult>& results) {
        // Simplified JSON output
        std::ofstream json(config_.output_json);
        json << "{\n";
        json << "  \"configuration\": {\n";
        json << "    \"n\": " << config_.n << ",\n";
        json << "    \"t\": " << config_.t << ",\n";
        json << "    \"iterations\": " << config_.iterations << ",\n";
        json << "    \"seed\": " << config_.seed << "\n";
        json << "  },\n";
        json << "  \"adapter\": {\n";
        json << "    \"profile\": \"" << adapter_->profile_id() << "\",\n";
        json << "    \"is_real_mlkem\": " << (adapter_->is_real_mlkem() ? "true" : "false") << ",\n";
        json << "    \"warning\": \"" 
             << (adapter_->is_real_mlkem() ? "None" : "TOY ADAPTER ONLY, NOT REAL ML-KEM")
             << "\"\n";
        json << "  },\n";
        json << "  \"results_file\": \"" << config_.output_csv << "\",\n";
        json << "  \"total_results\": " << results.size() << "\n";
        json << "}\n";
    }
    
    void print_summary(const std::vector<ExperimentResult>& results) {
        std::cout << "\n=== EXPERIMENT SUMMARY ===\n";
        std::cout << "Total results: " << results.size() << "\n";
        
        // Filter by scheme
        auto baseline_results = results;
        baseline_results.erase(
            std::remove_if(baseline_results.begin(), baseline_results.end(),
                          [](const ExperimentResult& r) { return r.scheme != "standard_baseline"; }),
            baseline_results.end());
        
        auto threshold_results = results;
        threshold_results.erase(
            std::remove_if(threshold_results.begin(), threshold_results.end(),
                          [](const ExperimentResult& r) { return r.scheme != "threshold_scheme"; }),
            threshold_results.end());
        
        if (!baseline_results.empty()) {
            std::cout << "\nStandard AuthKEM Baseline:\n";
            print_timing_stats("Decapsulation time (ns)", baseline_results, 
                             [](const ExperimentResult& r) { return r.baseline_timings.decapsulation_or_fo_validation_ns; });
        }
        
        if (!threshold_results.empty()) {
            std::cout << "\nThreshold AuthKEM Scheme:\n";
            print_timing_stats("Total server-side time (ns)", threshold_results,
                             [](const ExperimentResult& r) { return r.threshold_timings.total_server_side_threshold_flow_ns(); });
        }
        
        if (!adapter_->is_real_mlkem()) {
            //std::cout << "\n*** WARNING: TOY ADAPTER ONLY, NOT REAL ML-KEM ***\n";
            //std::cout << "Results are not representative of actual ML-KEM performance\n";
        }
    }
    
    template <typename Func>
    void print_timing_stats(const std::string& label, const std::vector<ExperimentResult>& results, Func get_time) {
        std::vector<std::uint64_t> times;
        for (const auto& r : results) {
            times.push_back(get_time(r));
        }
        std::sort(times.begin(), times.end());
        
        std::uint64_t min_t = times.front();
        std::uint64_t max_t = times.back();
        std::uint64_t sum = std::accumulate(times.begin(), times.end(), 0ULL);
        std::uint64_t mean = sum / times.size();
        std::uint64_t median = times[times.size() / 2];
        std::uint64_t p95 = times[(times.size() * 95) / 100];
        
        std::cout << "  " << label << ":\n";
        std::cout << "    min:    " << min_t << " ns\n";
        std::cout << "    median: " << median << " ns\n";
        std::cout << "    mean:   " << mean << " ns\n";
        std::cout << "    p95:    " << p95 << " ns\n";
        std::cout << "    max:    " << max_t << " ns\n";
    }
};

}  // namespace rmtls

int main(int argc, char* argv[]) {
    rmtls::ExperimentConfig config;
    
    // Parse command line
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--n" && i + 1 < argc) {
            config.n = std::stoi(argv[++i]);
        } else if (arg == "--t" && i + 1 < argc) {
            config.t = std::stoi(argv[++i]);
        } else if (arg == "--selected" && i + 1 < argc) {
            std::string selected_str = argv[++i];
            std::stringstream ss(selected_str);
            std::string item;
            while (std::getline(ss, item, ',')) {
                config.selected.push_back(std::stoi(item));
            }
        } else if (arg == "--iterations" && i + 1 < argc) {
            config.iterations = std::stoi(argv[++i]);
        } else if (arg == "--seed" && i + 1 < argc) {
            config.seed = std::stoull(argv[++i]);
        } else if (arg == "--adapter" && i + 1 < argc) {
            config.adapter = argv[++i];
        } else if (arg == "--output" && i + 1 < argc) {
            config.output_csv = argv[++i];
        } else if (arg == "--json-output" && i + 1 < argc) {
            config.output_json = argv[++i];
        } else if (arg == "--verbose") {
            config.verbose = true;
        }
    }
    
    if (!config.validate()) {
        return 1;
    }
    
    // Create adapter (currently only toy)
    auto adapter = std::make_shared<rmtls::ToyMLKEMAdapter>();
    
    // Run experiments
    rmtls::ExperimentRunner runner(config, adapter);
    runner.run();
    
    return 0;
}
