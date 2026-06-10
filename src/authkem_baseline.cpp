#include "rmtls_threshold_mlkem/authkem_baseline.hpp"
#include <cstring>
#include <sstream>

namespace rmtls {

// ===== StandardAuthKEMMessage Serialization =====
Bytes StandardAuthKEMMessage::serialize() const {
    Bytes result;
    
    // Serialize strings with length prefix
    auto append_string = [&result](const std::string& s) {
        uint32_t len = s.length();
        result.insert(result.end(), (uint8_t*)&len, (uint8_t*)&len + 4);
        result.insert(result.end(), s.begin(), s.end());
    };
    
    auto append_bytes = [&result](const Bytes& b) {
        uint32_t len = b.size();
        result.insert(result.end(), (uint8_t*)&len, (uint8_t*)&len + 4);
        result.insert(result.end(), b.begin(), b.end());
    };
    
    append_string(peer_id);
    append_string(server_id);
    append_string(policy_id);
    append_bytes(ciphertext);
    
    return result;
}

StandardAuthKEMMessage StandardAuthKEMMessage::deserialize(const Bytes& data) {
    StandardAuthKEMMessage result;
    size_t offset = 0;
    
    auto read_string = [&data, &offset](std::string& s) {
        if (offset + 4 > data.size()) throw PrototypeError("deserialize: not enough data for string length");
        uint32_t len = *(uint32_t*)(data.data() + offset);
        offset += 4;
        if (offset + len > data.size()) throw PrototypeError("deserialize: not enough data for string");
        s = std::string((char*)(data.data() + offset), len);
        offset += len;
    };
    
    auto read_bytes = [&data, &offset](Bytes& b) {
        if (offset + 4 > data.size()) throw PrototypeError("deserialize: not enough data for bytes length");
        uint32_t len = *(uint32_t*)(data.data() + offset);
        offset += 4;
        if (offset + len > data.size()) throw PrototypeError("deserialize: not enough data for bytes");
        b = Bytes(data.begin() + offset, data.begin() + offset + len);
        offset += len;
    };
    
    read_string(result.peer_id);
    read_string(result.server_id);
    read_string(result.policy_id);
    read_bytes(result.ciphertext);
    
    return result;
}

// ===== StandardAuthKEMResponse Serialization =====
Bytes StandardAuthKEMResponse::serialize() const {
    Bytes result;
    
    auto append_string = [&result](const std::string& s) {
        uint32_t len = s.length();
        result.insert(result.end(), (uint8_t*)&len, (uint8_t*)&len + 4);
        result.insert(result.end(), s.begin(), s.end());
    };
    
    append_string(status);
    append_string(server_fingerprint);
    
    return result;
}

StandardAuthKEMResponse StandardAuthKEMResponse::deserialize(const Bytes& data) {
    StandardAuthKEMResponse result;
    size_t offset = 0;
    
    auto read_string = [&data, &offset](std::string& s) {
        if (offset + 4 > data.size()) throw PrototypeError("deserialize: not enough data");
        uint32_t len = *(uint32_t*)(data.data() + offset);
        offset += 4;
        if (offset + len > data.size()) throw PrototypeError("deserialize: not enough data");
        s = std::string((char*)(data.data() + offset), len);
        offset += len;
    };
    
    read_string(result.status);
    read_string(result.server_fingerprint);
    
    return result;
}

// ===== ThresholdAuthKEMMessage Serialization =====
Bytes ThresholdAuthKEMMessage::serialize() const {
    Bytes result;
    
    auto append_string = [&result](const std::string& s) {
        uint32_t len = s.length();
        result.insert(result.end(), (uint8_t*)&len, (uint8_t*)&len + 4);
        result.insert(result.end(), s.begin(), s.end());
    };
    
    auto append_bytes = [&result](const Bytes& b) {
        uint32_t len = b.size();
        result.insert(result.end(), (uint8_t*)&len, (uint8_t*)&len + 4);
        result.insert(result.end(), b.begin(), b.end());
    };
    
    auto append_int = [&result](int v) {
        result.insert(result.end(), (uint8_t*)&v, (uint8_t*)&v + 4);
    };
    
    append_string(peer_id);
    append_string(server_id);
    append_string(policy_id);
    append_bytes(ciphertext);
    append_string(threshold_key_id);
    append_int(t);
    append_int(n);
    
    // Serialize selected assistants
    uint32_t num_selected = selected_assistants.size();
    result.insert(result.end(), (uint8_t*)&num_selected, (uint8_t*)&num_selected + 4);
    for (int id : selected_assistants) {
        result.insert(result.end(), (uint8_t*)&id, (uint8_t*)&id + 4);
    }
    
    append_bytes(transcript_or_admission);
    
    return result;
}

ThresholdAuthKEMMessage ThresholdAuthKEMMessage::deserialize(const Bytes& data) {
    ThresholdAuthKEMMessage result;
    size_t offset = 0;
    
    auto read_string = [&data, &offset](std::string& s) {
        if (offset + 4 > data.size()) throw PrototypeError("deserialize: not enough data");
        uint32_t len = *(uint32_t*)(data.data() + offset);
        offset += 4;
        if (offset + len > data.size()) throw PrototypeError("deserialize: not enough data");
        s = std::string((char*)(data.data() + offset), len);
        offset += len;
    };
    
    auto read_bytes = [&data, &offset](Bytes& b) {
        if (offset + 4 > data.size()) throw PrototypeError("deserialize: not enough data");
        uint32_t len = *(uint32_t*)(data.data() + offset);
        offset += 4;
        if (offset + len > data.size()) throw PrototypeError("deserialize: not enough data");
        b = Bytes(data.begin() + offset, data.begin() + offset + len);
        offset += len;
    };
    
    auto read_int = [&data, &offset]() {
        if (offset + 4 > data.size()) throw PrototypeError("deserialize: not enough data");
        int v = *(int*)(data.data() + offset);
        offset += 4;
        return v;
    };
    
    read_string(result.peer_id);
    read_string(result.server_id);
    read_string(result.policy_id);
    read_bytes(result.ciphertext);
    read_string(result.threshold_key_id);
    result.t = read_int();
    result.n = read_int();
    
    uint32_t num_selected = read_int();
    for (uint32_t i = 0; i < num_selected; ++i) {
        result.selected_assistants.push_back(read_int());
    }
    
    read_bytes(result.transcript_or_admission);
    
    return result;
}

// ===== ThresholdAuthKEMResponse Serialization =====
Bytes ThresholdAuthKEMResponse::serialize() const {
    Bytes result;
    
    auto append_string = [&result](const std::string& s) {
        uint32_t len = s.length();
        result.insert(result.end(), (uint8_t*)&len, (uint8_t*)&len + 4);
        result.insert(result.end(), s.begin(), s.end());
    };
    
    append_string(status);
    append_string(server_fingerprint);
    
    return result;
}

ThresholdAuthKEMResponse ThresholdAuthKEMResponse::deserialize(const Bytes& data) {
    ThresholdAuthKEMResponse result;
    size_t offset = 0;
    
    auto read_string = [&data, &offset](std::string& s) {
        if (offset + 4 > data.size()) throw PrototypeError("deserialize: not enough data");
        uint32_t len = *(uint32_t*)(data.data() + offset);
        offset += 4;
        if (offset + len > data.size()) throw PrototypeError("deserialize: not enough data");
        s = std::string((char*)(data.data() + offset), len);
        offset += len;
    };
    
    read_string(result.status);
    read_string(result.server_fingerprint);
    
    return result;
}

// ===== AssistantRequest Serialization =====
Bytes AssistantRequest::serialize() const {
    Bytes result;
    
    auto append_string = [&result](const std::string& s) {
        uint32_t len = s.length();
        result.insert(result.end(), (uint8_t*)&len, (uint8_t*)&len + 4);
        result.insert(result.end(), s.begin(), s.end());
    };
    
    auto append_bytes = [&result](const Bytes& b) {
        uint32_t len = b.size();
        result.insert(result.end(), (uint8_t*)&len, (uint8_t*)&len + 4);
        result.insert(result.end(), b.begin(), b.end());
    };
    
    auto append_int = [&result](int v) {
        result.insert(result.end(), (uint8_t*)&v, (uint8_t*)&v + 4);
    };
    
    append_string(operation);
    append_int(assistant_id);
    append_bytes(payload);
    
    return result;
}

AssistantRequest AssistantRequest::deserialize(const Bytes& data) {
    AssistantRequest result;
    size_t offset = 0;
    
    auto read_string = [&data, &offset](std::string& s) {
        if (offset + 4 > data.size()) throw PrototypeError("deserialize: not enough data");
        uint32_t len = *(uint32_t*)(data.data() + offset);
        offset += 4;
        if (offset + len > data.size()) throw PrototypeError("deserialize: not enough data");
        s = std::string((char*)(data.data() + offset), len);
        offset += len;
    };
    
    auto read_bytes = [&data, &offset](Bytes& b) {
        if (offset + 4 > data.size()) throw PrototypeError("deserialize: not enough data");
        uint32_t len = *(uint32_t*)(data.data() + offset);
        offset += 4;
        if (offset + len > data.size()) throw PrototypeError("deserialize: not enough data");
        b = Bytes(data.begin() + offset, data.begin() + offset + len);
        offset += len;
    };
    
    auto read_int = [&data, &offset]() {
        if (offset + 4 > data.size()) throw PrototypeError("deserialize: not enough data");
        int v = *(int*)(data.data() + offset);
        offset += 4;
        return v;
    };
    
    read_string(result.operation);
    result.assistant_id = read_int();
    read_bytes(result.payload);
    
    return result;
}

// ===== AssistantResponse Serialization =====
Bytes AssistantResponse::serialize() const {
    Bytes result;
    
    auto append_string = [&result](const std::string& s) {
        uint32_t len = s.length();
        result.insert(result.end(), (uint8_t*)&len, (uint8_t*)&len + 4);
        result.insert(result.end(), s.begin(), s.end());
    };
    
    auto append_bytes = [&result](const Bytes& b) {
        uint32_t len = b.size();
        result.insert(result.end(), (uint8_t*)&len, (uint8_t*)&len + 4);
        result.insert(result.end(), b.begin(), b.end());
    };
    
    auto append_int = [&result](int v) {
        result.insert(result.end(), (uint8_t*)&v, (uint8_t*)&v + 4);
    };
    
    append_int(assistant_id);
    append_string(status);
    append_bytes(payload);
    
    return result;
}

AssistantResponse AssistantResponse::deserialize(const Bytes& data) {
    AssistantResponse result;
    size_t offset = 0;
    
    auto read_string = [&data, &offset](std::string& s) {
        if (offset + 4 > data.size()) throw PrototypeError("deserialize: not enough data");
        uint32_t len = *(uint32_t*)(data.data() + offset);
        offset += 4;
        if (offset + len > data.size()) throw PrototypeError("deserialize: not enough data");
        s = std::string((char*)(data.data() + offset), len);
        offset += len;
    };
    
    auto read_bytes = [&data, &offset](Bytes& b) {
        if (offset + 4 > data.size()) throw PrototypeError("deserialize: not enough data");
        uint32_t len = *(uint32_t*)(data.data() + offset);
        offset += 4;
        if (offset + len > data.size()) throw PrototypeError("deserialize: not enough data");
        b = Bytes(data.begin() + offset, data.begin() + offset + len);
        offset += len;
    };
    
    auto read_int = [&data, &offset]() {
        if (offset + 4 > data.size()) throw PrototypeError("deserialize: not enough data");
        int v = *(int*)(data.data() + offset);
        offset += 4;
        return v;
    };
    
    result.assistant_id = read_int();
    read_string(result.status);
    read_bytes(result.payload);
    
    return result;
}

}  // namespace rmtls
