#pragma once

#include "rmtls_threshold_mlkem/types.hpp"

#include <string>
#include <vector>

namespace rmtls {

class PublicLog {
public:
    void emit(const PublicResult& result);
    const std::vector<std::string>& entries() const { return entries_; }
    bool contains_forbidden_token() const;
private:
    std::vector<std::string> entries_;
};

} // namespace rmtls
