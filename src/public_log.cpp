#include "rmtls_threshold_mlkem/public_log.hpp"
#include "public_output_safety.hpp"

namespace rmtls {

void PublicLog::emit(const PublicResult& result) {
    entries_.push_back(
        "request=" + result.request_id() +
        " status=" + result.status_class());
}

bool PublicLog::contains_forbidden_token() const {
    for (const auto& e : entries_) {
        if (detail::contains_forbidden_public_token(e)) {
            return true;
        }
    }
    return false;
}

} // namespace rmtls
