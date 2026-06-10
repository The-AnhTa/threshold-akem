#pragma once

#include <array>
#include <cstddef>
#include <string_view>

namespace rmtls::detail {

inline char ascii_lower(char value) noexcept {
    if (value >= 'A' && value <= 'Z') {
        return static_cast<char>(value - 'A' + 'a');
    }
    return value;
}

inline bool ascii_equal_case_insensitive(
    std::string_view value,
    std::size_t offset,
    std::string_view expected) noexcept {
    if (offset > value.size() || expected.size() > value.size() - offset) {
        return false;
    }
    for (std::size_t index = 0; index < expected.size(); ++index) {
        if (ascii_lower(value[offset + index]) != expected[index]) {
            return false;
        }
    }
    return true;
}

inline bool contains_case_insensitive(
    std::string_view value,
    std::string_view expected) noexcept {
    for (std::size_t offset = 0; offset <= value.size(); ++offset) {
        if (ascii_equal_case_insensitive(value, offset, expected)) {
            return true;
        }
    }
    return false;
}

inline bool is_public_token_character(char value) noexcept {
    const char lowered = ascii_lower(value);
    return (lowered >= 'a' && lowered <= 'z') ||
           (lowered >= '0' && lowered <= '9');
}

inline bool contains_standalone_token(
    std::string_view value,
    std::string_view token) noexcept {
    for (std::size_t offset = 0; offset <= value.size(); ++offset) {
        if (!ascii_equal_case_insensitive(value, offset, token)) {
            continue;
        }
        const bool starts_at_boundary =
            offset == 0 || !is_public_token_character(value[offset - 1]);
        const std::size_t end = offset + token.size();
        const bool ends_at_boundary =
            end == value.size() || !is_public_token_character(value[end]);
        if (starts_at_boundary && ends_at_boundary) {
            return true;
        }
    }
    return false;
}

inline bool contains_forbidden_public_token(std::string_view value) noexcept {
    static constexpr std::array<std::string_view, 8> compound_tokens{
        "delta_i",
        "delta_hat",
        "m_prime",
        "k_kem",
        "z_s",
        "k_s_kem",
        "fo-success",
        "fo-failure",
    };
    for (std::string_view token : compound_tokens) {
        if (contains_case_insensitive(value, token)) {
            return true;
        }
    }

    static constexpr std::array<std::string_view, 6> standalone_tokens{
        "delta",
        "w",
        "sk",
        "valid",
        "invalid",
        "branch",
    };
    for (std::string_view token : standalone_tokens) {
        if (contains_standalone_token(value, token)) {
            return true;
        }
    }
    return false;
}

} // namespace rmtls::detail
