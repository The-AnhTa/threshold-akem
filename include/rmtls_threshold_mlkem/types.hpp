#pragma once

#include <cstdint>
#include <limits>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace rmtls {

template <class T>
class WipingAllocator {
public:
    static_assert(std::is_trivially_copyable_v<T>);

    using value_type = T;
    using propagate_on_container_move_assignment = std::true_type;
    using propagate_on_container_swap = std::true_type;
    using is_always_equal = std::true_type;

    WipingAllocator() noexcept = default;

    template <class U>
    WipingAllocator(const WipingAllocator<U>&) noexcept {}

    [[nodiscard]] T* allocate(std::size_t count) {
        return std::allocator<T>{}.allocate(count);
    }

    void deallocate(T* pointer, std::size_t count) noexcept {
        if (pointer != nullptr) {
            volatile unsigned char* bytes =
                reinterpret_cast<volatile unsigned char*>(pointer);
            const std::size_t byte_count = count * sizeof(T);
            for (std::size_t i = 0; i < byte_count; ++i) {
                bytes[i] = 0;
            }
            std::allocator<T>{}.deallocate(pointer, count);
        }
    }
};

template <class T, class U>
bool operator==(const WipingAllocator<T>&,
                const WipingAllocator<U>&) noexcept {
    return true;
}

template <class T, class U>
bool operator!=(const WipingAllocator<T>&,
                const WipingAllocator<U>&) noexcept {
    return false;
}

using Bytes = std::vector<std::uint8_t, WipingAllocator<std::uint8_t>>;
using Coeff = std::uint16_t;
using CoeffVector = std::vector<Coeff, WipingAllocator<Coeff>>;

constexpr Coeff Q = 3329;
constexpr std::size_t MLKEM512_PUBLIC_KEY_BYTES = 800;
constexpr std::size_t MLKEM512_SECRET_KEY_BYTES = 1632;
constexpr std::size_t MLKEM512_CIPHERTEXT_BYTES = 768;
constexpr std::size_t MLKEM512_SHARED_SECRET_BYTES = 32;
constexpr std::size_t MLKEM512_S_HAT_COEFFICIENTS = 512;
constexpr std::size_t MLKEM512_INNER_COEFFICIENTS = 256;
constexpr std::size_t MLKEM512_MESSAGE_BYTES = 32;

class Combiner;
class MLKEMAdapter;
class Shamir23;

struct ThresholdParams {
    int t = 2;
    int n = 3;
};

class PrototypeError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

namespace detail {

template <class T>
void erase_value(T& value) noexcept {
    static_assert(std::is_trivially_copyable_v<T>);
    volatile unsigned char* bytes =
        reinterpret_cast<volatile unsigned char*>(std::addressof(value));
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        bytes[i] = 0;
    }
}

template <class T, class Allocator>
void erase_value(std::vector<T, Allocator>& value) noexcept {
    volatile T* elements = value.data();
    for (std::size_t i = 0; i < value.size(); ++i) {
        elements[i] = T{};
    }
    std::vector<T, Allocator> empty(value.get_allocator());
    value.swap(empty);
}

template <class T>
bool value_is_erased(const T&) noexcept {
    return false;
}

template <class T, class Allocator>
bool value_is_erased(const std::vector<T, Allocator>& value) noexcept {
    return value.empty() && value.capacity() == 0;
}

} // namespace detail

// Internal-only, move-only wrapper for sensitive values. It deliberately has
// no stream operator and clears owned storage on erase or destruction.
template <class T>
class Secret {
public:
    explicit Secret(T value) : value_(std::move(value)) {}
    Secret(const Secret&) = delete;
    Secret& operator=(const Secret&) = delete;

    Secret(Secret&& other) noexcept(std::is_nothrow_move_constructible_v<T>)
        : value_(std::move(other.value_)) {
        detail::erase_value(other.value_);
    }

    Secret& operator=(Secret&& other) noexcept(std::is_nothrow_move_assignable_v<T>) {
        if (this != &other) {
            erase_internal();
            value_ = std::move(other.value_);
            detail::erase_value(other.value_);
        }
        return *this;
    }

    ~Secret() { erase_internal(); }

    void erase_internal() noexcept { detail::erase_value(value_); }
    bool is_erased_internal() const noexcept { return detail::value_is_erased(value_); }

private:
    friend class Combiner;
    friend class MLKEMAdapter;
    friend class Shamir23;

    T value_;
};

class PublicResult {
public:
    const std::string& request_id() const noexcept {
        return request_id_;
    }

    const std::string& status_class() const noexcept {
        return status_class_;
    }

private:
    friend class MLKEMAdapter;

    PublicResult(std::string request_id, std::string status_class)
        : request_id_(std::move(request_id)),
          status_class_(std::move(status_class)) {}

    std::string request_id_;
    std::string status_class_;
};

inline Coeff mod_q(int value) {
    int r = value % static_cast<int>(Q);
    if (r < 0) r += Q;
    return static_cast<Coeff>(r);
}

} // namespace rmtls
