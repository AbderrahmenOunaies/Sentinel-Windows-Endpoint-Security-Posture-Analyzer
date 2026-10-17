#pragma once

#include <string>
#include <string_view>
#include <utility>

namespace sentinel::core {

enum class ErrorCode {
    Success,
    PermissionDenied,
    NotSupported,
    NotFound,
    SystemError
};

[[nodiscard]] constexpr std::string_view errorCodeToString(ErrorCode code) noexcept {
    switch (code) {
        case ErrorCode::Success:          return "Success";
        case ErrorCode::PermissionDenied: return "PermissionDenied";
        case ErrorCode::NotSupported:     return "NotSupported";
        case ErrorCode::NotFound:         return "NotFound";
        case ErrorCode::SystemError:      return "SystemError";
    }
    return "UnknownError";
}

template <typename T>
class CollectionResult {
public:
    CollectionResult(T value)
        : m_value(std::move(value)), m_code(ErrorCode::Success) {}

    CollectionResult(ErrorCode code, std::string message)
        : m_code(code), m_message(std::move(message)) {}

    [[nodiscard]] bool isSuccess() const noexcept { return m_code == ErrorCode::Success; }
    [[nodiscard]] ErrorCode code() const noexcept { return m_code; }
    [[nodiscard]] const std::string& errorMessage() const noexcept { return m_message; }

    [[nodiscard]] const T& value() const { return m_value; }
    [[nodiscard]] T& value() { return m_value; }

    [[nodiscard]] const T* operator->() const { return &m_value; }
    [[nodiscard]] T* operator->() { return &m_value; }

    static CollectionResult<T> success(T val) {
        return CollectionResult<T>(std::move(val));
    }

    static CollectionResult<T> failure(ErrorCode code, std::string message) {
        return CollectionResult<T>(code, std::move(message));
    }

private:
    T m_value{};
    ErrorCode m_code{ErrorCode::Success};
    std::string m_message;
};

template <typename T>
using Result = CollectionResult<T>;

} // namespace sentinel::core
