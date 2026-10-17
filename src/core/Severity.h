#pragma once

#include <string>
#include <string_view>

namespace sentinel::core {

enum class Severity {
    Info,
    Low,
    Medium,
    High,
    Critical
};

[[nodiscard]] constexpr std::string_view severityToString(Severity severity) noexcept {
    switch (severity) {
        case Severity::Info:     return "Info";
        case Severity::Low:      return "Low";
        case Severity::Medium:   return "Medium";
        case Severity::High:     return "High";
        case Severity::Critical: return "Critical";
    }
    return "Unknown";
}

[[nodiscard]] constexpr Severity severityFromString(std::string_view str) noexcept {
    if (str == "Critical" || str == "CRITICAL") return Severity::Critical;
    if (str == "High"     || str == "HIGH")     return Severity::High;
    if (str == "Medium"   || str == "MEDIUM")   return Severity::Medium;
    if (str == "Low"      || str == "LOW")      return Severity::Low;
    return Severity::Info;
}

[[nodiscard]] constexpr int severityScorePenalty(Severity severity) noexcept {
    switch (severity) {
        case Severity::Critical: return 25;
        case Severity::High:     return 10;
        case Severity::Medium:   return 5;
        case Severity::Low:      return 2;
        case Severity::Info:     return 0;
    }
    return 0;
}

} // namespace sentinel::core
