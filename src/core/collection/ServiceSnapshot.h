#pragma once

#include <string>
#include <string_view>
#include <cstdint>
#include <optional>
#include <vector>

namespace sentinel::core {

enum class ServiceState {
    Unknown,
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused
};

[[nodiscard]] constexpr std::string_view serviceStateToString(ServiceState state) noexcept {
    switch (state) {
        case ServiceState::Stopped:         return "Stopped";
        case ServiceState::StartPending:    return "StartPending";
        case ServiceState::StopPending:     return "StopPending";
        case ServiceState::Running:         return "Running";
        case ServiceState::ContinuePending: return "ContinuePending";
        case ServiceState::PausePending:    return "PausePending";
        case ServiceState::Paused:          return "Paused";
        case ServiceState::Unknown:         return "Unknown";
    }
    return "Unknown";
}

enum class ServiceStartType {
    Unknown,
    Boot,
    System,
    Automatic,
    Manual,
    Disabled
};

[[nodiscard]] constexpr std::string_view serviceStartTypeToString(ServiceStartType startType) noexcept {
    switch (startType) {
        case ServiceStartType::Boot:      return "Boot";
        case ServiceStartType::System:    return "System";
        case ServiceStartType::Automatic: return "Automatic";
        case ServiceStartType::Manual:    return "Manual";
        case ServiceStartType::Disabled:  return "Disabled";
        case ServiceStartType::Unknown:   return "Unknown";
    }
    return "Unknown";
}

struct ServiceInfo {
    std::string name;
    std::string displayName;

    ServiceState state{ServiceState::Unknown};
    ServiceStartType startType{ServiceStartType::Unknown};

    std::string binaryPath;
    std::optional<std::string> account;
    std::optional<std::uint32_t> processId;
};

struct ServiceSnapshot {
    std::vector<ServiceInfo> services;
};

} // namespace sentinel::core
