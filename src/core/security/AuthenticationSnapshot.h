#pragma once

#include <cstdint>
#include <optional>

namespace sentinel::core {

struct AuthenticationPolicySnapshot {
    std::optional<std::uint32_t> minimumPasswordLength;
    std::optional<std::uint32_t> passwordHistoryLength;

    std::optional<std::uint32_t> maximumPasswordAgeDays;
    std::optional<std::uint32_t> minimumPasswordAgeDays;

    std::optional<bool> passwordComplexityRequired;

    std::optional<std::uint32_t> lockoutThreshold;
    std::optional<std::uint32_t> lockoutDurationMinutes;
    std::optional<std::uint32_t> lockoutObservationWindowMinutes;

    bool collected{false};
};

} // namespace sentinel::core
