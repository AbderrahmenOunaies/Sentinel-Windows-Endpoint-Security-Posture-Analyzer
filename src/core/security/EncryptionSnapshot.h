#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <cstdint>

namespace sentinel::core {

enum class EncryptionState {
    Unknown,
    FullyEncrypted,
    PartiallyEncrypted,
    NotEncrypted
};

[[nodiscard]] constexpr std::string_view encryptionStateToString(EncryptionState state) noexcept {
    switch (state) {
        case EncryptionState::FullyEncrypted:     return "FullyEncrypted";
        case EncryptionState::PartiallyEncrypted: return "PartiallyEncrypted";
        case EncryptionState::NotEncrypted:       return "NotEncrypted";
        case EncryptionState::Unknown:            return "Unknown";
    }
    return "Unknown";
}

struct VolumeEncryptionInfo {
    std::string volume;
    EncryptionState state{EncryptionState::Unknown};
    std::optional<std::uint32_t> encryptionPercentage;
    std::optional<std::string> encryptionMethod;
    std::optional<bool> protectionEnabled;
};

struct EncryptionSnapshot {
    std::vector<VolumeEncryptionInfo> volumes;
    bool collected{false};
};

} // namespace sentinel::core
