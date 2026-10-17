#pragma once

#include <string>
#include <vector>
#include <optional>
#include <chrono>

namespace sentinel::core {

struct UpdateInfo {
    std::string identifier;
    std::string title;
    std::optional<std::chrono::system_clock::time_point> installedAt;
    std::optional<bool> succeeded;
};

struct UpdateSnapshot {
    std::optional<bool> updateServiceRunning;
    std::optional<bool> rebootRequired;
    std::optional<std::chrono::system_clock::time_point> latestInstalledUpdate;
    std::vector<UpdateInfo> recentUpdates;

    bool collected{false};
};

} // namespace sentinel::core
