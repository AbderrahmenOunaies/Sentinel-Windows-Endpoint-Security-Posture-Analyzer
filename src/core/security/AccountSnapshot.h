#pragma once

#include <string>
#include <vector>
#include <optional>
#include <chrono>

namespace sentinel::core {

struct AccountInfo {
    std::string username;
    std::string displayName;

    bool enabled{false};
    bool passwordRequired{true};

    std::optional<bool> passwordNeverExpires;
    std::optional<bool> accountLocked;

    std::optional<std::chrono::system_clock::time_point> passwordLastSet;
    std::optional<std::chrono::system_clock::time_point> accountExpires;
};

struct AccountSnapshot {
    std::vector<AccountInfo> accounts;
    bool collected{false};
};

} // namespace sentinel::core
