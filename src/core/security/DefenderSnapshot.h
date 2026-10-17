#pragma once

#include <string>
#include <optional>
#include <chrono>

namespace sentinel::core {

struct DefenderSnapshot {
    std::optional<bool> antivirusEnabled;
    std::optional<bool> realTimeProtectionEnabled;
    std::optional<bool> antispywareEnabled;
    std::optional<bool> behaviorMonitoringEnabled;
    std::optional<bool> ioavProtectionEnabled;
    std::optional<bool> potentiallyUnwantedAppProtectionEnabled;

    std::optional<std::string> engineVersion;
    std::optional<std::string> antivirusSignatureVersion;
    std::optional<std::string> antispywareSignatureVersion;

    std::optional<std::chrono::system_clock::time_point> antivirusSignatureUpdated;

    bool collected{false};
};

} // namespace sentinel::core
