#pragma once

#include "Severity.h"
#include "Evidence.h"

#include <string>
#include <vector>
#include <chrono>

namespace sentinel::core {

struct Finding {
    std::string id;
    std::string ruleId;
    std::string title;

    Severity severity{Severity::Info};

    std::string category;
    std::string description;
    std::string impact;

    std::vector<Evidence> evidence;

    std::string recommendation;

    bool remediationAvailable{false};
    std::string remediationId;

    std::chrono::system_clock::time_point detectedAt{std::chrono::system_clock::now()};
};

} // namespace sentinel::core
