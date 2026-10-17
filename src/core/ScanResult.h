#pragma once

#include "Finding.h"
#include "SecurityScore.h"
#include "SecurityProfile.h"
#include "RuleEvaluation.h"
#include "CollectorStatus.h"

#include <string>
#include <vector>
#include <chrono>

namespace sentinel::core {

struct ScanConfiguration {
    SecurityProfile profile{SecurityProfile::createDefault(ProfileType::Standard)};
    std::vector<std::string> enabledCategories;
    bool fastScan{false};
};

struct ScanResult {
    std::string scanId;
    std::chrono::system_clock::time_point startedAt;
    std::chrono::system_clock::time_point completedAt;
    
    std::string profileName;
    SecurityScoreBreakdown scoreBreakdown;
    std::vector<RuleEvaluation> evaluations;
    std::vector<Finding> findings;
    std::vector<CollectorStatus> collectorStatuses;
    
    bool completedSuccessfully{true};
    std::string statusMessage{"Completed"};

    [[nodiscard]] std::chrono::milliseconds duration() const {
        return std::chrono::duration_cast<std::chrono::milliseconds>(completedAt - startedAt);
    }

    [[nodiscard]] size_t passedCount() const noexcept {
        size_t count = 0;
        for (const auto& ev : evaluations) {
            if (ev.outcome == RuleOutcome::Pass) ++count;
        }
        return count;
    }

    [[nodiscard]] size_t failedCount() const noexcept {
        size_t count = 0;
        for (const auto& ev : evaluations) {
            if (ev.outcome == RuleOutcome::Fail) ++count;
        }
        return count;
    }

    [[nodiscard]] size_t unknownCount() const noexcept {
        size_t count = 0;
        for (const auto& ev : evaluations) {
            if (ev.outcome == RuleOutcome::Unknown) ++count;
        }
        return count;
    }
};

} // namespace sentinel::core
