#pragma once

#include "Evidence.h"
#include <string>
#include <string_view>
#include <vector>

namespace sentinel::core {

enum class EvaluationState {
    True,
    False,
    Unknown
};

enum class RuleOutcome {
    Pass,
    Fail,
    Unknown
};

[[nodiscard]] constexpr std::string_view ruleOutcomeToString(RuleOutcome outcome) noexcept {
    switch (outcome) {
        case RuleOutcome::Pass:    return "Pass";
        case RuleOutcome::Fail:    return "Fail";
        case RuleOutcome::Unknown: return "Unknown";
    }
    return "Unknown";
}

struct RuleEvaluation {
    std::string ruleId;
    std::string title;
    RuleOutcome outcome{RuleOutcome::Unknown};
    std::vector<Evidence> evidence;
    std::string reason;
};

} // namespace sentinel::core
