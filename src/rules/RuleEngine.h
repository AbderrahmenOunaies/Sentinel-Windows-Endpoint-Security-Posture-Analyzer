#pragma once

#include "core/SecurityContext.h"
#include "core/SecurityProfile.h"
#include "core/SecurityRule.h"
#include "core/Finding.h"
#include "core/RuleEvaluation.h"

#include <vector>

namespace sentinel::rules {

struct RuleEvaluationResult {
    std::vector<core::RuleEvaluation> evaluations;
    std::vector<core::Finding> findings;
};

class RuleEngine {
public:
    RuleEngine();
    explicit RuleEngine(std::vector<core::SecurityRule> rules);
    ~RuleEngine() = default;

    [[nodiscard]] RuleEvaluationResult evaluate(
        const core::SecurityContext& context,
        const core::SecurityProfile& profile
    ) const;

    [[nodiscard]] const std::vector<core::SecurityRule>& rules() const noexcept { return m_rules; }

private:
    std::vector<core::SecurityRule> m_rules;

    core::EvaluationState evaluateCondition(
        const core::RuleCondition& condition,
        const core::SecurityContext& context,
        const core::SecurityProfile& profile,
        std::vector<core::Evidence>& outEvidence
    ) const;
};

} // namespace sentinel::rules
