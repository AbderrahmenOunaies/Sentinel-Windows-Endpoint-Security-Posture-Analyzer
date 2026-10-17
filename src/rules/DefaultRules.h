#pragma once

#include "core/SecurityRule.h"
#include <vector>

namespace sentinel::rules {

class DefaultRules {
public:
    [[nodiscard]] static std::vector<core::SecurityRule> createInitialRuleSet();
};

} // namespace sentinel::rules
