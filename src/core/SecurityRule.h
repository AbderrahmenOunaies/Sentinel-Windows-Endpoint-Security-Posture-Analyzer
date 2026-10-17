#pragma once

#include "Severity.h"
#include <cstdint>
#include <string>
#include <string_view>
#include <variant>

namespace sentinel::core {

enum class ConditionOperator {
    Equals,
    NotEquals,
    LessThan,
    GreaterThan,
    Contains,
    NotContains,
    Exists,
    NotExists
};

[[nodiscard]] constexpr std::string_view conditionOperatorToString(ConditionOperator op) noexcept {
    switch (op) {
        case ConditionOperator::Equals:      return "equals";
        case ConditionOperator::NotEquals:   return "not_equals";
        case ConditionOperator::LessThan:    return "less_than";
        case ConditionOperator::GreaterThan: return "greater_than";
        case ConditionOperator::Contains:    return "contains";
        case ConditionOperator::NotContains: return "not_contains";
        case ConditionOperator::Exists:      return "exists";
        case ConditionOperator::NotExists:   return "not_exists";
    }
    return "unknown";
}

[[nodiscard]] inline ConditionOperator conditionOperatorFromString(std::string_view op) noexcept {
    if (op == "equals" || op == "==")             return ConditionOperator::Equals;
    if (op == "not_equals" || op == "!=")          return ConditionOperator::NotEquals;
    if (op == "less_than" || op == "<")            return ConditionOperator::LessThan;
    if (op == "greater_than" || op == ">")         return ConditionOperator::GreaterThan;
    if (op == "contains")                          return ConditionOperator::Contains;
    if (op == "not_contains")                      return ConditionOperator::NotContains;
    if (op == "exists")                            return ConditionOperator::Exists;
    if (op == "not_exists")                        return ConditionOperator::NotExists;
    return ConditionOperator::Equals;
}

using RuleValue = std::variant<bool, int64_t, double, std::string>;

struct RuleCondition {
    std::string field;
    ConditionOperator op{ConditionOperator::Equals};
    RuleValue value;
};

struct SecurityRule {
    std::string id;
    std::string name;
    std::string category;
    Severity severity{Severity::Medium};
    std::string description;
    RuleCondition condition;
    std::string recommendation;
    bool remediationAvailable{false};
    std::string remediationId;

    [[nodiscard]] bool isValid() const noexcept {
        return !id.empty() && !name.empty() && !category.empty() && !condition.field.empty();
    }
};

} // namespace sentinel::core
