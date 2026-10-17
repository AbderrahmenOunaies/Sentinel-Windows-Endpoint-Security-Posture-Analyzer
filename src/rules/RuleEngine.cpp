#include "RuleEngine.h"
#include "DefaultRules.h"
#include "core/Logger.h"

#include <format>
#include <optional>
#include <type_traits>

namespace sentinel::rules {

namespace {

using ActualValue = std::variant<bool, int64_t, double, std::string>;

std::optional<bool> compareValue(const ActualValue& actual,
                                core::ConditionOperator op,
                                const core::RuleValue& expected) {
    if (op == core::ConditionOperator::Exists) return true;
    if (op == core::ConditionOperator::NotExists) return false;

    return std::visit([op](const auto& actualValue, const auto& expectedValue) -> std::optional<bool> {
        using ActualType = std::decay_t<decltype(actualValue)>;
        using ExpectedType = std::decay_t<decltype(expectedValue)>;

        if constexpr (std::is_same_v<ActualType, std::string> && std::is_same_v<ExpectedType, std::string>) {
            switch (op) {
                case core::ConditionOperator::Equals: return actualValue == expectedValue;
                case core::ConditionOperator::NotEquals: return actualValue != expectedValue;
                case core::ConditionOperator::Contains: return actualValue.find(expectedValue) != std::string::npos;
                case core::ConditionOperator::NotContains: return actualValue.find(expectedValue) == std::string::npos;
                default: return std::nullopt;
            }
        } else if constexpr ((std::is_same_v<ActualType, int64_t> || std::is_same_v<ActualType, double>) &&
                             (std::is_same_v<ExpectedType, int64_t> || std::is_same_v<ExpectedType, double>)) {
            const double actualNumber = static_cast<double>(actualValue);
            const double expectedNumber = static_cast<double>(expectedValue);
            switch (op) {
                case core::ConditionOperator::Equals: return actualNumber == expectedNumber;
                case core::ConditionOperator::NotEquals: return actualNumber != expectedNumber;
                case core::ConditionOperator::LessThan: return actualNumber < expectedNumber;
                case core::ConditionOperator::GreaterThan: return actualNumber > expectedNumber;
                case core::ConditionOperator::GreaterThanOrEqual: return actualNumber >= expectedNumber;
                default: return std::nullopt;
            }
        } else if constexpr (std::is_same_v<ActualType, bool> && std::is_same_v<ExpectedType, bool>) {
            switch (op) {
                case core::ConditionOperator::Equals: return actualValue == expectedValue;
                case core::ConditionOperator::NotEquals: return actualValue != expectedValue;
                default: return std::nullopt;
            }
        } else {
            return std::nullopt;
        }
    }, actual, expected);
}

core::EvaluationState evaluateValue(const ActualValue& actual, const core::RuleCondition& condition,
                                    std::vector<core::Evidence>& evidence,
                                    std::string source, std::string key, std::string value) {
    const auto comparison = compareValue(actual, condition.op, condition.value);
    if (!comparison.has_value()) return core::EvaluationState::Unknown;
    evidence.push_back({std::move(source), std::move(key), std::move(value)});
    return *comparison ? core::EvaluationState::True : core::EvaluationState::False;
}

}

RuleEngine::RuleEngine()
    : m_rules(DefaultRules::createInitialRuleSet()) {
    LOG_INFO(std::format("RuleEngine initialized with {} default security rules.", m_rules.size()));
}

RuleEngine::RuleEngine(std::vector<core::SecurityRule> rules)
    : m_rules() {
    for (auto& rule : rules) {
        if (rule.isValid()) {
            m_rules.push_back(std::move(rule));
        } else {
            LOG_WARNING("RuleEngine: rejected malformed rule definition.");
        }
    }
    LOG_INFO(std::format("RuleEngine initialized with {} custom security rules.", m_rules.size()));
}

core::EvaluationState RuleEngine::evaluateCondition(
    const core::RuleCondition& condition,
    const core::SecurityContext& context,
    const core::SecurityProfile& profile,
    std::vector<core::Evidence>& outEvidence
) const {
    const std::string& field = condition.field;

    // --- FIREWALL RULES ---
    if (field == "Firewall.Domain.Enabled") {
        if (!context.firewall || !context.firewall->collected) return core::EvaluationState::Unknown;
        bool actual = context.firewall->domain.enabled;
        return evaluateValue(actual, condition, outEvidence, "FirewallCollector", "Domain.Enabled", actual ? "true" : "false");
    }
    if (field == "Firewall.Private.Enabled") {
        if (!context.firewall || !context.firewall->collected) return core::EvaluationState::Unknown;
        bool actual = context.firewall->privateProfile.enabled;
        return evaluateValue(actual, condition, outEvidence, "FirewallCollector", "Private.Enabled", actual ? "true" : "false");
    }
    if (field == "Firewall.Public.Enabled") {
        if (!context.firewall || !context.firewall->collected) return core::EvaluationState::Unknown;
        bool actual = context.firewall->publicProfile.enabled;
        return evaluateValue(actual, condition, outEvidence, "FirewallCollector", "Public.Enabled", actual ? "true" : "false");
    }
    if (field == "Firewall.Public.DefaultInboundAction") {
        if (!context.firewall || !context.firewall->collected) return core::EvaluationState::Unknown;
        auto action = context.firewall->publicProfile.defaultInboundAction;
        if (action == core::FirewallAction::Unknown) return core::EvaluationState::Unknown;
        std::string actual = std::string(core::firewallActionToString(action));
        return evaluateValue(actual, condition, outEvidence, "FirewallCollector", "Public.DefaultInboundAction", actual);
    }

    // --- DEFENDER RULES ---
    if (field == "Defender.AntivirusEnabled") {
        if (!context.defender || !context.defender->collected || !context.defender->antivirusEnabled.has_value()) {
            return core::EvaluationState::Unknown;
        }
        bool actual = *context.defender->antivirusEnabled;
        return evaluateValue(actual, condition, outEvidence, "DefenderCollector", "AntivirusEnabled", actual ? "true" : "false");
    }
    if (field == "Defender.RealTimeProtectionEnabled") {
        if (!context.defender || !context.defender->collected || !context.defender->realTimeProtectionEnabled.has_value()) {
            return core::EvaluationState::Unknown;
        }
        bool actual = *context.defender->realTimeProtectionEnabled;
        return evaluateValue(actual, condition, outEvidence, "DefenderCollector", "RealTimeProtectionEnabled", actual ? "true" : "false");
    }
    if (field == "Defender.AntispywareEnabled") {
        if (!context.defender || !context.defender->collected || !context.defender->antispywareEnabled.has_value()) {
            return core::EvaluationState::Unknown;
        }
        bool actual = *context.defender->antispywareEnabled;
        return evaluateValue(actual, condition, outEvidence, "DefenderCollector", "AntispywareEnabled", actual ? "true" : "false");
    }
    if (field == "Defender.BehaviorMonitoringEnabled") {
        if (!context.defender || !context.defender->collected || !context.defender->behaviorMonitoringEnabled.has_value()) {
            return core::EvaluationState::Unknown;
        }
        bool actual = *context.defender->behaviorMonitoringEnabled;
        return evaluateValue(actual, condition, outEvidence, "DefenderCollector", "BehaviorMonitoringEnabled", actual ? "true" : "false");
    }

    // --- AUTHENTICATION RULES ---
    if (field == "Authentication.MinimumPasswordLength") {
        if (!context.authentication || !context.authentication->collected || !context.authentication->minimumPasswordLength.has_value()) {
            return core::EvaluationState::Unknown;
        }
        int64_t actual = *context.authentication->minimumPasswordLength;
        int64_t threshold = 8; // Default standard threshold

        // Check if current profile has parameter override for minimum_length
        if (profile.ruleOverrides.contains("AUTH-001") && profile.ruleOverrides.at("AUTH-001").contains("minimum_length")) {
            const auto& overrideValue = profile.ruleOverrides.at("AUTH-001").at("minimum_length");
            const auto* integerOverride = std::get_if<int64_t>(&overrideValue);
            if (integerOverride == nullptr) return core::EvaluationState::Unknown;
            threshold = *integerOverride;
        }

        core::RuleCondition effectiveCondition = condition;
        effectiveCondition.op = core::ConditionOperator::GreaterThanOrEqual;
        effectiveCondition.value = threshold;
        const auto state = evaluateValue(actual, effectiveCondition, outEvidence,
                                         "AuthenticationCollector", "MinimumPasswordLength", std::to_string(actual));
        if (state != core::EvaluationState::Unknown) {
            outEvidence.push_back({ "SecurityProfile", "ExpectedBaseline", std::format(">={}", threshold) });
        }
        return state;
    }
    if (field == "Authentication.PasswordComplexityRequired") {
        if (!context.authentication || !context.authentication->collected || !context.authentication->passwordComplexityRequired.has_value()) {
            return core::EvaluationState::Unknown;
        }
        bool actual = *context.authentication->passwordComplexityRequired;
        return evaluateValue(actual, condition, outEvidence, "AuthenticationCollector", "PasswordComplexityRequired", actual ? "true" : "false");
    }
    if (field == "Authentication.LockoutThreshold") {
        if (!context.authentication || !context.authentication->collected || !context.authentication->lockoutThreshold.has_value()) {
            return core::EvaluationState::Unknown;
        }
        uint32_t actual = *context.authentication->lockoutThreshold;
        return evaluateValue(static_cast<int64_t>(actual), condition, outEvidence,
                             "AuthenticationCollector", "LockoutThreshold", std::to_string(actual));
    }

    // --- ENCRYPTION RULES ---
    if (field == "Encryption.OSVolume.State") {
        if (!context.encryption || !context.encryption->collected || context.encryption->volumes.empty()) {
            return core::EvaluationState::Unknown;
        }
        const auto& vol = context.encryption->volumes.front();
        if (vol.state == core::EncryptionState::Unknown) {
            return core::EvaluationState::Unknown;
        }
        std::string actualStr = std::string(core::encryptionStateToString(vol.state));
        return evaluateValue(actualStr, condition, outEvidence, "EncryptionCollector", "Volume C: State", actualStr);
    }

    // --- UPDATES RULES ---
    if (field == "Updates.RebootRequired") {
        if (!context.updates || !context.updates->collected || !context.updates->rebootRequired.has_value()) {
            return core::EvaluationState::Unknown;
        }
        bool rebootPending = *context.updates->rebootRequired;
        return evaluateValue(rebootPending, condition, outEvidence, "UpdateCollector", "RebootRequired", rebootPending ? "true" : "false");
    }
    if (field == "Updates.ServiceRunning") {
        if (!context.updates || !context.updates->collected || !context.updates->updateServiceRunning.has_value()) {
            return core::EvaluationState::Unknown;
        }
        bool running = *context.updates->updateServiceRunning;
        return evaluateValue(running, condition, outEvidence, "UpdateCollector", "UpdateServiceRunning", running ? "true" : "false");
    }

    return core::EvaluationState::Unknown;
}

RuleEvaluationResult RuleEngine::evaluate(
    const core::SecurityContext& context,
    const core::SecurityProfile& profile
) const {
    LOG_INFO(std::format("RuleEngine: Evaluating {} rules against Profile '{}'...", m_rules.size(), profile.name));

    RuleEvaluationResult result;
    size_t passedCount = 0;
    size_t failedCount = 0;
    size_t unknownCount = 0;

    for (const auto& rule : m_rules) {
        std::vector<core::Evidence> evidence;
        core::EvaluationState evalState = evaluateCondition(rule.condition, context, profile, evidence);

        core::RuleEvaluation eval;
        eval.ruleId = rule.id;
        eval.title = rule.name;
        eval.evidence = evidence;

        if (evalState == core::EvaluationState::True) {
            eval.outcome = core::RuleOutcome::Pass;
            eval.reason = "Configuration meets required security baseline.";
            passedCount++;
        } else if (evalState == core::EvaluationState::False) {
            eval.outcome = core::RuleOutcome::Fail;
            eval.reason = rule.description;
            failedCount++;

            // Failed rule generates a concrete Finding
            core::Finding finding;
            finding.id = std::format("FINDING-{}", rule.id);
            finding.ruleId = rule.id;
            finding.title = rule.name;
            finding.severity = rule.severity;
            finding.category = rule.category;
            finding.description = rule.description;
            finding.impact = "Configuration does not meet recommended security posture guidelines.";
            finding.evidence = evidence;
            finding.recommendation = rule.recommendation;
            finding.remediationAvailable = rule.remediationAvailable;
            finding.remediationId = rule.remediationId;
            finding.detectedAt = std::chrono::system_clock::now();

            result.findings.push_back(std::move(finding));
        } else {
            eval.outcome = core::RuleOutcome::Unknown;
            eval.reason = "Necessary telemetry data is unavailable or could not be determined.";
            unknownCount++;
        }

        result.evaluations.push_back(std::move(eval));
    }

    LOG_INFO(std::format("RuleEngine: Evaluation completed: {} passed, {} failed, {} unknown. Produced {} findings.",
                         passedCount, failedCount, unknownCount, result.findings.size()));

    return result;
}

} // namespace sentinel::rules
