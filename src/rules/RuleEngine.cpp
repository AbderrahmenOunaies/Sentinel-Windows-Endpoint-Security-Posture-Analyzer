#include "RuleEngine.h"
#include "DefaultRules.h"
#include "core/Logger.h"

#include <format>

namespace sentinel::rules {

RuleEngine::RuleEngine()
    : m_rules(DefaultRules::createInitialRuleSet()) {
    LOG_INFO(std::format("RuleEngine initialized with {} default security rules.", m_rules.size()));
}

RuleEngine::RuleEngine(std::vector<core::SecurityRule> rules)
    : m_rules(std::move(rules)) {
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
        outEvidence.push_back({ "FirewallCollector", "Domain.Enabled", actual ? "true" : "false" });
        return actual ? core::EvaluationState::True : core::EvaluationState::False;
    }
    if (field == "Firewall.Private.Enabled") {
        if (!context.firewall || !context.firewall->collected) return core::EvaluationState::Unknown;
        bool actual = context.firewall->privateProfile.enabled;
        outEvidence.push_back({ "FirewallCollector", "Private.Enabled", actual ? "true" : "false" });
        return actual ? core::EvaluationState::True : core::EvaluationState::False;
    }
    if (field == "Firewall.Public.Enabled") {
        if (!context.firewall || !context.firewall->collected) return core::EvaluationState::Unknown;
        bool actual = context.firewall->publicProfile.enabled;
        outEvidence.push_back({ "FirewallCollector", "Public.Enabled", actual ? "true" : "false" });
        return actual ? core::EvaluationState::True : core::EvaluationState::False;
    }
    if (field == "Firewall.Public.DefaultInboundAction") {
        if (!context.firewall || !context.firewall->collected) return core::EvaluationState::Unknown;
        auto action = context.firewall->publicProfile.defaultInboundAction;
        if (action == core::FirewallAction::Unknown) return core::EvaluationState::Unknown;
        std::string actual = std::string(core::firewallActionToString(action));
        outEvidence.push_back({ "FirewallCollector", "Public.DefaultInboundAction", actual });
        return (action == core::FirewallAction::Block) ? core::EvaluationState::True : core::EvaluationState::False;
    }

    // --- DEFENDER RULES ---
    if (field == "Defender.AntivirusEnabled") {
        if (!context.defender || !context.defender->collected || !context.defender->antivirusEnabled.has_value()) {
            return core::EvaluationState::Unknown;
        }
        bool actual = *context.defender->antivirusEnabled;
        outEvidence.push_back({ "DefenderCollector", "AntivirusEnabled", actual ? "true" : "false" });
        return actual ? core::EvaluationState::True : core::EvaluationState::False;
    }
    if (field == "Defender.RealTimeProtectionEnabled") {
        if (!context.defender || !context.defender->collected || !context.defender->realTimeProtectionEnabled.has_value()) {
            return core::EvaluationState::Unknown;
        }
        bool actual = *context.defender->realTimeProtectionEnabled;
        outEvidence.push_back({ "DefenderCollector", "RealTimeProtectionEnabled", actual ? "true" : "false" });
        return actual ? core::EvaluationState::True : core::EvaluationState::False;
    }
    if (field == "Defender.AntispywareEnabled") {
        if (!context.defender || !context.defender->collected || !context.defender->antispywareEnabled.has_value()) {
            return core::EvaluationState::Unknown;
        }
        bool actual = *context.defender->antispywareEnabled;
        outEvidence.push_back({ "DefenderCollector", "AntispywareEnabled", actual ? "true" : "false" });
        return actual ? core::EvaluationState::True : core::EvaluationState::False;
    }
    if (field == "Defender.BehaviorMonitoringEnabled") {
        if (!context.defender || !context.defender->collected || !context.defender->behaviorMonitoringEnabled.has_value()) {
            return core::EvaluationState::Unknown;
        }
        bool actual = *context.defender->behaviorMonitoringEnabled;
        outEvidence.push_back({ "DefenderCollector", "BehaviorMonitoringEnabled", actual ? "true" : "false" });
        return actual ? core::EvaluationState::True : core::EvaluationState::False;
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

        outEvidence.push_back({ "AuthenticationCollector", "MinimumPasswordLength", std::to_string(actual) });
        outEvidence.push_back({ "SecurityProfile", "ExpectedBaseline", std::format(">={}", threshold) });

        return (actual >= threshold) ? core::EvaluationState::True : core::EvaluationState::False;
    }
    if (field == "Authentication.PasswordComplexityRequired") {
        if (!context.authentication || !context.authentication->collected || !context.authentication->passwordComplexityRequired.has_value()) {
            return core::EvaluationState::Unknown;
        }
        bool actual = *context.authentication->passwordComplexityRequired;
        outEvidence.push_back({ "AuthenticationCollector", "PasswordComplexityRequired", actual ? "true" : "false" });
        return actual ? core::EvaluationState::True : core::EvaluationState::False;
    }
    if (field == "Authentication.LockoutThreshold") {
        if (!context.authentication || !context.authentication->collected || !context.authentication->lockoutThreshold.has_value()) {
            return core::EvaluationState::Unknown;
        }
        uint32_t actual = *context.authentication->lockoutThreshold;
        outEvidence.push_back({ "AuthenticationCollector", "LockoutThreshold", std::to_string(actual) });
        return (actual > 0) ? core::EvaluationState::True : core::EvaluationState::False;
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
        outEvidence.push_back({ "EncryptionCollector", "Volume C: State", actualStr });
        return (vol.state == core::EncryptionState::FullyEncrypted) ? core::EvaluationState::True : core::EvaluationState::False;
    }

    // --- UPDATES RULES ---
    if (field == "Updates.RebootRequired") {
        if (!context.updates || !context.updates->collected || !context.updates->rebootRequired.has_value()) {
            return core::EvaluationState::Unknown;
        }
        bool rebootPending = *context.updates->rebootRequired;
        outEvidence.push_back({ "UpdateCollector", "RebootRequired", rebootPending ? "true" : "false" });
        // Fails when reboot is required
        return (!rebootPending) ? core::EvaluationState::True : core::EvaluationState::False;
    }
    if (field == "Updates.ServiceRunning") {
        if (!context.updates || !context.updates->collected || !context.updates->updateServiceRunning.has_value()) {
            return core::EvaluationState::Unknown;
        }
        bool running = *context.updates->updateServiceRunning;
        outEvidence.push_back({ "UpdateCollector", "UpdateServiceRunning", running ? "true" : "false" });
        return running ? core::EvaluationState::True : core::EvaluationState::False;
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
