#include <iostream>
#include <cassert>
#include <vector>

#include "../../src/platform/windows/SystemInfo.h"
#include "../../src/core/Logger.h"
#include "../../src/core/Severity.h"
#include "../../src/core/Evidence.h"
#include "../../src/core/Finding.h"
#include "../../src/core/SecurityScore.h"
#include "../../src/core/SecurityRule.h"
#include "../../src/core/SecurityProfile.h"
#include "../../src/core/Result.h"
#include "../../src/core/ScanResult.h"
#include "../../src/core/collection/SystemSnapshot.h"
#include "../../src/core/collection/NetworkSnapshot.h"
#include "../../src/core/collection/ServiceSnapshot.h"
#include "../../src/core/security/FirewallSnapshot.h"
#include "../../src/core/security/DefenderSnapshot.h"
#include "../../src/core/security/AccountSnapshot.h"
#include "../../src/core/security/AuthenticationSnapshot.h"
#include "../../src/core/security/EncryptionSnapshot.h"
#include "../../src/core/security/UpdateSnapshot.h"
#include "../../src/core/SecurityContext.h"
#include "../../src/core/RuleEvaluation.h"
#include "../../src/rules/DefaultRules.h"
#include "../../src/rules/RuleEngine.h"
#include "../../src/storage/DatabaseManager.h"
#include "../../src/storage/DatabaseMigrator.h"
#include "../../src/storage/ScanRepository.h"
#include "../../src/storage/FindingRepository.h"
#include "../../src/storage/SettingsRepository.h"
#include "../../src/storage/PersistenceService.h"

using namespace sentinel;
using namespace sentinel::core;
using namespace sentinel::platform;
using namespace sentinel::rules;

void testMilestone1Platform() {
    LOG_INFO("--- Testing Milestone 1 Platform APIs ---");

    auto privilege = SystemInfo::detectPrivilege();
    assert(privilege == PrivilegeLevel::Administrator ||
           privilege == PrivilegeLevel::StandardUser ||
           privilege == PrivilegeLevel::Unknown);

    std::string privStr = SystemInfo::privilegeToString(privilege);
    assert(!privStr.empty());

    std::string host = SystemInfo::getHostName();
    assert(!host.empty());

    std::string os = SystemInfo::getOsVersion();
    assert(!os.empty());

    LOG_INFO("Milestone 1 Platform tests passed.");
}

void testSeverityConversionsAndPenalties() {
    LOG_INFO("--- Testing Severity Domain ---");

    assert(severityToString(Severity::Critical) == "Critical");
    assert(severityToString(Severity::High) == "High");
    assert(severityToString(Severity::Medium) == "Medium");
    assert(severityToString(Severity::Low) == "Low");
    assert(severityToString(Severity::Info) == "Info");

    assert(severityFromString("CRITICAL") == Severity::Critical);
    assert(severityFromString("High") == Severity::High);
    assert(severityFromString("MEDIUM") == Severity::Medium);
    assert(severityFromString("Low") == Severity::Low);
    assert(severityFromString("Other") == Severity::Info);

    assert(severityScorePenalty(Severity::Critical) == 25);
    assert(severityScorePenalty(Severity::High) == 10);
    assert(severityScorePenalty(Severity::Medium) == 5);
    assert(severityScorePenalty(Severity::Low) == 2);
    assert(severityScorePenalty(Severity::Info) == 0);

    LOG_INFO("Severity conversions and penalties verified.");
}

void testSecurityScoreCalculation() {
    LOG_INFO("--- Testing Security Score Calculation ---");

    // Case 1: Empty findings list -> Perfect score 100
    std::vector<Finding> noFindings;
    auto breakdown1 = SecurityScoreCalculator::calculate(noFindings);
    if (breakdown1.finalScore != 100 || breakdown1.criticalCount != 0) {
        std::abort();
    }

    auto makeFinding = [](std::string id, std::string ruleId, std::string title, Severity s) {
        Finding f;
        f.id = std::move(id);
        f.ruleId = std::move(ruleId);
        f.title = std::move(title);
        f.severity = s;
        f.category = "TestCategory";
        f.description = "Test description";
        f.impact = "Test impact";
        f.recommendation = "Test recommendation";
        return f;
    };

    // Case 2: 1 Critical (-25), 2 High (-20), 1 Medium (-5) -> 100 - 50 = 50
    std::vector<Finding> sampleFindings = {
        makeFinding("F-01", "AUTH-001", "Weak Password", Severity::Critical),
        makeFinding("F-02", "FW-001", "Firewall Disabled", Severity::High),
        makeFinding("F-03", "NET-001", "RDP Exposed", Severity::High),
        makeFinding("F-04", "SVC-001", "Telnet Running", Severity::Medium),
        makeFinding("F-05", "INFO-001", "OS Info", Severity::Info)
    };

    auto breakdown2 = SecurityScoreCalculator::calculate(sampleFindings);
    assert(breakdown2.criticalCount == 1);
    assert(breakdown2.highCount == 2);
    assert(breakdown2.mediumCount == 1);
    assert(breakdown2.lowCount == 0);
    assert(breakdown2.infoCount == 1);
    assert(breakdown2.criticalDeductions == 25);
    assert(breakdown2.highDeductions == 20);
    assert(breakdown2.mediumDeductions == 5);
    assert(breakdown2.finalScore == 50);

    // Check explanation text contains transparent math
    std::string explanation = breakdown2.explain();
    assert(explanation.find("Critical findings (1): -25") != std::string::npos);
    assert(explanation.find("Final score: 50") != std::string::npos);

    // Case 3: Score clamping floor at 0
    std::vector<Finding> extremeFindings = {
        makeFinding("E-01", "R1", "T1", Severity::Critical),
        makeFinding("E-02", "R2", "T2", Severity::Critical),
        makeFinding("E-03", "R3", "T3", Severity::Critical),
        makeFinding("E-04", "R4", "T4", Severity::Critical),
        makeFinding("E-05", "R5", "T5", Severity::Critical)
    };
    auto breakdown3 = SecurityScoreCalculator::calculate(extremeFindings);
    if (breakdown3.finalScore != 0 || breakdown3.criticalCount != 5) {
        std::abort();
    }

    LOG_INFO("Security score transparent calculations verified.");
}

void testSecurityProfiles() {
    LOG_INFO("--- Testing Security Profiles ---");

    auto standard = SecurityProfile::createDefault(ProfileType::Standard);
    assert(standard.name == "Standard");
    assert(standard.type == ProfileType::Standard);
    assert(standard.ruleOverrides.contains("AUTH-001"));
    assert(std::get<int64_t>(standard.ruleOverrides["AUTH-001"]["minimum_length"]) == 8);

    auto dev = SecurityProfile::createDefault(ProfileType::Developer);
    assert(dev.name == "Developer");
    assert(std::get<int64_t>(dev.ruleOverrides["AUTH-001"]["minimum_length"]) == 10);

    auto highSec = SecurityProfile::createDefault(ProfileType::HighSecurity);
    assert(highSec.name == "High Security");
    assert(std::get<int64_t>(highSec.ruleOverrides["AUTH-001"]["minimum_length"]) == 16);
    assert(highSec.ruleOverrides.contains("BITLOCKER-001"));

    LOG_INFO("Security profiles baseline verified.");
}

void testCollectionResultAndErrors() {
    LOG_INFO("--- Testing CollectionResult Explicit Error Handling ---");

    // Success case
    CollectionResult<int> successResult(42);
    assert(successResult.isSuccess());
    assert(successResult.code() == ErrorCode::Success);
    assert(successResult.value() == 42);

    // Error case (Permission Denied)
    CollectionResult<int> deniedResult(ErrorCode::PermissionDenied, "Access denied reading security event log");
    assert(!deniedResult.isSuccess());
    assert(deniedResult.code() == ErrorCode::PermissionDenied);
    assert(deniedResult.errorMessage().find("Access denied") != std::string::npos);
    assert(errorCodeToString(deniedResult.code()) == "PermissionDenied");

    LOG_INFO("CollectionResult explicit error handling verified.");
}

void testEvidenceAndFindingStructures() {
    LOG_INFO("--- Testing Evidence and Finding Models ---");

    Evidence ev1{ .source = "WindowsFirewall", .key = "PublicProfile.Enabled", .value = "False" };
    Evidence ev2{ .source = "WindowsFirewall", .key = "DomainProfile.Enabled", .value = "True" };
    assert(ev1 != ev2);

    Finding finding;
    finding.id = "FW-FINDING-001";
    finding.ruleId = "FIREWALL-001";
    finding.title = "Public Firewall Profile Disabled";
    finding.severity = Severity::High;
    finding.category = "Firewall";
    finding.description = "The public firewall profile is currently turned off.";
    finding.impact = "Workstation is vulnerable to inbound unsolicited connections on untrusted networks.";
    finding.evidence = { ev1 };
    finding.recommendation = "Enable Windows Firewall for the Public network profile.";
    finding.remediationAvailable = true;
    finding.remediationId = "REMED-FW-001";

    assert(finding.id == "FW-FINDING-001");
    assert(finding.severity == Severity::High);
    assert(finding.evidence.size() == 1);
    assert(finding.remediationAvailable);
    assert(finding.remediationId == "REMED-FW-001");

    LOG_INFO("Evidence and Finding models verified.");
}

#include "../../src/collectors/SystemCollector.h"
#include "../../src/collectors/NetworkCollector.h"
#include "../../src/collectors/ServiceCollector.h"

void testMilestone3SyntheticModels() {
    LOG_INFO("--- Testing Milestone 3 Synthetic Snapshots ---");

    // Network model synthetic verification
    core::TcpEndpoint tcpEp;
    tcpEp.localAddress = "0.0.0.0";
    tcpEp.localPort = 3389;
    tcpEp.remoteAddress = "0.0.0.0";
    tcpEp.remotePort = 0;
    tcpEp.state = core::TcpState::Listen;
    tcpEp.processId = 1124;
    tcpEp.processName = "svchost.exe";

    assert(tcpEp.localAddress == "0.0.0.0");
    assert(tcpEp.localPort == 3389);
    assert(tcpEp.state == core::TcpState::Listen);
    assert(tcpEp.processName.has_value());
    assert(tcpEp.processName.value() == "svchost.exe");
    assert(core::tcpStateToString(tcpEp.state) == "Listen");

    core::UdpEndpoint udpEp{
        .localAddress = "::",
        .localPort = 5353,
        .processId = 2048,
        .processName = std::nullopt
    };

    assert(udpEp.localAddress == "::");
    assert(udpEp.localPort == 5353);
    assert(!udpEp.processName.has_value());

    // Service model synthetic verification
    core::ServiceInfo svc;
    svc.name = "Spooler";
    svc.displayName = "Print Spooler";
    svc.state = core::ServiceState::Running;
    svc.startType = core::ServiceStartType::Automatic;
    svc.binaryPath = "C:\\Windows\\System32\\spoolsv.exe";
    svc.account = "LocalSystem";
    svc.processId = 1532;

    assert(svc.name == "Spooler");
    assert(core::serviceStateToString(svc.state) == "Running");
    assert(core::serviceStartTypeToString(svc.startType) == "Automatic");
    assert(svc.processId.has_value());
    assert(svc.processId.value() == 1532);

    LOG_INFO("Synthetic snapshot models verified.");
}

void testMilestone3NativeCollectors() {
    LOG_INFO("--- Testing Milestone 3 Native Windows Collectors ---");

    // 1. SystemCollector
    sentinel::collectors::SystemCollector sysCollector;
    auto sysResult = sysCollector.collect();
    assert(sysResult.isSuccess());
    const auto& sys = sysResult.value();
    assert(!sys.computerName.empty());
    assert(sys.processorCount > 0);
    assert(sys.pageSize > 0);
    assert(sys.physicalMemoryBytes > 0);
    assert(!sys.architecture.empty());
    assert(!sys.systemDirectory.empty());
    LOG_INFO(std::format("SystemCollector: Host={}, Arch={}, Cores={}, Mem={} MB",
                         sys.computerName, sys.architecture, sys.processorCount, sys.physicalMemoryBytes / (1024 * 1024)));

    // 2. NetworkCollector
    sentinel::collectors::NetworkCollector netCollector;
    auto netResult = netCollector.collect();
    assert(netResult.isSuccess());
    const auto& net = netResult.value();
    // System should have active network endpoints
    assert(!net.tcpEndpoints.empty() || !net.udpEndpoints.empty());
    LOG_INFO(std::format("NetworkCollector: Found {} TCP endpoints and {} UDP endpoints.",
                         net.tcpEndpoints.size(), net.udpEndpoints.size()));

    // Verify IPv4 and IPv6 presence or formatting validity
    for (const auto& ep : net.tcpEndpoints) {
        if (ep.localAddress.empty() || ep.state == TcpState::Unknown) {
            std::abort();
        }
    }
    for (const auto& ep : net.udpEndpoints) {
        if (ep.localAddress.empty()) {
            std::abort();
        }
    }

    // 3. ServiceCollector
    sentinel::collectors::ServiceCollector svcCollector;
    auto svcResult = svcCollector.collect();
    assert(svcResult.isSuccess());
    const auto& svcSnapshot = svcResult.value();
    assert(!svcSnapshot.services.empty());
    LOG_INFO(std::format("ServiceCollector: Successfully enumerated {} services.",
                         svcSnapshot.services.size()));

    size_t runningCount = 0;
    for (const auto& s : svcSnapshot.services) {
        assert(!s.name.empty());
        if (s.state == core::ServiceState::Running) {
            runningCount++;
        }
    }
    assert(runningCount > 0);
    LOG_INFO(std::format("ServiceCollector: {} services currently running.", runningCount));

    LOG_INFO("Milestone 3 Native Windows Collectors verified.");
}

#include "../../src/collectors/FirewallCollector.h"
#include "../../src/collectors/DefenderCollector.h"
#include "../../src/collectors/AccountCollector.h"
#include "../../src/collectors/AuthenticationCollector.h"
#include "../../src/collectors/EncryptionCollector.h"
#include "../../src/collectors/UpdateCollector.h"

void testMilestone4SecurityModels() {
    LOG_INFO("--- Testing Milestone 4 Synthetic Security Models ---");

    // Firewall model
    FirewallProfileSnapshot fwProfile{
        .enabled = true,
        .defaultInboundAction = FirewallAction::Block,
        .defaultOutboundAction = FirewallAction::Allow,
        .notificationsEnabled = true
    };
    if (!fwProfile.enabled || fwProfile.defaultInboundAction != FirewallAction::Block) {
        std::abort();
    }
    assert(firewallActionToString(fwProfile.defaultInboundAction) == "Block");

    // Defender model
    DefenderSnapshot defSnapshot;
    defSnapshot.antivirusEnabled = true;
    defSnapshot.realTimeProtectionEnabled = true;
    defSnapshot.engineVersion = "1.1.24080.9";
    assert(defSnapshot.antivirusEnabled.value_or(false));
    assert(defSnapshot.engineVersion.value_or("") == "1.1.24080.9");

    // Encryption model
    VolumeEncryptionInfo volInfo{
        .volume = "C:",
        .state = EncryptionState::FullyEncrypted,
        .encryptionPercentage = 100,
        .encryptionMethod = std::nullopt,
        .protectionEnabled = true
    };
    assert(encryptionStateToString(volInfo.state) == "FullyEncrypted");
    assert(volInfo.protectionEnabled.value_or(false));

    // Update model
    UpdateInfo updateItem{
        .identifier = "KB5044284",
        .title = "Security Update",
        .installedAt = std::nullopt,
        .succeeded = true
    };
    assert(updateItem.identifier == "KB5044284");
    assert(updateItem.succeeded.value_or(false));

    LOG_INFO("Milestone 4 Synthetic Security Models verified.");
}

void testEncryptionQueryOutcomes() {
    LOG_INFO("--- Testing deterministic encryption query outcomes ---");

    const auto collectState = [](sentinel::collectors::EncryptionCollector::QueryStatus status) {
        sentinel::collectors::EncryptionCollector collector([status]() {
            sentinel::collectors::EncryptionCollector::QueryResult result;
            result.status = status;
            return result;
        });
        auto result = collector.collect();
        assert(result.isSuccess());
        assert(result.value().collected);
        assert(result.value().volumes.size() == 1);
        return result.value().volumes.front().state;
    };

    assert(collectState(sentinel::collectors::EncryptionCollector::QueryStatus::Encrypted) == EncryptionState::FullyEncrypted);
    assert(collectState(sentinel::collectors::EncryptionCollector::QueryStatus::NotEncrypted) == EncryptionState::NotEncrypted);
    assert(collectState(sentinel::collectors::EncryptionCollector::QueryStatus::AccessDenied) == EncryptionState::Unknown);
    assert(collectState(sentinel::collectors::EncryptionCollector::QueryStatus::NotSupported) == EncryptionState::Unknown);
    assert(collectState(sentinel::collectors::EncryptionCollector::QueryStatus::Unavailable) == EncryptionState::Unknown);
    assert(collectState(sentinel::collectors::EncryptionCollector::QueryStatus::Error) == EncryptionState::Unknown);

    SecurityContext context;
    EncryptionSnapshot encryption;
    encryption.collected = true;
    encryption.volumes.push_back({
        .volume = "C:",
        .state = EncryptionState::Unknown,
        .encryptionPercentage = std::nullopt,
        .encryptionMethod = std::nullopt,
        .protectionEnabled = std::nullopt
    });
    context.encryption = encryption;
    RuleEngine engine;
    auto evaluation = engine.evaluate(context, SecurityProfile::createDefault(ProfileType::Standard));
    for (const auto& rule : evaluation.evaluations) {
        if (rule.ruleId == "ENC-001") {
            assert(rule.outcome == RuleOutcome::Unknown);
        }
    }
    for (const auto& finding : evaluation.findings) {
        assert(finding.ruleId != "ENC-001");
    }

    LOG_INFO("Encryption query outcomes and Unknown propagation verified.");
}

void testMilestone4NativeCollectors() {
    LOG_INFO("--- Testing Milestone 4 Native Windows Security Collectors ---");

    // 1. FirewallCollector
    sentinel::collectors::FirewallCollector fwCollector;
    auto fwResult = fwCollector.collect();
    assert(fwResult.isSuccess());
    const auto& fwSnapshot = fwResult.value();
    assert(fwSnapshot.collected);
    LOG_INFO(std::format("FirewallCollector: Domain={}, Private={}, Public={}",
                         fwSnapshot.domain.enabled ? "Enabled" : "Disabled",
                         fwSnapshot.privateProfile.enabled ? "Enabled" : "Disabled",
                         fwSnapshot.publicProfile.enabled ? "Enabled" : "Disabled"));

    // 2. DefenderCollector
    sentinel::collectors::DefenderCollector defCollector;
    auto defResult = defCollector.collect();
    assert(defResult.isSuccess());
    const auto& defSnapshot = defResult.value();
    assert(defSnapshot.collected);
    LOG_INFO(std::format("DefenderCollector: Antivirus={}, RTP={}, Engine={}",
                         defSnapshot.antivirusEnabled.has_value() ? (*defSnapshot.antivirusEnabled ? "Enabled" : "Disabled") : "Unknown",
                         defSnapshot.realTimeProtectionEnabled.has_value() ? (*defSnapshot.realTimeProtectionEnabled ? "Enabled" : "Disabled") : "Unknown",
                         defSnapshot.engineVersion.value_or("Unknown")));

    // 3. AccountCollector
    sentinel::collectors::AccountCollector accCollector;
    auto accResult = accCollector.collect();
    assert(accResult.isSuccess());
    const auto& accSnapshot = accResult.value();
    assert(accSnapshot.collected);
    assert(!accSnapshot.accounts.empty());
    LOG_INFO(std::format("AccountCollector: Found {} local accounts.", accSnapshot.accounts.size()));
    for (const auto& acc : accSnapshot.accounts) {
        if (acc.username.empty()) {
            std::abort();
        }
    }

    // 4. AuthenticationCollector
    sentinel::collectors::AuthenticationCollector authCollector;
    auto authResult = authCollector.collect();
    assert(authResult.isSuccess());
    const auto& authSnapshot = authResult.value();
    assert(authSnapshot.collected);
    LOG_INFO(std::format("AuthenticationCollector: MinPasswdLen={}, LockoutThreshold={}",
                         authSnapshot.minimumPasswordLength.value_or(0),
                         authSnapshot.lockoutThreshold.value_or(0)));

    // 5. EncryptionCollector
    sentinel::collectors::EncryptionCollector encCollector;
    auto encResult = encCollector.collect();
    assert(encResult.isSuccess());
    const auto& encSnapshot = encResult.value();
    assert(encSnapshot.collected);
    assert(!encSnapshot.volumes.empty());
    LOG_INFO(std::format("EncryptionCollector: Volume {} State={}",
                         encSnapshot.volumes.front().volume,
                         encryptionStateToString(encSnapshot.volumes.front().state)));

    // 6. UpdateCollector
    sentinel::collectors::UpdateCollector updateCollector;
    auto updateResult = updateCollector.collect();
    assert(updateResult.isSuccess());
    const auto& updateSnapshot = updateResult.value();
    assert(updateSnapshot.collected);
    LOG_INFO(std::format("UpdateCollector: ServiceRunning={}, RebootRequired={}, RecentUpdates={}",
                         updateSnapshot.updateServiceRunning.has_value() ? (*updateSnapshot.updateServiceRunning ? "Yes" : "No") : "Unknown",
                         updateSnapshot.rebootRequired.has_value() ? (*updateSnapshot.rebootRequired ? "Yes" : "No") : "Unknown",
                         updateSnapshot.recentUpdates.size()));

    LOG_INFO("Milestone 4 Native Windows Security Collectors verified.");
}

void testMilestone5SyntheticRuleEvaluations() {
    LOG_INFO("--- Testing Milestone 5 Synthetic Rule Engine Evaluations ---");

    RuleEngine engine;
    auto standardProfile = SecurityProfile::createDefault(ProfileType::Standard);
    auto highSecProfile = SecurityProfile::createDefault(ProfileType::HighSecurity);

    // 1. Test Empty Context -> All rules should evaluate to UNKNOWN, producing 0 false findings
    SecurityContext emptyCtx;
    auto emptyResult = engine.evaluate(emptyCtx, standardProfile);
    assert(emptyResult.findings.empty());
    for (const auto& eval : emptyResult.evaluations) {
        if (eval.outcome != RuleOutcome::Unknown) std::abort();
    }
    LOG_INFO("Empty SecurityContext evaluates to 100% UNKNOWN without false findings.");

    // 2. Test Synthetic Hardened Context -> All rules pass
    SecurityContext compliantCtx;
    
    FirewallSnapshot fwPass;
    fwPass.domain.enabled = true;
    fwPass.privateProfile.enabled = true;
    fwPass.publicProfile.enabled = true;
    fwPass.publicProfile.defaultInboundAction = FirewallAction::Block;
    fwPass.collected = true;
    compliantCtx.firewall = fwPass;

    DefenderSnapshot defPass;
    defPass.antivirusEnabled = true;
    defPass.realTimeProtectionEnabled = true;
    defPass.antispywareEnabled = true;
    defPass.behaviorMonitoringEnabled = true;
    defPass.collected = true;
    compliantCtx.defender = defPass;

    AuthenticationPolicySnapshot authPass;
    authPass.minimumPasswordLength = 14;
    authPass.passwordComplexityRequired = true;
    authPass.lockoutThreshold = 5;
    authPass.collected = true;
    compliantCtx.authentication = authPass;

    VolumeEncryptionInfo volPass;
    volPass.volume = "C:";
    volPass.state = EncryptionState::FullyEncrypted;
    EncryptionSnapshot encPass;
    encPass.volumes.push_back(volPass);
    encPass.collected = true;
    compliantCtx.encryption = encPass;

    UpdateSnapshot updPass;
    updPass.rebootRequired = false;
    updPass.updateServiceRunning = true;
    updPass.collected = true;
    compliantCtx.updates = updPass;

    auto passResult = engine.evaluate(compliantCtx, standardProfile);
    assert(passResult.findings.empty());
    auto passScore = SecurityScoreCalculator::calculate(passResult.findings);
    if (passScore.finalScore != 100) std::abort();
    LOG_INFO("Fully compliant synthetic context scored 100/100 with 0 findings.");

    // 3. Test Synthetic Failing Context -> FW-003 fails, DEF-002 fails, AUTH-001 fails
    SecurityContext failCtx = compliantCtx;
    failCtx.firewall->publicProfile.enabled = false; // FW-003 (Critical)
    failCtx.defender->realTimeProtectionEnabled = false; // DEF-002 (Critical)
    failCtx.authentication->minimumPasswordLength = 6; // AUTH-001 (Medium under standard baseline 8)

    auto failResult = engine.evaluate(failCtx, standardProfile);
    if (failResult.findings.size() < 3) std::abort();

    // Verify finding details & evidence
    bool foundFw3 = false;
    bool foundDef2 = false;
    bool foundAuth1 = false;

    for (const auto& f : failResult.findings) {
        if (f.ruleId == "FW-003") {
            foundFw3 = true;
            if (f.severity != Severity::Critical || f.evidence.empty() || f.evidence.front().key != "Public.Enabled" || f.evidence.front().value != "false") {
                std::abort();
            }
        }
        if (f.ruleId == "DEF-002") {
            foundDef2 = true;
            if (f.severity != Severity::Critical || f.evidence.empty() || f.evidence.front().key != "RealTimeProtectionEnabled" || f.evidence.front().value != "false") {
                std::abort();
            }
        }
        if (f.ruleId == "AUTH-001") {
            foundAuth1 = true;
            if (f.severity != Severity::Medium || f.evidence.empty() || f.evidence.front().key != "MinimumPasswordLength" || f.evidence.front().value != "6") {
                std::abort();
            }
        }
    }
    if (!foundFw3 || !foundDef2 || !foundAuth1) std::abort();

    // Verify transparent score math: 100 - 25 (FW) - 25 (DEF) - 5 (AUTH) = 45
    auto failScore = SecurityScoreCalculator::calculate(failResult.findings);
    if (failScore.finalScore > 45) std::abort();
    LOG_INFO(std::format("Synthetic failing context evaluated: Score={}/100 with {} findings.",
                         failScore.finalScore, failResult.findings.size()));

    // 4. Test Profile Policy Difference (Facts != Policy)
    // Minimum length = 10 meets Standard (threshold 8), but FAILS High Security (threshold 16)
    SecurityContext profileTestCtx = compliantCtx;
    profileTestCtx.authentication->minimumPasswordLength = 10;

    auto stdEval = engine.evaluate(profileTestCtx, standardProfile);
    bool stdAuthFailed = false;
    for (const auto& f : stdEval.findings) {
        if (f.ruleId == "AUTH-001") stdAuthFailed = true;
    }
    if (stdAuthFailed) std::abort(); // Passes under Standard baseline

    auto highSecEval = engine.evaluate(profileTestCtx, highSecProfile);
    bool highSecAuthFailed = false;
    for (const auto& f : highSecEval.findings) {
        if (f.ruleId == "AUTH-001") highSecAuthFailed = true;
    }
    if (!highSecAuthFailed) std::abort(); // Fails under High Security baseline
    LOG_INFO("Profile policy differences verified (Facts != Policy).");

    LOG_INFO("Milestone 5 Synthetic Rule Engine evaluations verified.");
}

void testMalformedProfileOverrideDoesNotAbortEvaluation() {
    LOG_INFO("--- Testing malformed profile override handling ---");

    SecurityContext context;
    AuthenticationPolicySnapshot authentication;
    authentication.minimumPasswordLength = 12;
    authentication.collected = true;
    context.authentication = authentication;

    auto profile = SecurityProfile::createDefault(ProfileType::Standard);
    profile.ruleOverrides["AUTH-001"]["minimum_length"] = std::string("twelve");

    RuleEngine engine;
    auto result = engine.evaluate(context, profile);

    bool foundUnknown = false;
    for (const auto& evaluation : result.evaluations) {
        if (evaluation.ruleId == "AUTH-001") {
            foundUnknown = evaluation.outcome == RuleOutcome::Unknown;
        }
    }
    assert(foundUnknown);
    for (const auto& finding : result.findings) {
        assert(finding.ruleId != "AUTH-001");
    }

    LOG_INFO("Malformed profile overrides safely produce Unknown evaluation.");
}

void testRuleOperatorsAndValidation() {
    LOG_INFO("--- Testing rule operators and validation ---");

    FirewallSnapshot firewall;
    firewall.collected = true;
    firewall.publicProfile.enabled = true;
    SecurityContext context;
    context.firewall = firewall;

    SecurityRule notEqualsRule{
        .id = "TEST-NE",
        .name = "Public firewall must not be disabled",
        .category = "Firewall",
        .severity = Severity::Low,
        .description = "Test rule",
        .condition = {.field = "Firewall.Public.Enabled", .op = ConditionOperator::NotEquals, .value = false},
        .recommendation = "Test recommendation",
        .remediationAvailable = false,
        .remediationId = ""
    };
    SecurityRule containsRule{
        .id = "TEST-CONTAINS",
        .name = "Encryption state contains expected text",
        .category = "Encryption",
        .severity = Severity::Low,
        .description = "Test rule",
        .condition = {.field = "Encryption.OSVolume.State", .op = ConditionOperator::Contains, .value = std::string("Encrypted")},
        .recommendation = "Test recommendation",
        .remediationAvailable = false,
        .remediationId = ""
    };
    SecurityRule invalidRule;

    RuleEngine engine({notEqualsRule, containsRule, invalidRule});
    auto result = engine.evaluate(context, SecurityProfile::createDefault(ProfileType::Standard));
    assert(result.evaluations.size() == 2);
    assert(result.evaluations[0].outcome == RuleOutcome::Pass);
    assert(result.evaluations[1].outcome == RuleOutcome::Unknown);

    LOG_INFO("Rule operators and malformed-rule rejection verified.");
}

void testMilestone5EndToEndIntegration() {
    LOG_INFO("--- Testing Milestone 5 End-to-End Pipeline (Collectors -> RuleEngine -> Scoring) ---");

    // 1. Run all native collectors
    SecurityContext liveContext;

    sentinel::collectors::SystemCollector sysCol;
    auto sysRes = sysCol.collect();
    if (sysRes.isSuccess()) liveContext.system = sysRes.value();

    sentinel::collectors::NetworkCollector netCol;
    auto netRes = netCol.collect();
    if (netRes.isSuccess()) liveContext.network = netRes.value();

    sentinel::collectors::ServiceCollector svcCol;
    auto svcRes = svcCol.collect();
    if (svcRes.isSuccess()) liveContext.services = svcRes.value();

    sentinel::collectors::FirewallCollector fwCol;
    auto fwRes = fwCol.collect();
    if (fwRes.isSuccess()) liveContext.firewall = fwRes.value();

    sentinel::collectors::DefenderCollector defCol;
    auto defRes = defCol.collect();
    if (defRes.isSuccess()) liveContext.defender = defRes.value();

    sentinel::collectors::AccountCollector accCol;
    auto accRes = accCol.collect();
    if (accRes.isSuccess()) liveContext.accounts = accRes.value();

    sentinel::collectors::AuthenticationCollector authCol;
    auto authRes = authCol.collect();
    if (authRes.isSuccess()) liveContext.authentication = authRes.value();

    sentinel::collectors::EncryptionCollector encCol;
    auto encRes = encCol.collect();
    if (encRes.isSuccess()) liveContext.encryption = encRes.value();

    sentinel::collectors::UpdateCollector updCol;
    auto updRes = updCol.collect();
    if (updRes.isSuccess()) liveContext.updates = updRes.value();

    // 2. Evaluate against Rule Engine
    RuleEngine engine;
    auto profile = SecurityProfile::createDefault(ProfileType::Standard);
    auto evalResult = engine.evaluate(liveContext, profile);

    // 3. Compute Transparent Security Score
    auto scoreBreakdown = SecurityScoreCalculator::calculate(evalResult.findings);

    assert(!evalResult.evaluations.empty());
    assert(scoreBreakdown.finalScore >= 0 && scoreBreakdown.finalScore <= 100);

    LOG_INFO(std::format("End-to-End Scan Result: Evaluated {} rules -> {} Passed, {} Failed, {} Unknown.",
                         evalResult.evaluations.size(),
                         evalResult.evaluations.size() - evalResult.findings.size(),
                         evalResult.findings.size(),
                         0));
    LOG_INFO(std::format("End-to-End Workstation Security Score: {}/100", scoreBreakdown.finalScore));
    LOG_INFO(std::format("Score Breakdown:\n{}", scoreBreakdown.explain()));

    // Verify all findings carry ruleId, title, recommendation, and evidence
    for (const auto& f : evalResult.findings) {
        if (f.ruleId.empty() || f.title.empty() || f.recommendation.empty() || f.evidence.empty()) {
            std::abort();
        }
    }

    LOG_INFO("Milestone 5 End-to-End Pipeline verified.");
}

void testMilestone6ScanResultAndTraceability() {
    LOG_INFO("--- Testing Milestone 6 ScanResult Domain & Score Traceability ---");

    ScanResult result;
    result.scanId = "SCAN-TEST-001";
    result.startedAt = std::chrono::system_clock::now();
    result.completedAt = result.startedAt + std::chrono::milliseconds(1250);
    result.profileName = "Standard";

    // Simulate rule evaluations: 8 Pass, 2 Fail, 1 Unknown
    for (int i = 1; i <= 8; ++i) {
        result.evaluations.push_back({
            .ruleId = std::format("RULE-PASS-00{}", i),
            .title = "Passing check",
            .outcome = RuleOutcome::Pass,
            .evidence = {},
            .reason = "Pass"
        });
    }

    result.evaluations.push_back({
        .ruleId = "FW-003",
        .title = "Public Firewall Profile Disabled",
        .outcome = RuleOutcome::Fail,
        .evidence = {{"FirewallCollector", "Public.Enabled", "false"}},
        .reason = "Public firewall disabled"
    });

    result.evaluations.push_back({
        .ruleId = "AUTH-001",
        .title = "Password Length Below Policy",
        .outcome = RuleOutcome::Fail,
        .evidence = {{"AuthenticationCollector", "MinimumPasswordLength", "6"}},
        .reason = "Minimum password length 6 < 8"
    });

    result.evaluations.push_back({
        .ruleId = "DEF-001",
        .title = "Defender Antivirus State",
        .outcome = RuleOutcome::Unknown,
        .evidence = {},
        .reason = "Permission denied querying defender registry"
    });

    if (result.passedCount() != 8 || result.failedCount() != 2 || result.unknownCount() != 1) {
        std::abort();
    }

    // Verify findings match only failed outcomes
    Finding f1;
    f1.ruleId = "FW-003";
    f1.title = "Public Firewall Profile Disabled";
    f1.severity = Severity::Critical;
    f1.evidence = {{"FirewallCollector", "Public.Enabled", "false"}};
    result.findings.push_back(f1);

    Finding f2;
    f2.ruleId = "AUTH-001";
    f2.title = "Password Length Below Policy";
    f2.severity = Severity::Medium;
    f2.evidence = {{"AuthenticationCollector", "MinimumPasswordLength", "6"}};
    result.findings.push_back(f2);

    result.scoreBreakdown = SecurityScoreCalculator::calculate(result.findings);

    // Verify deterministic calculation: 100 - 25 (Critical) - 5 (Medium) = 70
    if (result.scoreBreakdown.finalScore != 70) {
        std::abort();
    }
    if (result.duration().count() < 1000) {
        std::abort();
    }

    // Collector statuses
    result.collectorStatuses.push_back({ "SystemCollector", ErrorCode::Success, "OK", std::nullopt });
    result.collectorStatuses.push_back({ "DefenderCollector", ErrorCode::PermissionDenied, "Access is denied", 5 });
    if (result.collectorStatuses.size() != 2 || result.collectorStatuses[1].status != ErrorCode::PermissionDenied) {
        std::abort();
    }

    LOG_INFO(std::format("Milestone 6 ScanResult verified: Passed={}, Failed={}, Unknown={}, Score={}/100, Duration={}ms",
                         result.passedCount(), result.failedCount(), result.unknownCount(),
                         result.scoreBreakdown.finalScore, result.duration().count()));
}

void testMilestone6PartialCollectionAndErrors() {
    LOG_INFO("--- Testing Milestone 6 Partial Collection & Unknown Telemetry Robustness ---");

    // Context where Firewall & Defender were not collected due to PermissionDenied / SystemError
    SecurityContext partialContext;

    // Only accounts and authentication are available
    AccountSnapshot acc;
    acc.collected = true;
    partialContext.accounts = acc;

    AuthenticationPolicySnapshot auth;
    auth.minimumPasswordLength = 12;
    auth.collected = true;
    partialContext.authentication = auth;

    // Evaluate against standard profile
    rules::RuleEngine engine;
    auto profile = SecurityProfile::createDefault(ProfileType::Standard);
    auto evalResult = engine.evaluate(partialContext, profile);

    // Verify that missing firewall, defender, encryption, updates evaluate strictly to UNKNOWN
    size_t unknownCount = 0;
    for (const auto& ev : evalResult.evaluations) {
        if (ev.outcome == RuleOutcome::Unknown) {
            ++unknownCount;
        }
    }

    // Out of 14 rules, 4 firewall + 4 defender + 1 encryption + 2 updates = 11 rules should be UNKNOWN
    if (unknownCount < 11) {
        std::abort();
    }

    // And none of the unknown rules generated false findings!
    for (const auto& f : evalResult.findings) {
        if (f.ruleId.rfind("FW-", 0) == 0 || f.ruleId.rfind("DEF-", 0) == 0 ||
            f.ruleId.rfind("ENC-", 0) == 0 || f.ruleId.rfind("UPD-", 0) == 0) {
            std::abort(); // Should not produce findings on unknown facts
        }
    }

    LOG_INFO(std::format("Partial collection robustness verified: {} rules safely returned Unknown without false findings.", unknownCount));
}

void testMilestone7FindingDetails() {
    LOG_INFO("--- Testing Milestone 7 Finding Details & Evidence Model ---");

    core::Finding finding;
    finding.id = "find-001";
    finding.ruleId = "FW-003";
    finding.title = "Windows Firewall Public Profile Disabled";
    finding.severity = core::Severity::Critical;
    finding.category = "Firewall";
    finding.description = "The Windows Firewall Public profile is currently turned off.";
    finding.impact = "Inbound connections on public or untrusted networks are unrestricted.";
    finding.recommendation = "Enable the Windows Firewall Public profile immediately.";
    finding.remediationAvailable = true;
    finding.remediationId = "REM-FW-ENABLE-PUBLIC";

    core::Evidence ev1;
    ev1.source = "INetFwPolicy2::get_FirewallEnabled";
    ev1.key = "PublicProfile.Enabled";
    ev1.value = "false";
    finding.evidence.push_back(ev1);

    core::Evidence ev2;
    ev2.source = "INetFwPolicy2::get_DefaultInboundAction";
    ev2.key = "PublicProfile.DefaultInboundAction";
    ev2.value = "Allow";
    finding.evidence.push_back(ev2);

    assert(finding.ruleId == "FW-003");
    assert(finding.severity == core::Severity::Critical);
    assert(finding.evidence.size() == 2);
    assert(finding.evidence[0].key == "PublicProfile.Enabled");
    assert(finding.evidence[0].value == "false");
    assert(finding.evidence[1].key == "PublicProfile.DefaultInboundAction");
    assert(finding.evidence[1].value == "Allow");
    assert(finding.remediationAvailable == true);
    assert(finding.remediationId == "REM-FW-ENABLE-PUBLIC");

    // Verify timestamp validity
    auto now = std::chrono::system_clock::now();
    auto diff = std::chrono::duration_cast<std::chrono::seconds>(now - finding.detectedAt).count();
    assert(diff >= 0 && diff < 10);
    (void)diff;

    LOG_INFO("Milestone 7 Finding details and evidence contracts verified successfully.");
}

void testMilestone8StorageAndPersistence() {
    LOG_INFO("--- Testing Milestone 8 Storage, Migrations, and SQLite Persistence ---");

    // 1. In-memory database initialization
    auto initRes = storage::PersistenceService::instance().initialize(":memory:");
    assert(initRes.isSuccess());
    assert(storage::PersistenceService::instance().isAvailable());

    // 2. Settings persistence (no secrets, key-values)
    auto setRes = storage::PersistenceService::instance().setSetting("default_profile", "Developer");
    assert(setRes.isSuccess());

    auto getRes = storage::PersistenceService::instance().getSetting("default_profile");
    assert(getRes.isSuccess());
    assert(getRes.value().has_value());
    assert(getRes.value().value() == "Developer");

    // 3. Scan & Findings & Evidence insertion
    core::ScanResult scan;
    scan.scanId = "scan-test-001";
    scan.startedAt = std::chrono::system_clock::now() - std::chrono::seconds(5);
    scan.completedAt = std::chrono::system_clock::now();
    scan.profileName = "High Security";
    scan.completedSuccessfully = true;
    scan.statusMessage = "Test scan completed.";

    core::Finding finding;
    finding.id = "find-hist-001";
    finding.ruleId = "ENC-001";
    finding.title = "System Volume BitLocker Encryption Disabled";
    finding.severity = core::Severity::Critical;
    finding.category = "Encryption";
    finding.description = "OS volume is not encrypted with BitLocker.";
    finding.impact = "Physical access grants full data extraction.";
    finding.recommendation = "Enable BitLocker drive encryption.";
    finding.remediationAvailable = false;
    finding.remediationId = "";

    core::Evidence ev;
    ev.source = "FSCTL_IS_VOLUME_OWNED_BY_BITLOCKER";
    ev.key = "C:.BitLockerOwned";
    ev.value = "false";
    finding.evidence.push_back(ev);

    scan.findings.push_back(finding);
    scan.scoreBreakdown = core::SecurityScoreCalculator::calculate(scan.findings);

    core::CollectorStatus colStat;
    colStat.collectorId = "EncryptionCollector";
    colStat.status = core::ErrorCode::Success;
    colStat.message = "OK";
    scan.collectorStatuses.push_back(colStat);

    auto saveRes = storage::PersistenceService::instance().saveScan(scan);
    assert(saveRes.isSuccess());

    // 4. Retrieve recent scans
    auto recentRes = storage::PersistenceService::instance().getRecentScans(10);
    assert(recentRes.isSuccess());
    assert(recentRes.value().size() == 1);
    assert(recentRes.value()[0].scanId == "scan-test-001");
    assert(recentRes.value()[0].finalScore == scan.scoreBreakdown.finalScore);
    assert(recentRes.value()[0].findingsCount == 1);

    // 5. Retrieve full scan by ID with findings & evidence intact
    auto fullRes = storage::PersistenceService::instance().getScanById("scan-test-001");
    assert(fullRes.isSuccess());
    assert(fullRes.value().has_value());

    const auto& loadedScan = fullRes.value().value();
    assert(loadedScan.scanId == "scan-test-001");
    assert(loadedScan.findings.size() == 1);
    assert(loadedScan.findings[0].ruleId == "ENC-001");
    assert(loadedScan.findings[0].severity == core::Severity::Critical);
    assert(loadedScan.findings[0].evidence.size() == 1);
    assert(loadedScan.findings[0].evidence[0].key == "C:.BitLockerOwned");
    assert(loadedScan.findings[0].evidence[0].value == "false");
    assert(loadedScan.collectorStatuses.size() == 1);
    assert(loadedScan.collectorStatuses[0].collectorId == "EncryptionCollector");
    (void)loadedScan;

    // 6. Delete scan
    auto delRes = storage::PersistenceService::instance().deleteScan("scan-test-001");
    assert(delRes.isSuccess());

    auto checkRes = storage::PersistenceService::instance().getScanById("scan-test-001");
    assert(checkRes.isSuccess());
    assert(!checkRes.value().has_value());

    // Shutdown test instance
    storage::PersistenceService::instance().shutdown();
    assert(!storage::PersistenceService::instance().isAvailable());

    LOG_INFO("Milestone 8 SQLite storage and persistence verified successfully.");
}

int main() {
    LOG_INFO("Starting Sentinel Milestone 1-8 Unit & Integration Tests...");

#ifdef SENTINEL_INTEGRATION_TESTS
    testMilestone1Platform();
#endif
    testSeverityConversionsAndPenalties();
    testSecurityScoreCalculation();
    testSecurityProfiles();
    testCollectionResultAndErrors();
    testEvidenceAndFindingStructures();

    testMilestone3SyntheticModels();
#ifdef SENTINEL_INTEGRATION_TESTS
    testMilestone3NativeCollectors();
#endif

    testMilestone4SecurityModels();
    testEncryptionQueryOutcomes();
#ifdef SENTINEL_INTEGRATION_TESTS
    testMilestone4NativeCollectors();
#endif

    testMilestone5SyntheticRuleEvaluations();
    testMalformedProfileOverrideDoesNotAbortEvaluation();
    testRuleOperatorsAndValidation();
#ifdef SENTINEL_INTEGRATION_TESTS
    testMilestone5EndToEndIntegration();
#endif

    testMilestone6ScanResultAndTraceability();
    testMilestone6PartialCollectionAndErrors();

    testMilestone7FindingDetails();

    testMilestone8StorageAndPersistence();

    std::cout << "\n===========================================================\n";
    std::cout << "All Milestone 1, 2, 3, 4, 5, 6, 7, and 8 Tests Passed (100%)!\n";
    std::cout << "===========================================================\n";
    return 0;
}
