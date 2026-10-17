#include "DefaultRules.h"

namespace sentinel::rules {

std::vector<core::SecurityRule> DefaultRules::createInitialRuleSet() {
    std::vector<core::SecurityRule> rules;

    // FW-001: Domain Firewall Enabled
    rules.push_back({
        .id = "FW-001",
        .name = "Domain Firewall Enabled",
        .category = "Firewall",
        .severity = core::Severity::High,
        .description = "Windows Firewall Domain network profile is turned off.",
        .condition = {
            .field = "Firewall.Domain.Enabled",
            .op = core::ConditionOperator::Equals,
            .value = true
        },
        .recommendation = "Enable the Windows Firewall for the Domain profile.",
        .remediationAvailable = false,
        .remediationId = "REMED-FW-001"
    });

    // FW-002: Private Firewall Enabled
    rules.push_back({
        .id = "FW-002",
        .name = "Private Firewall Enabled",
        .category = "Firewall",
        .severity = core::Severity::High,
        .description = "Windows Firewall Private network profile is turned off.",
        .condition = {
            .field = "Firewall.Private.Enabled",
            .op = core::ConditionOperator::Equals,
            .value = true
        },
        .recommendation = "Enable the Windows Firewall for the Private profile.",
        .remediationAvailable = false,
        .remediationId = "REMED-FW-002"
    });

    // FW-003: Public Firewall Enabled
    rules.push_back({
        .id = "FW-003",
        .name = "Public Firewall Enabled",
        .category = "Firewall",
        .severity = core::Severity::Critical,
        .description = "Windows Firewall Public network profile is turned off, leaving the workstation exposed on untrusted networks.",
        .condition = {
            .field = "Firewall.Public.Enabled",
            .op = core::ConditionOperator::Equals,
            .value = true
        },
        .recommendation = "Immediately enable the Windows Firewall for the Public profile.",
        .remediationAvailable = false,
        .remediationId = "REMED-FW-003"
    });

    // FW-004: Public Inbound Default Action
    rules.push_back({
        .id = "FW-004",
        .name = "Public Inbound Default Action Block",
        .category = "Firewall",
        .severity = core::Severity::High,
        .description = "The default inbound action for the Public firewall profile allows connections by default.",
        .condition = {
            .field = "Firewall.Public.DefaultInboundAction",
            .op = core::ConditionOperator::Equals,
            .value = std::string("Block")
        },
        .recommendation = "Set the default inbound action for Public network profile to Block.",
        .remediationAvailable = false,
        .remediationId = "REMED-FW-004"
    });

    // DEF-001: Antivirus Protection Enabled
    rules.push_back({
        .id = "DEF-001",
        .name = "Antivirus Protection Enabled",
        .category = "Endpoint Protection",
        .severity = core::Severity::Critical,
        .description = "Microsoft Defender Antivirus protection is reported as disabled or turned off.",
        .condition = {
            .field = "Defender.AntivirusEnabled",
            .op = core::ConditionOperator::Equals,
            .value = true
        },
        .recommendation = "Enable Microsoft Defender Antivirus or verify that third-party AV is registered.",
        .remediationAvailable = false,
        .remediationId = "REMED-DEF-001"
    });

    // DEF-002: Real-Time Protection Enabled
    rules.push_back({
        .id = "DEF-002",
        .name = "Real-Time Protection Enabled",
        .category = "Endpoint Protection",
        .severity = core::Severity::Critical,
        .description = "Microsoft Defender Real-Time Protection is disabled, preventing on-access malware detection.",
        .condition = {
            .field = "Defender.RealTimeProtectionEnabled",
            .op = core::ConditionOperator::Equals,
            .value = true
        },
        .recommendation = "Turn on Real-Time Protection in Windows Security.",
        .remediationAvailable = false,
        .remediationId = "REMED-DEF-002"
    });

    // DEF-003: Antispyware Enabled
    rules.push_back({
        .id = "DEF-003",
        .name = "Antispyware Protection Enabled",
        .category = "Endpoint Protection",
        .severity = core::Severity::High,
        .description = "Microsoft Defender Antispyware protection is disabled.",
        .condition = {
            .field = "Defender.AntispywareEnabled",
            .op = core::ConditionOperator::Equals,
            .value = true
        },
        .recommendation = "Enable Antispyware protection in Defender configuration.",
        .remediationAvailable = false,
        .remediationId = "REMED-DEF-003"
    });

    // DEF-004: Behavior Monitoring Enabled
    rules.push_back({
        .id = "DEF-004",
        .name = "Behavior Monitoring Enabled",
        .category = "Endpoint Protection",
        .severity = core::Severity::Medium,
        .description = "Microsoft Defender Behavior Monitoring is disabled, reducing detection of suspicious process activity.",
        .condition = {
            .field = "Defender.BehaviorMonitoringEnabled",
            .op = core::ConditionOperator::Equals,
            .value = true
        },
        .recommendation = "Enable Behavior Monitoring in Defender configuration.",
        .remediationAvailable = false,
        .remediationId = "REMED-DEF-004"
    });

    // AUTH-001: Minimum Password Length
    rules.push_back({
        .id = "AUTH-001",
        .name = "Minimum Password Length",
        .category = "Authentication",
        .severity = core::Severity::Medium,
        .description = "Configured minimum password length does not meet the selected profile baseline.",
        .condition = {
            .field = "Authentication.MinimumPasswordLength",
            .op = core::ConditionOperator::GreaterThanOrEqual,
            .value = static_cast<int64_t>(8)
        },
        .recommendation = "Increase the minimum password length policy using secpol.msc or Group Policy.",
        .remediationAvailable = false,
        .remediationId = "REMED-AUTH-001"
    });

    // AUTH-002: Password Complexity
    rules.push_back({
        .id = "AUTH-002",
        .name = "Password Complexity Required",
        .category = "Authentication",
        .severity = core::Severity::Medium,
        .description = "Password complexity enforcement is disabled on this workstation.",
        .condition = {
            .field = "Authentication.PasswordComplexityRequired",
            .op = core::ConditionOperator::Equals,
            .value = true
        },
        .recommendation = "Enable 'Password must meet complexity requirements' in local security policy.",
        .remediationAvailable = false,
        .remediationId = "REMED-AUTH-002"
    });

    // AUTH-003: Account Lockout Threshold
    rules.push_back({
        .id = "AUTH-003",
        .name = "Account Lockout Threshold Configured",
        .category = "Authentication",
        .severity = core::Severity::High,
        .description = "Account lockout threshold is not configured (set to 0), permitting unlimited brute-force logon attempts.",
        .condition = {
            .field = "Authentication.LockoutThreshold",
            .op = core::ConditionOperator::GreaterThan,
            .value = static_cast<int64_t>(0)
        },
        .recommendation = "Configure an Account Lockout Threshold (recommended: 5-10 invalid logon attempts).",
        .remediationAvailable = false,
        .remediationId = "REMED-AUTH-003"
    });

    // ENC-001: OS Volume Encryption
    rules.push_back({
        .id = "ENC-001",
        .name = "System Volume BitLocker Encryption",
        .category = "Encryption",
        .severity = core::Severity::High,
        .description = "Operating system drive (C:) is not fully encrypted with BitLocker.",
        .condition = {
            .field = "Encryption.OSVolume.State",
            .op = core::ConditionOperator::Equals,
            .value = std::string("FullyEncrypted")
        },
        .recommendation = "Enable BitLocker drive encryption on system volume C:.",
        .remediationAvailable = false,
        .remediationId = "REMED-ENC-001"
    });

    // UPD-001: Reboot Required for Updates
    rules.push_back({
        .id = "UPD-001",
        .name = "System Pending Reboot",
        .category = "Updates",
        .severity = core::Severity::Medium,
        .description = "Windows indicates a pending restart is required to complete installed system updates.",
        .condition = {
            .field = "Updates.RebootRequired",
            .op = core::ConditionOperator::Equals,
            .value = false
        },
        .recommendation = "Restart workstation to apply pending updates and security fixes.",
        .remediationAvailable = false,
        .remediationId = "REMED-UPD-001"
    });

    // UPD-002: Windows Update Service State
    rules.push_back({
        .id = "UPD-002",
        .name = "Windows Update Service Running",
        .category = "Updates",
        .severity = core::Severity::Low,
        .description = "Windows Update service (wuauserv) is stopped, which may delay receiving critical security patches.",
        .condition = {
            .field = "Updates.ServiceRunning",
            .op = core::ConditionOperator::Equals,
            .value = true
        },
        .recommendation = "Ensure Windows Update service startup type is configured to Automatic or Manual (Triggered).",
        .remediationAvailable = false,
        .remediationId = "REMED-UPD-002"
    });

    return rules;
}

} // namespace sentinel::rules
