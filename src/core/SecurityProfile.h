#pragma once

#include "SecurityRule.h"
#include <string>
#include <unordered_map>
#include <string_view>

namespace sentinel::core {

enum class ProfileType {
    Standard,
    Developer,
    HighSecurity,
    Custom
};

[[nodiscard]] constexpr std::string_view profileTypeToString(ProfileType type) noexcept {
    switch (type) {
        case ProfileType::Standard:     return "Standard";
        case ProfileType::Developer:    return "Developer";
        case ProfileType::HighSecurity: return "High Security";
        case ProfileType::Custom:       return "Custom";
    }
    return "Custom";
}

[[nodiscard]] inline ProfileType profileTypeFromString(std::string_view str) noexcept {
    if (str == "Standard" || str == "standard") return ProfileType::Standard;
    if (str == "Developer" || str == "developer") return ProfileType::Developer;
    if (str == "High Security" || str == "high-security" || str == "high_security") return ProfileType::HighSecurity;
    return ProfileType::Custom;
}

struct SecurityProfile {
    std::string name;
    ProfileType type{ProfileType::Standard};
    std::string description;
    
    // Per-rule parameter overrides: ruleId -> (parameter name -> value)
    std::unordered_map<std::string, std::unordered_map<std::string, RuleValue>> ruleOverrides;

    static SecurityProfile createDefault(ProfileType type) {
        SecurityProfile p;
        p.type = type;
        p.name = std::string(profileTypeToString(type));

        switch (type) {
            case ProfileType::Standard:
                p.description = "Balanced security baseline suitable for standard business workstations.";
                p.ruleOverrides["AUTH-001"]["minimum_length"] = static_cast<int64_t>(8);
                p.ruleOverrides["FIREWALL-001"]["required"] = true;
                break;
            case ProfileType::Developer:
                p.description = "Permits development services with local binding checks and standard protections.";
                p.ruleOverrides["AUTH-001"]["minimum_length"] = static_cast<int64_t>(10);
                p.ruleOverrides["FIREWALL-001"]["required"] = true;
                break;
            case ProfileType::HighSecurity:
                p.description = "Strict security baseline for mission-critical and compliance-bound systems.";
                p.ruleOverrides["AUTH-001"]["minimum_length"] = static_cast<int64_t>(16);
                p.ruleOverrides["FIREWALL-001"]["required"] = true;
                p.ruleOverrides["BITLOCKER-001"]["required"] = true;
                break;
            case ProfileType::Custom:
                p.description = "User-customized security profile parameters.";
                break;
        }

        return p;
    }
};

} // namespace sentinel::core
