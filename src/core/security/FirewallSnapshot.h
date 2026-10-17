#pragma once

#include <string_view>

namespace sentinel::core {

enum class FirewallAction {
    Block,
    Allow,
    Unknown
};

[[nodiscard]] constexpr std::string_view firewallActionToString(FirewallAction action) noexcept {
    switch (action) {
        case FirewallAction::Block:   return "Block";
        case FirewallAction::Allow:   return "Allow";
        case FirewallAction::Unknown: return "Unknown";
    }
    return "Unknown";
}

struct FirewallProfileSnapshot {
    bool enabled{false};
    FirewallAction defaultInboundAction{FirewallAction::Unknown};
    FirewallAction defaultOutboundAction{FirewallAction::Unknown};
    bool notificationsEnabled{false};
};

struct FirewallSnapshot {
    FirewallProfileSnapshot domain;
    FirewallProfileSnapshot privateProfile;
    FirewallProfileSnapshot publicProfile;

    bool collected{false};
};

} // namespace sentinel::core
