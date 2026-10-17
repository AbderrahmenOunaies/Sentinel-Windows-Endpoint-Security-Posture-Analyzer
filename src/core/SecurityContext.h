#pragma once

#include "collection/SystemSnapshot.h"
#include "collection/NetworkSnapshot.h"
#include "collection/ServiceSnapshot.h"
#include "security/FirewallSnapshot.h"
#include "security/DefenderSnapshot.h"
#include "security/AccountSnapshot.h"
#include "security/AuthenticationSnapshot.h"
#include "security/EncryptionSnapshot.h"
#include "security/UpdateSnapshot.h"

#include <optional>

namespace sentinel::core {

struct SecurityContext {
    std::optional<SystemSnapshot> system;
    std::optional<NetworkSnapshot> network;
    std::optional<ServiceSnapshot> services;

    std::optional<FirewallSnapshot> firewall;
    std::optional<DefenderSnapshot> defender;
    std::optional<AccountSnapshot> accounts;
    std::optional<AuthenticationPolicySnapshot> authentication;
    std::optional<EncryptionSnapshot> encryption;
    std::optional<UpdateSnapshot> updates;
};

} // namespace sentinel::core
