#include "FirewallCollector.h"
#include "core/Logger.h"
#include "platform/windows/WinRaii.h"

#ifdef _WIN32
#include <windows.h>
#include <netfw.h>
#endif

#include <format>

namespace sentinel::collectors {

core::CollectionResult<core::FirewallSnapshot> FirewallCollector::collect() {
    LOG_INFO("FirewallCollector started.");

#ifdef _WIN32
    platform::ScopedCoInitialize scopedCom;

    INetFwPolicy2* pNetFwPolicy2 = nullptr;
    HRESULT hr = CoCreateInstance(
        __uuidof(NetFwPolicy2),
        nullptr,
        CLSCTX_INPROC_SERVER,
        __uuidof(INetFwPolicy2),
        reinterpret_cast<void**>(&pNetFwPolicy2)
    );

    if (FAILED(hr) || pNetFwPolicy2 == nullptr) {
        LOG_WARNING(std::format("FirewallCollector: Failed to instantiate NetFwPolicy2 COM interface. HRESULT: 0x{:08X}", static_cast<unsigned long>(hr)));
        return core::CollectionResult<core::FirewallSnapshot>(
            core::ErrorCode::SystemError,
            std::format("Failed to access Windows Firewall COM interface (HRESULT: 0x{:08X})", static_cast<unsigned long>(hr))
        );
    }

    core::FirewallSnapshot snapshot;

    auto collectProfile = [pNetFwPolicy2](NET_FW_PROFILE_TYPE2_ profileType, core::FirewallProfileSnapshot& profile) {
        VARIANT_BOOL bEnabled = VARIANT_FALSE;
        if (SUCCEEDED(pNetFwPolicy2->get_FirewallEnabled(profileType, &bEnabled))) {
            profile.enabled = (bEnabled == VARIANT_TRUE);
        }

        NET_FW_ACTION action;
        if (SUCCEEDED(pNetFwPolicy2->get_DefaultInboundAction(profileType, &action))) {
            profile.defaultInboundAction = (action == NET_FW_ACTION_BLOCK) ? core::FirewallAction::Block : core::FirewallAction::Allow;
        }

        if (SUCCEEDED(pNetFwPolicy2->get_DefaultOutboundAction(profileType, &action))) {
            profile.defaultOutboundAction = (action == NET_FW_ACTION_BLOCK) ? core::FirewallAction::Block : core::FirewallAction::Allow;
        }

        VARIANT_BOOL bNotif = VARIANT_FALSE;
        if (SUCCEEDED(pNetFwPolicy2->get_NotificationsDisabled(profileType, &bNotif))) {
            profile.notificationsEnabled = (bNotif == VARIANT_FALSE);
        }
    };

    collectProfile(NET_FW_PROFILE2_DOMAIN, snapshot.domain);
    collectProfile(NET_FW_PROFILE2_PRIVATE, snapshot.privateProfile);
    collectProfile(NET_FW_PROFILE2_PUBLIC, snapshot.publicProfile);

    pNetFwPolicy2->Release();
    snapshot.collected = true;

    LOG_INFO(std::format("FirewallCollector completed: Domain={}, Private={}, Public={}",
                         snapshot.domain.enabled ? "Enabled" : "Disabled",
                         snapshot.privateProfile.enabled ? "Enabled" : "Disabled",
                         snapshot.publicProfile.enabled ? "Enabled" : "Disabled"));

    return core::CollectionResult<core::FirewallSnapshot>(std::move(snapshot));
#else
    LOG_ERROR("FirewallCollector unsupported on non-Windows platform.");
    return core::CollectionResult<core::FirewallSnapshot>(core::ErrorCode::NotSupported, "Non-Windows platform not supported");
#endif
}

} // namespace sentinel::collectors
