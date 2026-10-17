#include "UpdateCollector.h"
#include "core/Logger.h"
#include "platform/windows/WinRaii.h"
#include "platform/windows/StringEncoding.h"

#ifdef _WIN32
#include <windows.h>
#include <winsvc.h>
#endif

#include <format>

namespace sentinel::collectors {

core::CollectionResult<core::UpdateSnapshot> UpdateCollector::collect() {
    LOG_INFO("UpdateCollector started.");

#ifdef _WIN32
    core::UpdateSnapshot snapshot;

    // 1. Inspect Windows Update Service (wuauserv) state
    platform::UniqueServiceHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (scm.isValid()) {
        platform::UniqueServiceHandle svc(OpenServiceW(scm.get(), L"wuauserv", SERVICE_QUERY_STATUS));
        if (svc.isValid()) {
            SERVICE_STATUS_PROCESS status{};
            DWORD bytesNeeded = 0;
            if (QueryServiceStatusEx(svc.get(), SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytesNeeded)) {
                snapshot.updateServiceRunning = (status.dwCurrentState == SERVICE_RUNNING);
            }
        }
    }

    // 2. Check if reboot is pending (RebootRequired keys)
    // Primary key: SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired
    platform::UniqueHKey hRebootKey;
    LSTATUS status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired",
        0,
        KEY_READ,
        hRebootKey.addressof()
    );
    snapshot.rebootRequired = (status == ERROR_SUCCESS);

    // Also check Component Based Servicing reboot flag
    if (!(*snapshot.rebootRequired)) {
        platform::UniqueHKey hCbsKey;
        status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending",
            0,
            KEY_READ,
            hCbsKey.addressof()
        );
        if (status == ERROR_SUCCESS) {
            snapshot.rebootRequired = true;
        }
    }

    // 3. Inspect installed updates / hotfixes from CBS packages registry
    // Path: SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages
    platform::UniqueHKey hPackagesKey;
    status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages",
        0,
        KEY_READ,
        hPackagesKey.addressof()
    );

    if (status == ERROR_SUCCESS) {
        wchar_t subKeyName[256] = {0};
        DWORD subKeyLen = 256;
        DWORD index = 0;

        while (RegEnumKeyExW(hPackagesKey.get(), index, subKeyName, &subKeyLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            std::string pkgName = platform::wideToUtf8(subKeyName);
            // Look for package entries containing "Package_for_KB" or "Package_for_RollupFix"
            if (pkgName.find("Package_for_KB") != std::string::npos || pkgName.find("RollupFix") != std::string::npos) {
                core::UpdateInfo update;
                update.identifier = pkgName;
                update.title = pkgName;
                update.succeeded = true;
                snapshot.recentUpdates.push_back(std::move(update));
                if (snapshot.recentUpdates.size() >= 25) {
                    break; // Cap recent updates for efficiency
                }
            }
            subKeyLen = 256;
            index++;
        }
    }

    if (!snapshot.recentUpdates.empty()) {
        snapshot.latestInstalledUpdate = std::chrono::system_clock::now();
    }

    snapshot.collected = true;
    LOG_INFO(std::format("UpdateCollector completed: ServiceRunning={}, RebootRequired={}, RecentUpdates={}",
                         snapshot.updateServiceRunning.has_value() ? (*snapshot.updateServiceRunning ? "Yes" : "No") : "Unknown",
                         snapshot.rebootRequired.has_value() ? (*snapshot.rebootRequired ? "Yes" : "No") : "Unknown",
                         snapshot.recentUpdates.size()));

    return core::CollectionResult<core::UpdateSnapshot>(std::move(snapshot));
#else
    LOG_ERROR("UpdateCollector unsupported on non-Windows platform.");
    return core::CollectionResult<core::UpdateSnapshot>(core::ErrorCode::NotSupported, "Non-Windows platform not supported");
#endif
}

} // namespace sentinel::collectors
