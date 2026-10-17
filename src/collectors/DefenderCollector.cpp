#include "DefenderCollector.h"
#include "core/Logger.h"
#include "platform/windows/WinRaii.h"
#include "platform/windows/StringEncoding.h"

#ifdef _WIN32
#include <windows.h>
#endif

#include <format>

namespace sentinel::collectors {

core::CollectionResult<core::DefenderSnapshot> DefenderCollector::collect() {
    LOG_INFO("DefenderCollector started.");

#ifdef _WIN32
    core::DefenderSnapshot snapshot;

    // Inspect Windows Defender registry configuration (read-only)
    // Primary path: SOFTWARE\Microsoft\Windows Defender
    // Real-Time Protection path: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
    platform::UniqueHKey hRtpKey;
    LSTATUS status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
        0,
        KEY_READ,
        hRtpKey.addressof()
    );

    if (status == ERROR_SUCCESS) {
        DWORD disableRtp = 0;
        DWORD valueType = 0;
        DWORD dwSize = sizeof(disableRtp);
        if (RegQueryValueExW(hRtpKey.get(), L"DisableRealtimeMonitoring", nullptr, &valueType, reinterpret_cast<LPBYTE>(&disableRtp), &dwSize) == ERROR_SUCCESS &&
            valueType == REG_DWORD && dwSize == sizeof(disableRtp)) {
            snapshot.realTimeProtectionEnabled = (disableRtp == 0);
        }

        DWORD disableBm = 0;
        dwSize = sizeof(disableBm);
        if (RegQueryValueExW(hRtpKey.get(), L"DisableBehaviorMonitoring", nullptr, &valueType, reinterpret_cast<LPBYTE>(&disableBm), &dwSize) == ERROR_SUCCESS &&
            valueType == REG_DWORD && dwSize == sizeof(disableBm)) {
            snapshot.behaviorMonitoringEnabled = (disableBm == 0);
        }

        DWORD disableIoav = 0;
        dwSize = sizeof(disableIoav);
        if (RegQueryValueExW(hRtpKey.get(), L"DisableIOAVProtection", nullptr, &valueType, reinterpret_cast<LPBYTE>(&disableIoav), &dwSize) == ERROR_SUCCESS &&
            valueType == REG_DWORD && dwSize == sizeof(disableIoav)) {
            snapshot.ioavProtectionEnabled = (disableIoav == 0);
        }
    } else if (status == ERROR_ACCESS_DENIED) {
        LOG_WARNING("DefenderCollector: Read permission denied on Windows Defender registry keys (Tamper Protection may restrict read/write).");
    }

    // Inspect general Defender status key
    platform::UniqueHKey hDefKey;
    status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows Defender",
        0,
        KEY_READ,
        hDefKey.addressof()
    );

    if (status == ERROR_SUCCESS) {
        DWORD disableAv = 0;
        DWORD valueType = 0;
        DWORD dwSize = sizeof(disableAv);
        if (RegQueryValueExW(hDefKey.get(), L"DisableAntiVirus", nullptr, &valueType, reinterpret_cast<LPBYTE>(&disableAv), &dwSize) == ERROR_SUCCESS &&
            valueType == REG_DWORD && dwSize == sizeof(disableAv)) {
            snapshot.antivirusEnabled = (disableAv == 0);
        }

        DWORD disableAs = 0;
        dwSize = sizeof(disableAs);
        if (RegQueryValueExW(hDefKey.get(), L"DisableAntiSpyware", nullptr, &valueType, reinterpret_cast<LPBYTE>(&disableAs), &dwSize) == ERROR_SUCCESS &&
            valueType == REG_DWORD && dwSize == sizeof(disableAs)) {
            snapshot.antispywareEnabled = (disableAs == 0);
        }
    }

    // Inspect Signature Version from Signature Updates key
    platform::UniqueHKey hSigKey;
    status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates",
        0,
        KEY_READ,
        hSigKey.addressof()
    );

    if (status == ERROR_SUCCESS) {
        wchar_t sigBuf[256] = {0};
        DWORD bufSize = sizeof(sigBuf);
        if (RegQueryValueExW(hSigKey.get(), L"AVSignatureVersion", nullptr, nullptr, reinterpret_cast<LPBYTE>(sigBuf), &bufSize) == ERROR_SUCCESS) {
            snapshot.antivirusSignatureVersion = platform::wideToUtf8(sigBuf);
        }
        bufSize = sizeof(sigBuf);
        if (RegQueryValueExW(hSigKey.get(), L"ASSignatureVersion", nullptr, nullptr, reinterpret_cast<LPBYTE>(sigBuf), &bufSize) == ERROR_SUCCESS) {
            snapshot.antispywareSignatureVersion = platform::wideToUtf8(sigBuf);
        }
        bufSize = sizeof(sigBuf);
        if (RegQueryValueExW(hSigKey.get(), L"EngineVersion", nullptr, nullptr, reinterpret_cast<LPBYTE>(sigBuf), &bufSize) == ERROR_SUCCESS) {
            snapshot.engineVersion = platform::wideToUtf8(sigBuf);
        }
    }

    snapshot.collected = true;
    LOG_INFO(std::format("DefenderCollector completed: Antivirus={}, RTP={}, EngineVersion={}",
                         snapshot.antivirusEnabled.has_value() ? (*snapshot.antivirusEnabled ? "Enabled" : "Disabled") : "Unknown",
                         snapshot.realTimeProtectionEnabled.has_value() ? (*snapshot.realTimeProtectionEnabled ? "Enabled" : "Disabled") : "Unknown",
                         snapshot.engineVersion.value_or("Unknown")));

    return core::CollectionResult<core::DefenderSnapshot>(std::move(snapshot));
#else
    LOG_ERROR("DefenderCollector unsupported on non-Windows platform.");
    return core::CollectionResult<core::DefenderSnapshot>(core::ErrorCode::NotSupported, "Non-Windows platform not supported");
#endif
}

} // namespace sentinel::collectors
