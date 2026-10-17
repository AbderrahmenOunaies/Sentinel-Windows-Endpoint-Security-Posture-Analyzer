#include "EncryptionCollector.h"
#include "core/Logger.h"
#include "platform/windows/WinRaii.h"

#ifdef _WIN32
#include <windows.h>
#include <winioctl.h>
#endif

#include <format>

namespace sentinel::collectors {

core::CollectionResult<core::EncryptionSnapshot> EncryptionCollector::collect() {
    LOG_INFO("EncryptionCollector started.");

#ifdef _WIN32
    core::EncryptionSnapshot snapshot;

    // Check system drive (typically C:)
    core::VolumeEncryptionInfo sysVol;
    sysVol.volume = "C:";

    // Query volume protection using GetVolumeInformationW for basic flags
    DWORD fsFlags = 0;
    wchar_t fsName[MAX_PATH] = {0};
    if (GetVolumeInformationW(L"C:\\", nullptr, 0, nullptr, nullptr, &fsFlags, fsName, MAX_PATH)) {
        if (fsFlags & FILE_VOLUME_IS_COMPRESSED) {
            sysVol.encryptionMethod = "NTFS Compression";
        }
    }

    // Inspect BitLocker device handle using native DeviceIoControl (read-only)
    platform::UniqueHandle hVolume(CreateFileW(
        L"\\\\.\\C:",
        0, // Query access only (accessible without administrator elevation)
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr
    ));

    if (hVolume.isValid()) {
        // Query BitLocker IOCTL: FSCTL_IS_VOLUME_ENCRYPTED / FSCTL_IS_VOLUME_OWNED_BY_BITLOCKER
        #ifndef FSCTL_IS_VOLUME_OWNED_BY_BITLOCKER
        #define FSCTL_IS_VOLUME_OWNED_BY_BITLOCKER CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 222, METHOD_BUFFERED, FILE_ANY_ACCESS)
        #endif

        DWORD bytesReturned = 0;
        BOOL isBitLocker = DeviceIoControl(
            hVolume.get(),
            FSCTL_IS_VOLUME_OWNED_BY_BITLOCKER,
            nullptr,
            0,
            nullptr,
            0,
            &bytesReturned,
            nullptr
        );

        if (isBitLocker) {
            sysVol.state = core::EncryptionState::FullyEncrypted;
            sysVol.protectionEnabled = true;
            sysVol.encryptionPercentage = 100;
            sysVol.encryptionMethod = "XTS-AES";
        } else {
            DWORD err = GetLastError();
            if (err == ERROR_ACCESS_DENIED) {
                sysVol.state = core::EncryptionState::Unknown;
            } else {
                sysVol.state = core::EncryptionState::NotEncrypted;
                sysVol.protectionEnabled = false;
            }
        }
    } else {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            LOG_WARNING("EncryptionCollector: Access denied opening volume handle for C:. Marking state as Unknown.");
            sysVol.state = core::EncryptionState::Unknown;
        } else {
            sysVol.state = core::EncryptionState::NotEncrypted;
        }
    }

    snapshot.volumes.push_back(std::move(sysVol));
    snapshot.collected = true;

    LOG_INFO(std::format("EncryptionCollector completed: Volume C: State={}",
                         core::encryptionStateToString(snapshot.volumes.front().state)));

    return core::CollectionResult<core::EncryptionSnapshot>(std::move(snapshot));
#else
    LOG_ERROR("EncryptionCollector unsupported on non-Windows platform.");
    return core::CollectionResult<core::EncryptionSnapshot>(core::ErrorCode::NotSupported, "Non-Windows platform not supported");
#endif
}

} // namespace sentinel::collectors
