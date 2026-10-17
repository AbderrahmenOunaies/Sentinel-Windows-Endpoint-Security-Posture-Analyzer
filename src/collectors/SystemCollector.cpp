#include "SystemCollector.h"
#include "core/Logger.h"
#include "platform/windows/StringEncoding.h"

#ifdef _WIN32
#include <windows.h>
#include <sysinfoapi.h>
#endif

namespace sentinel::collectors {

core::CollectionResult<core::SystemSnapshot> SystemCollector::collect() {
    LOG_INFO("SystemCollector started.");

#ifdef _WIN32
    core::SystemSnapshot snapshot;

    // Computer name
    wchar_t computerBuf[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD computerLen = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(computerBuf, &computerLen)) {
        snapshot.computerName = platform::wideToUtf8(computerBuf);
    } else {
        snapshot.computerName = "UnknownHost";
    }

    // System info
    SYSTEM_INFO sysInfo{};
    GetNativeSystemInfo(&sysInfo);

    snapshot.processorCount = sysInfo.dwNumberOfProcessors;
    snapshot.pageSize = sysInfo.dwPageSize;

    switch (sysInfo.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            snapshot.architecture = "x64";
            break;
        case PROCESSOR_ARCHITECTURE_ARM64:
            snapshot.architecture = "ARM64";
            break;
        case PROCESSOR_ARCHITECTURE_INTEL:
            snapshot.architecture = "x86";
            break;
        case PROCESSOR_ARCHITECTURE_ARM:
            snapshot.architecture = "ARM";
            break;
        default:
            snapshot.architecture = "Unknown";
            break;
    }

    // Physical Memory
    MEMORYSTATUSEX memStatus{};
    memStatus.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memStatus)) {
        snapshot.physicalMemoryBytes = memStatus.ullTotalPhys;
    }

    // Windows Directory
    wchar_t sysDirBuf[MAX_PATH] = {0};
    UINT sysDirLen = GetSystemDirectoryW(sysDirBuf, MAX_PATH);
    if (sysDirLen > 0 && sysDirLen < MAX_PATH) {
        snapshot.systemDirectory = platform::wideToUtf8(sysDirBuf);
    }

    // OS Identification
    snapshot.operatingSystem = "Microsoft Windows";
    snapshot.osVersion = "10/11";
    snapshot.osBuild = "NT 10.0";

    LOG_INFO("SystemCollector completed successfully.");
    return core::CollectionResult<core::SystemSnapshot>(std::move(snapshot));
#else
    LOG_ERROR("SystemCollector unsupported on non-Windows platform.");
    return core::CollectionResult<core::SystemSnapshot>(core::ErrorCode::NotSupported, "Non-Windows platform not supported");
#endif
}

} // namespace sentinel::collectors
