#include "EncryptionCollector.h"
#include "core/Logger.h"
#include "platform/windows/WinRaii.h"

#ifdef _WIN32
#include <windows.h>
#include <winioctl.h>
#endif

#include <format>
#include <system_error>

namespace sentinel::collectors {

EncryptionCollector::EncryptionCollector(Query query)
    : m_query(std::move(query)) {}

core::CollectionResult<core::EncryptionSnapshot> EncryptionCollector::collect() {
    LOG_INFO("EncryptionCollector started.");

#ifdef _WIN32
    core::EncryptionSnapshot snapshot;

    core::VolumeEncryptionInfo sysVol;
    sysVol.volume = "C:";

    const QueryResult queryResult = m_query ? m_query() : querySystemVolume();
    switch (queryResult.status) {
        case QueryStatus::Encrypted:
            sysVol.state = core::EncryptionState::FullyEncrypted;
            break;
        case QueryStatus::NotEncrypted:
            sysVol.state = core::EncryptionState::NotEncrypted;
            break;
        case QueryStatus::AccessDenied:
        case QueryStatus::NotSupported:
        case QueryStatus::Unavailable:
        case QueryStatus::Error:
            sysVol.state = core::EncryptionState::Unknown;
            break;
    }
    sysVol.encryptionPercentage = queryResult.encryptionPercentage;
    sysVol.encryptionMethod = queryResult.encryptionMethod;
    sysVol.protectionEnabled = queryResult.protectionEnabled;
    if (!queryResult.diagnostic.empty()) {
        LOG_WARNING("EncryptionCollector: " + queryResult.diagnostic);
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

EncryptionCollector::QueryResult EncryptionCollector::querySystemVolume() {
#ifdef _WIN32
    platform::UniqueHandle hVolume(CreateFileW(
        L"\\\\.\\C:",
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr
    ));

    if (!hVolume.isValid()) {
        const DWORD error = GetLastError();
        if (error == ERROR_ACCESS_DENIED) return {QueryStatus::AccessDenied, {}, {}, {}, "Access denied opening the system volume."};
        if (error == ERROR_INVALID_FUNCTION || error == ERROR_NOT_SUPPORTED) return {QueryStatus::NotSupported, {}, {}, {}, "The system volume query is not supported."};
        return {QueryStatus::Error, {}, {}, {}, std::format("Unable to open the system volume (error {}).", error)};
    }

#ifndef FSCTL_IS_VOLUME_OWNED_BY_BITLOCKER
#define FSCTL_IS_VOLUME_OWNED_BY_BITLOCKER CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 222, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
    DWORD bytesReturned = 0;
    if (DeviceIoControl(hVolume.get(), FSCTL_IS_VOLUME_OWNED_BY_BITLOCKER, nullptr, 0, nullptr, 0, &bytesReturned, nullptr)) {
        return {QueryStatus::Encrypted, 100, "BitLocker", true, {}};
    }

    const DWORD error = GetLastError();
    if (error == ERROR_NOT_FOUND) return {QueryStatus::NotEncrypted, 0, std::nullopt, false, {}};
    if (error == ERROR_ACCESS_DENIED) return {QueryStatus::AccessDenied, {}, {}, {}, "Access denied querying the system volume."};
    if (error == ERROR_INVALID_FUNCTION || error == ERROR_NOT_SUPPORTED) return {QueryStatus::NotSupported, {}, {}, {}, "The BitLocker query is not supported."};
    return {QueryStatus::Error, {}, {}, {}, std::format("The BitLocker query failed (error {}).", error)};
#else
    return {QueryStatus::NotSupported, {}, {}, {}, "Encryption inspection is only supported on Windows."};
#endif
}

} // namespace sentinel::collectors
