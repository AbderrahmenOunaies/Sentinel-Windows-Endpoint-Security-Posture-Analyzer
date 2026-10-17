#include "ServiceCollector.h"
#include "core/Logger.h"
#include "platform/windows/WinRaii.h"
#include "platform/windows/StringEncoding.h"

#ifdef _WIN32
#include <windows.h>
#include <winsvc.h>
#endif

#include <vector>
#include <format>

namespace sentinel::collectors {

#ifdef _WIN32

static core::ServiceState mapServiceState(DWORD state) noexcept {
    switch (state) {
        case SERVICE_STOPPED:          return core::ServiceState::Stopped;
        case SERVICE_START_PENDING:    return core::ServiceState::StartPending;
        case SERVICE_STOP_PENDING:     return core::ServiceState::StopPending;
        case SERVICE_RUNNING:          return core::ServiceState::Running;
        case SERVICE_CONTINUE_PENDING: return core::ServiceState::ContinuePending;
        case SERVICE_PAUSE_PENDING:    return core::ServiceState::PausePending;
        case SERVICE_PAUSED:           return core::ServiceState::Paused;
        default:                       return core::ServiceState::Unknown;
    }
}

static core::ServiceStartType mapServiceStartType(DWORD startType) noexcept {
    switch (startType) {
        case SERVICE_BOOT_START:   return core::ServiceStartType::Boot;
        case SERVICE_SYSTEM_START: return core::ServiceStartType::System;
        case SERVICE_AUTO_START:   return core::ServiceStartType::Automatic;
        case SERVICE_DEMAND_START: return core::ServiceStartType::Manual;
        case SERVICE_DISABLED:     return core::ServiceStartType::Disabled;
        default:                   return core::ServiceStartType::Unknown;
    }
}

#endif

core::CollectionResult<core::ServiceSnapshot> ServiceCollector::collect() {
    LOG_INFO("ServiceCollector started.");

#ifdef _WIN32
    // Connect to SCM with standard read access (accessible to non-elevated standard users)
    platform::UniqueServiceHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT));
    if (!scm.isValid()) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            LOG_WARNING("ServiceCollector: Permission denied opening Service Control Manager.");
            return core::CollectionResult<core::ServiceSnapshot>(core::ErrorCode::PermissionDenied, "Permission denied opening Service Control Manager");
        }
        LOG_ERROR(std::format("ServiceCollector: Failed opening SCM. Native error {}", err));
        return core::CollectionResult<core::ServiceSnapshot>(core::ErrorCode::SystemError, std::format("OpenSCManager failed with code {}", err));
    }

    core::ServiceSnapshot snapshot;

    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;

    // Initial query to get required buffer size (2-call buffer pattern)
    EnumServicesStatusExW(
        scm.get(),
        SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32,
        SERVICE_STATE_ALL,
        nullptr,
        0,
        &bytesNeeded,
        &servicesReturned,
        &resumeHandle,
        nullptr
    );

    if (bytesNeeded == 0) {
        LOG_INFO("ServiceCollector completed: 0 services returned.");
        return core::CollectionResult<core::ServiceSnapshot>(std::move(snapshot));
    }

    std::vector<BYTE> buffer(bytesNeeded);
    resumeHandle = 0;

    BOOL ok = EnumServicesStatusExW(
        scm.get(),
        SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32,
        SERVICE_STATE_ALL,
        buffer.data(),
        bytesNeeded,
        &bytesNeeded,
        &servicesReturned,
        &resumeHandle,
        nullptr
    );

    if (!ok && GetLastError() != ERROR_MORE_DATA) {
        DWORD err = GetLastError();
        LOG_ERROR(std::format("ServiceCollector: EnumServicesStatusExW failed with code {}", err));
        return core::CollectionResult<core::ServiceSnapshot>(core::ErrorCode::SystemError, std::format("EnumServicesStatusExW failed with code {}", err));
    }

    auto* services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
    snapshot.services.reserve(servicesReturned);

    for (DWORD i = 0; i < servicesReturned; ++i) {
        const auto& s = services[i];
        core::ServiceInfo info;
        info.name = platform::wideToUtf8(s.lpServiceName ? s.lpServiceName : L"");
        info.displayName = platform::wideToUtf8(s.lpDisplayName ? s.lpDisplayName : L"");
        info.state = mapServiceState(s.ServiceStatusProcess.dwCurrentState);

        if (s.ServiceStatusProcess.dwProcessId != 0) {
            info.processId = s.ServiceStatusProcess.dwProcessId;
        }

        // Query configuration for binaryPath, startType, and service account
        platform::UniqueServiceHandle serviceHandle(OpenServiceW(scm.get(), s.lpServiceName, SERVICE_QUERY_CONFIG));
        if (serviceHandle.isValid()) {
            DWORD configNeeded = 0;
            QueryServiceConfigW(serviceHandle.get(), nullptr, 0, &configNeeded);
            if (configNeeded > 0) {
                std::vector<BYTE> configBuf(configNeeded);
                auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(configBuf.data());
                if (QueryServiceConfigW(serviceHandle.get(), config, configNeeded, &configNeeded)) {
                    info.startType = mapServiceStartType(config->dwStartType);
                    if (config->lpBinaryPathName) {
                        info.binaryPath = platform::wideToUtf8(config->lpBinaryPathName);
                    }
                    if (config->lpServiceStartName) {
                        info.account = platform::wideToUtf8(config->lpServiceStartName);
                    }
                }
            }
        }

        snapshot.services.push_back(std::move(info));
    }

    LOG_INFO(std::format("ServiceCollector completed successfully: {} services collected.", snapshot.services.size()));
    return core::CollectionResult<core::ServiceSnapshot>(std::move(snapshot));
#else
    LOG_ERROR("ServiceCollector unsupported on non-Windows platform.");
    return core::CollectionResult<core::ServiceSnapshot>(core::ErrorCode::NotSupported, "Non-Windows platform not supported");
#endif
}

} // namespace sentinel::collectors
