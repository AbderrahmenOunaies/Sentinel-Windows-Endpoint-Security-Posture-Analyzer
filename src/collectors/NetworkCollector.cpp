#include "NetworkCollector.h"
#include "core/Logger.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <psapi.h>
#endif

#include "platform/windows/WinRaii.h"
#include "platform/windows/StringEncoding.h"

#include <vector>
#include <format>
#include <cstring>

namespace sentinel::collectors {

#ifdef _WIN32

static core::TcpState mapMibTcpState(DWORD state) noexcept {
    switch (state) {
        case MIB_TCP_STATE_CLOSED:     return core::TcpState::Closed;
        case MIB_TCP_STATE_LISTEN:     return core::TcpState::Listen;
        case MIB_TCP_STATE_SYN_SENT:   return core::TcpState::SynSent;
        case MIB_TCP_STATE_SYN_RCVD:   return core::TcpState::SynReceived;
        case MIB_TCP_STATE_ESTAB:      return core::TcpState::Established;
        case MIB_TCP_STATE_FIN_WAIT1:  return core::TcpState::FinWait1;
        case MIB_TCP_STATE_FIN_WAIT2:  return core::TcpState::FinWait2;
        case MIB_TCP_STATE_CLOSE_WAIT: return core::TcpState::CloseWait;
        case MIB_TCP_STATE_CLOSING:    return core::TcpState::Closing;
        case MIB_TCP_STATE_LAST_ACK:   return core::TcpState::LastAck;
        case MIB_TCP_STATE_TIME_WAIT:  return core::TcpState::TimeWait;
        case MIB_TCP_STATE_DELETE_TCB: return core::TcpState::DeleteTcb;
        default:                       return core::TcpState::Unknown;
    }
}

static std::string formatIpv4(DWORD ip) {
    IN_ADDR addr;
    addr.S_un.S_addr = ip;
    char buf[INET_ADDRSTRLEN] = {0};
    if (inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
        return std::string(buf);
    }
    return "0.0.0.0";
}

static std::string formatIpv6(const UCHAR* bytes) {
    IN6_ADDR addr;
    std::memcpy(&addr, bytes, sizeof(IN6_ADDR));
    char buf[INET6_ADDRSTRLEN] = {0};
    if (inet_ntop(AF_INET6, &addr, buf, sizeof(buf))) {
        return std::string(buf);
    }
    return "::";
}

#endif

std::optional<std::string> NetworkCollector::resolveProcessName(std::uint32_t pid) {
    if (pid == 0) {
        return "System Idle Process";
    }
    if (pid == 4) {
        return "System";
    }

    if (auto it = m_processNameCache.find(pid); it != m_processNameCache.end()) {
        return it->second;
    }

#ifdef _WIN32
    // Standard user can query limited process information
    platform::UniqueHandle hProcess(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (hProcess.isValid()) {
        wchar_t pathBuf[MAX_PATH] = {0};
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess.get(), 0, pathBuf, &size)) {
            std::string fullPath = platform::wideToUtf8(pathBuf);
            // Extract basename
            auto lastSlash = fullPath.find_last_of("\\/");
            std::string exeName = (lastSlash != std::string::npos) ? fullPath.substr(lastSlash + 1) : fullPath;
            m_processNameCache[pid] = exeName;
            return exeName;
        }
    }
#endif

    return std::nullopt;
}

core::CollectionResult<core::NetworkSnapshot> NetworkCollector::collect() {
    LOG_INFO("NetworkCollector started.");
    m_processNameCache.clear();

#ifdef _WIN32
    core::NetworkSnapshot snapshot;

    // 1. Enumerate IPv4 TCP Table with Owner PID
    {
        DWORD dwSize = 0;
        DWORD dwRetVal = GetExtendedTcpTable(nullptr, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (dwRetVal == ERROR_INSUFFICIENT_BUFFER && dwSize > 0) {
            std::vector<BYTE> buffer(dwSize);
            dwRetVal = GetExtendedTcpTable(buffer.data(), &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (dwRetVal == NO_ERROR) {
                auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buffer.data());
                for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                    const auto& row = table->table[i];
                    core::TcpEndpoint ep;
                    ep.localAddress = formatIpv4(row.dwLocalAddr);
                    ep.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
                    ep.remoteAddress = formatIpv4(row.dwRemoteAddr);
                    ep.remotePort = ntohs(static_cast<u_short>(row.dwRemotePort));
                    ep.state = mapMibTcpState(row.dwState);
                    ep.processId = row.dwOwningPid;
                    ep.processName = resolveProcessName(row.dwOwningPid);
                    snapshot.tcpEndpoints.push_back(std::move(ep));
                }
            } else {
                LOG_WARNING(std::format("GetExtendedTcpTable (IPv4) returned error code {}", dwRetVal));
            }
        }
    }

    // 2. Enumerate IPv6 TCP Table with Owner PID
    {
        DWORD dwSize = 0;
        DWORD dwRetVal = GetExtendedTcpTable(nullptr, &dwSize, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
        if (dwRetVal == ERROR_INSUFFICIENT_BUFFER && dwSize > 0) {
            std::vector<BYTE> buffer(dwSize);
            dwRetVal = GetExtendedTcpTable(buffer.data(), &dwSize, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
            if (dwRetVal == NO_ERROR) {
                auto* table = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(buffer.data());
                for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                    const auto& row = table->table[i];
                    core::TcpEndpoint ep;
                    ep.localAddress = formatIpv6(row.ucLocalAddr);
                    ep.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
                    ep.remoteAddress = formatIpv6(row.ucRemoteAddr);
                    ep.remotePort = ntohs(static_cast<u_short>(row.dwRemotePort));
                    ep.state = mapMibTcpState(row.dwState);
                    ep.processId = row.dwOwningPid;
                    ep.processName = resolveProcessName(row.dwOwningPid);
                    snapshot.tcpEndpoints.push_back(std::move(ep));
                }
            } else {
                LOG_WARNING(std::format("GetExtendedTcpTable (IPv6) returned error code {}", dwRetVal));
            }
        }
    }

    // 3. Enumerate IPv4 UDP Table with Owner PID
    {
        DWORD dwSize = 0;
        DWORD dwRetVal = GetExtendedUdpTable(nullptr, &dwSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        if (dwRetVal == ERROR_INSUFFICIENT_BUFFER && dwSize > 0) {
            std::vector<BYTE> buffer(dwSize);
            dwRetVal = GetExtendedUdpTable(buffer.data(), &dwSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
            if (dwRetVal == NO_ERROR) {
                auto* table = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buffer.data());
                for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                    const auto& row = table->table[i];
                    core::UdpEndpoint ep;
                    ep.localAddress = formatIpv4(row.dwLocalAddr);
                    ep.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
                    ep.processId = row.dwOwningPid;
                    ep.processName = resolveProcessName(row.dwOwningPid);
                    snapshot.udpEndpoints.push_back(std::move(ep));
                }
            } else {
                LOG_WARNING(std::format("GetExtendedUdpTable (IPv4) returned error code {}", dwRetVal));
            }
        }
    }

    // 4. Enumerate IPv6 UDP Table with Owner PID
    {
        DWORD dwSize = 0;
        DWORD dwRetVal = GetExtendedUdpTable(nullptr, &dwSize, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
        if (dwRetVal == ERROR_INSUFFICIENT_BUFFER && dwSize > 0) {
            std::vector<BYTE> buffer(dwSize);
            dwRetVal = GetExtendedUdpTable(buffer.data(), &dwSize, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
            if (dwRetVal == NO_ERROR) {
                auto* table = reinterpret_cast<MIB_UDP6TABLE_OWNER_PID*>(buffer.data());
                for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                    const auto& row = table->table[i];
                    core::UdpEndpoint ep;
                    ep.localAddress = formatIpv6(row.ucLocalAddr);
                    ep.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
                    ep.processId = row.dwOwningPid;
                    ep.processName = resolveProcessName(row.dwOwningPid);
                    snapshot.udpEndpoints.push_back(std::move(ep));
                }
            } else {
                LOG_WARNING(std::format("GetExtendedUdpTable (IPv6) returned error code {}", dwRetVal));
            }
        }
    }

    LOG_INFO(std::format("NetworkCollector completed: {} TCP endpoints, {} UDP endpoints collected.",
                         snapshot.tcpEndpoints.size(), snapshot.udpEndpoints.size()));

    return core::CollectionResult<core::NetworkSnapshot>(std::move(snapshot));
#else
    LOG_ERROR("NetworkCollector unsupported on non-Windows platform.");
    return core::CollectionResult<core::NetworkSnapshot>(core::ErrorCode::NotSupported, "Non-Windows platform not supported");
#endif
}

} // namespace sentinel::collectors
