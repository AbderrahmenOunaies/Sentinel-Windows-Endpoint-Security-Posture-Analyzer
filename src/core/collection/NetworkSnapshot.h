#pragma once

#include <string>
#include <string_view>
#include <cstdint>
#include <optional>
#include <vector>

namespace sentinel::core {

enum class TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
    Unknown
};

[[nodiscard]] constexpr std::string_view tcpStateToString(TcpState state) noexcept {
    switch (state) {
        case TcpState::Closed:      return "Closed";
        case TcpState::Listen:      return "Listen";
        case TcpState::SynSent:     return "SynSent";
        case TcpState::SynReceived: return "SynReceived";
        case TcpState::Established: return "Established";
        case TcpState::FinWait1:    return "FinWait1";
        case TcpState::FinWait2:    return "FinWait2";
        case TcpState::CloseWait:   return "CloseWait";
        case TcpState::Closing:     return "Closing";
        case TcpState::LastAck:     return "LastAck";
        case TcpState::TimeWait:    return "TimeWait";
        case TcpState::DeleteTcb:   return "DeleteTcb";
        case TcpState::Unknown:     return "Unknown";
    }
    return "Unknown";
}

struct TcpEndpoint {
    std::string localAddress;
    std::uint16_t localPort{0};

    std::string remoteAddress;
    std::uint16_t remotePort{0};

    TcpState state{TcpState::Unknown};

    std::uint32_t processId{0};
    std::optional<std::string> processName;
};

struct UdpEndpoint {
    std::string localAddress;
    std::uint16_t localPort{0};

    std::uint32_t processId{0};
    std::optional<std::string> processName;
};

struct NetworkSnapshot {
    std::vector<TcpEndpoint> tcpEndpoints;
    std::vector<UdpEndpoint> udpEndpoints;
};

} // namespace sentinel::core
