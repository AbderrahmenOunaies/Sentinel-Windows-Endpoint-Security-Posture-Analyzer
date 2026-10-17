#pragma once

#include <string>
#include <cstdint>

namespace sentinel::core {

struct SystemSnapshot {
    std::string computerName;
    std::string operatingSystem;
    std::string osVersion;
    std::string osBuild;
    std::string architecture;
    std::uint32_t processorCount{0};
    std::uint64_t physicalMemoryBytes{0};
    std::uint32_t pageSize{0};
    std::string systemDirectory;
};

} // namespace sentinel::core
