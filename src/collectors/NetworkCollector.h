#pragma once

#include "core/Result.h"
#include "core/collection/NetworkSnapshot.h"

#include <unordered_map>
#include <string>

namespace sentinel::collectors {

class NetworkCollector {
public:
    NetworkCollector() = default;
    ~NetworkCollector() = default;

    [[nodiscard]] core::CollectionResult<core::NetworkSnapshot> collect();

private:
    std::unordered_map<std::uint32_t, std::string> m_processNameCache;

    std::optional<std::string> resolveProcessName(std::uint32_t pid);
};

} // namespace sentinel::collectors
