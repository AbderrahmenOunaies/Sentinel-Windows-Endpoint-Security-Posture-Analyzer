#pragma once

#include "core/Result.h"
#include "core/security/FirewallSnapshot.h"

namespace sentinel::collectors {

class FirewallCollector {
public:
    FirewallCollector() = default;
    ~FirewallCollector() = default;

    [[nodiscard]] core::CollectionResult<core::FirewallSnapshot> collect();
};

} // namespace sentinel::collectors
