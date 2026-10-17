#pragma once

#include "core/Result.h"
#include "core/security/DefenderSnapshot.h"

namespace sentinel::collectors {

class DefenderCollector {
public:
    DefenderCollector() = default;
    ~DefenderCollector() = default;

    [[nodiscard]] core::CollectionResult<core::DefenderSnapshot> collect();
};

} // namespace sentinel::collectors
