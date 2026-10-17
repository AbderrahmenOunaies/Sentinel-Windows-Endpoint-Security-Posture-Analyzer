#pragma once

#include "core/Result.h"
#include "core/collection/SystemSnapshot.h"

namespace sentinel::collectors {

class SystemCollector {
public:
    SystemCollector() = default;
    ~SystemCollector() = default;

    [[nodiscard]] core::CollectionResult<core::SystemSnapshot> collect();
};

} // namespace sentinel::collectors
