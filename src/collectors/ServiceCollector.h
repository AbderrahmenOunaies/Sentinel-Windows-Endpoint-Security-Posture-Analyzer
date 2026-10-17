#pragma once

#include "core/Result.h"
#include "core/collection/ServiceSnapshot.h"

namespace sentinel::collectors {

class ServiceCollector {
public:
    ServiceCollector() = default;
    ~ServiceCollector() = default;

    [[nodiscard]] core::CollectionResult<core::ServiceSnapshot> collect();
};

} // namespace sentinel::collectors
