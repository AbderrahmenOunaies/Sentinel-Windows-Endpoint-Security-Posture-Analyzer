#pragma once

#include "core/Result.h"
#include "core/security/UpdateSnapshot.h"

namespace sentinel::collectors {

class UpdateCollector {
public:
    UpdateCollector() = default;
    ~UpdateCollector() = default;

    [[nodiscard]] core::CollectionResult<core::UpdateSnapshot> collect();
};

} // namespace sentinel::collectors
