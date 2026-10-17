#pragma once

#include "core/Result.h"
#include "core/security/AuthenticationSnapshot.h"

namespace sentinel::collectors {

class AuthenticationCollector {
public:
    AuthenticationCollector() = default;
    ~AuthenticationCollector() = default;

    [[nodiscard]] core::CollectionResult<core::AuthenticationPolicySnapshot> collect();
};

} // namespace sentinel::collectors
