#pragma once

#include "core/Result.h"
#include "core/security/AccountSnapshot.h"

namespace sentinel::collectors {

class AccountCollector {
public:
    AccountCollector() = default;
    ~AccountCollector() = default;

    [[nodiscard]] core::CollectionResult<core::AccountSnapshot> collect();
};

} // namespace sentinel::collectors
