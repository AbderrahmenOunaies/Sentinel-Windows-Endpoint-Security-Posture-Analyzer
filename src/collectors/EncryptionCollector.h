#pragma once

#include "core/Result.h"
#include "core/security/EncryptionSnapshot.h"

namespace sentinel::collectors {

class EncryptionCollector {
public:
    EncryptionCollector() = default;
    ~EncryptionCollector() = default;

    [[nodiscard]] core::CollectionResult<core::EncryptionSnapshot> collect();
};

} // namespace sentinel::collectors
