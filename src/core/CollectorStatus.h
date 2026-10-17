#pragma once

#include "Result.h"
#include <string>
#include <optional>

namespace sentinel::core {

struct CollectorStatus {
    std::string collectorId;
    ErrorCode status{ErrorCode::Success};
    std::string message;
    std::optional<long> nativeErrorCode;
};

} // namespace sentinel::core
