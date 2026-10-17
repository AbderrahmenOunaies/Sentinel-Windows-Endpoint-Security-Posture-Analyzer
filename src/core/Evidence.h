#pragma once

#include <string>

namespace sentinel::core {

struct Evidence {
    std::string source;
    std::string key;
    std::string value;

    auto operator<=>(const Evidence&) const = default;
};

} // namespace sentinel::core
