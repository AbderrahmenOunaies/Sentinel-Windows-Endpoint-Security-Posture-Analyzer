#pragma once

#include <string>
#include <string_view>

namespace sentinel::platform {

enum class PrivilegeLevel {
    StandardUser,
    Administrator,
    Unknown
};

class SystemInfo {
public:
    static PrivilegeLevel detectPrivilege();
    static std::string privilegeToString(PrivilegeLevel level);
    static std::string getHostName();
    static std::string getOsVersion();
};

} // namespace sentinel::platform
