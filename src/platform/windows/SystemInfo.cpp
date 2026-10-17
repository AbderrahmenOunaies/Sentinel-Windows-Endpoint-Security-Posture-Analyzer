#include "SystemInfo.h"

#ifdef _WIN32
#include <windows.h>
#include <securitybaseapi.h>
#endif

namespace sentinel::platform {

PrivilegeLevel SystemInfo::detectPrivilege() {
#ifdef _WIN32
    BOOL isMember = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(
            &ntAuthority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isMember);
        FreeSid(adminGroup);
    }

    return isMember ? PrivilegeLevel::Administrator : PrivilegeLevel::StandardUser;
#else
    return PrivilegeLevel::Unknown;
#endif
}

std::string SystemInfo::privilegeToString(PrivilegeLevel level) {
    switch (level) {
        case PrivilegeLevel::Administrator:
            return "ADMINISTRATOR";
        case PrivilegeLevel::StandardUser:
            return "STANDARD USER";
        default:
            return "UNKNOWN";
    }
}

std::string SystemInfo::getHostName() {
#ifdef _WIN32
    char buffer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(buffer);
    if (GetComputerNameA(buffer, &size)) {
        return std::string(buffer, size);
    }
#endif
    return "localhost";
}

std::string SystemInfo::getOsVersion() {
#ifdef _WIN32
    return "Windows (x64)";
#else
    return "Non-Windows";
#endif
}

} // namespace sentinel::platform
