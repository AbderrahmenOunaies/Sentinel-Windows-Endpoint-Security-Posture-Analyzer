#include "AccountCollector.h"
#include "core/Logger.h"
#include "platform/windows/WinRaii.h"
#include "platform/windows/StringEncoding.h"

#ifdef _WIN32
#include <windows.h>
#include <lm.h>
#endif

#include <format>

namespace sentinel::collectors {

core::CollectionResult<core::AccountSnapshot> AccountCollector::collect() {
    LOG_INFO("AccountCollector started.");

#ifdef _WIN32
    core::AccountSnapshot snapshot;

    USER_INFO_2* pBuf = nullptr;
    DWORD entriesRead = 0;
    DWORD totalEntries = 0;
    DWORD resumeHandle = 0;

    NET_API_STATUS nStatus = NetUserEnum(
        nullptr,
        2,
        FILTER_NORMAL_ACCOUNT,
        reinterpret_cast<LPBYTE*>(&pBuf),
        MAX_PREFERRED_LENGTH,
        &entriesRead,
        &totalEntries,
        &resumeHandle
    );

    platform::UniqueNetApiBuffer<USER_INFO_2> guard(pBuf);

    if (nStatus != NERR_Success && nStatus != ERROR_MORE_DATA) {
        LOG_WARNING(std::format("AccountCollector: NetUserEnum failed with status {}", nStatus));
        if (nStatus == ERROR_ACCESS_DENIED) {
            return core::CollectionResult<core::AccountSnapshot>(core::ErrorCode::PermissionDenied, "Permission denied accessing local accounts");
        }
        return core::CollectionResult<core::AccountSnapshot>(core::ErrorCode::SystemError, std::format("NetUserEnum failed with code {}", nStatus));
    }

    if (pBuf != nullptr) {
        snapshot.accounts.reserve(entriesRead);
        for (DWORD i = 0; i < entriesRead; ++i) {
            const auto& user = pBuf[i];
            core::AccountInfo acc;
            acc.username = platform::wideToUtf8(user.usri2_name ? user.usri2_name : L"");
            acc.displayName = platform::wideToUtf8(user.usri2_full_name ? user.usri2_full_name : L"");

            DWORD flags = user.usri2_flags;
            acc.enabled = !(flags & UF_ACCOUNTDISABLE);
            acc.passwordRequired = !(flags & UF_PASSWD_NOTREQD);
            acc.passwordNeverExpires = (flags & UF_DONT_EXPIRE_PASSWD) != 0;
            acc.accountLocked = (flags & UF_LOCKOUT) != 0;

            if (user.usri2_password_age > 0) {
                auto now = std::chrono::system_clock::now();
                acc.passwordLastSet = now - std::chrono::seconds(user.usri2_password_age);
            }

            snapshot.accounts.push_back(std::move(acc));
        }
    }

    snapshot.collected = true;
    LOG_INFO(std::format("AccountCollector completed: {} local accounts collected.", snapshot.accounts.size()));
    return core::CollectionResult<core::AccountSnapshot>(std::move(snapshot));
#else
    LOG_ERROR("AccountCollector unsupported on non-Windows platform.");
    return core::CollectionResult<core::AccountSnapshot>(core::ErrorCode::NotSupported, "Non-Windows platform not supported");
#endif
}

} // namespace sentinel::collectors
