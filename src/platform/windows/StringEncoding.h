#pragma once

#include <string>
#include <string_view>

#ifdef _WIN32
#include <windows.h>
#endif

namespace sentinel::platform {

[[nodiscard]] inline std::string wideToUtf8(std::wstring_view wstr) {
    if (wstr.empty()) return {};
#ifdef _WIN32
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), nullptr, 0, nullptr, nullptr);
    if (sizeNeeded <= 0) return {};
    std::string result(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), result.data(), sizeNeeded, nullptr, nullptr);
    return result;
#else
    return std::string(wstr.begin(), wstr.end());
#endif
}

[[nodiscard]] inline std::wstring utf8ToWide(std::string_view str) {
    if (str.empty()) return {};
#ifdef _WIN32
    int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), nullptr, 0);
    if (sizeNeeded <= 0) return {};
    std::wstring result(sizeNeeded, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), result.data(), sizeNeeded);
    return result;
#else
    return std::wstring(str.begin(), str.end());
#endif
}

} // namespace sentinel::platform
