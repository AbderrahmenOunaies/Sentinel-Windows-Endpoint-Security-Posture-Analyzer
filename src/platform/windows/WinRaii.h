#pragma once

#ifdef _WIN32
#include <windows.h>
#include <winsvc.h>
#endif

#include <utility>

namespace sentinel::platform {

#ifdef _WIN32

// RAII wrapper for generic Win32 HANDLE (CloseHandle)
class UniqueHandle {
public:
    UniqueHandle() noexcept : m_handle(nullptr) {}
    explicit UniqueHandle(HANDLE h) noexcept : m_handle((h == INVALID_HANDLE_VALUE) ? nullptr : h) {}
    ~UniqueHandle() noexcept { reset(); }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept : m_handle(other.m_handle) {
        other.m_handle = nullptr;
    }

    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) {
            reset();
            m_handle = other.m_handle;
            other.m_handle = nullptr;
        }
        return *this;
    }

    [[nodiscard]] HANDLE get() const noexcept { return m_handle; }
    [[nodiscard]] bool isValid() const noexcept { return m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE; }
    explicit operator bool() const noexcept { return isValid(); }

    void reset(HANDLE h = nullptr) noexcept {
        if (isValid()) {
            CloseHandle(m_handle);
        }
        m_handle = (h == INVALID_HANDLE_VALUE) ? nullptr : h;
    }

private:
    HANDLE m_handle{nullptr};
};

// RAII wrapper for Service Control Manager handles (CloseServiceHandle)
class UniqueServiceHandle {
public:
    UniqueServiceHandle() noexcept : m_handle(nullptr) {}
    explicit UniqueServiceHandle(SC_HANDLE h) noexcept : m_handle(h) {}
    ~UniqueServiceHandle() noexcept { reset(); }

    UniqueServiceHandle(const UniqueServiceHandle&) = delete;
    UniqueServiceHandle& operator=(const UniqueServiceHandle&) = delete;

    UniqueServiceHandle(UniqueServiceHandle&& other) noexcept : m_handle(other.m_handle) {
        other.m_handle = nullptr;
    }

    UniqueServiceHandle& operator=(UniqueServiceHandle&& other) noexcept {
        if (this != &other) {
            reset();
            m_handle = other.m_handle;
            other.m_handle = nullptr;
        }
        return *this;
    }

    [[nodiscard]] SC_HANDLE get() const noexcept { return m_handle; }
    [[nodiscard]] bool isValid() const noexcept { return m_handle != nullptr; }
    explicit operator bool() const noexcept { return isValid(); }

    void reset(SC_HANDLE h = nullptr) noexcept {
        if (m_handle != nullptr) {
            CloseServiceHandle(m_handle);
        }
        m_handle = h;
    }

private:
    SC_HANDLE m_handle{nullptr};
};

// RAII wrapper for HKEY (RegCloseKey)
class UniqueHKey {
public:
    UniqueHKey() noexcept : m_hkey(nullptr) {}
    explicit UniqueHKey(HKEY k) noexcept : m_hkey(k) {}
    ~UniqueHKey() noexcept { reset(); }

    UniqueHKey(const UniqueHKey&) = delete;
    UniqueHKey& operator=(const UniqueHKey&) = delete;

    UniqueHKey(UniqueHKey&& other) noexcept : m_hkey(other.m_hkey) {
        other.m_hkey = nullptr;
    }

    UniqueHKey& operator=(UniqueHKey&& other) noexcept {
        if (this != &other) {
            reset();
            m_hkey = other.m_hkey;
            other.m_hkey = nullptr;
        }
        return *this;
    }

    [[nodiscard]] HKEY get() const noexcept { return m_hkey; }
    [[nodiscard]] HKEY* addressof() noexcept { return &m_hkey; }
    [[nodiscard]] bool isValid() const noexcept { return m_hkey != nullptr; }
    explicit operator bool() const noexcept { return isValid(); }

    void reset(HKEY k = nullptr) noexcept {
        if (m_hkey != nullptr) {
            RegCloseKey(m_hkey);
        }
        m_hkey = k;
    }

private:
    HKEY m_hkey{nullptr};
};

// RAII wrapper for NetApiBufferFree
template <typename T>
class UniqueNetApiBuffer {
public:
    UniqueNetApiBuffer() noexcept : m_buf(nullptr) {}
    explicit UniqueNetApiBuffer(T* buf) noexcept : m_buf(buf) {}
    ~UniqueNetApiBuffer() noexcept { reset(); }

    UniqueNetApiBuffer(const UniqueNetApiBuffer&) = delete;
    UniqueNetApiBuffer& operator=(const UniqueNetApiBuffer&) = delete;

    UniqueNetApiBuffer(UniqueNetApiBuffer&& other) noexcept : m_buf(other.m_buf) {
        other.m_buf = nullptr;
    }

    UniqueNetApiBuffer& operator=(UniqueNetApiBuffer&& other) noexcept {
        if (this != &other) {
            reset();
            m_buf = other.m_buf;
            other.m_buf = nullptr;
        }
        return *this;
    }

    [[nodiscard]] T* get() const noexcept { return m_buf; }
    [[nodiscard]] T** addressof() noexcept { return &m_buf; }
    [[nodiscard]] bool isValid() const noexcept { return m_buf != nullptr; }
    explicit operator bool() const noexcept { return isValid(); }

    void reset(T* buf = nullptr) noexcept {
        if (m_buf != nullptr) {
            NetApiBufferFree(m_buf);
        }
        m_buf = buf;
    }

private:
    T* m_buf{nullptr};
};

// RAII wrapper for COM Initializer
class ScopedCoInitialize {
public:
    ScopedCoInitialize() noexcept {
        m_hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (m_hr == RPC_E_CHANGED_MODE) {
            m_hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        }
    }

    ~ScopedCoInitialize() noexcept {
        if (SUCCEEDED(m_hr)) {
            CoUninitialize();
        }
    }

    [[nodiscard]] bool isSucceeded() const noexcept { return SUCCEEDED(m_hr); }
    [[nodiscard]] HRESULT result() const noexcept { return m_hr; }

private:
    HRESULT m_hr{E_FAIL};
};

#endif

} // namespace sentinel::platform
