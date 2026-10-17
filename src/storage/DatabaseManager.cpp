#include "DatabaseManager.h"
#include "core/Logger.h"
#include <filesystem>
#include <cstdlib>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#endif

namespace sentinel::storage {

DatabaseManager& DatabaseManager::instance() {
    static DatabaseManager instance;
    return instance;
}

DatabaseManager::~DatabaseManager() {
    close();
}

std::string DatabaseManager::getDefaultDatabasePath() {
#ifdef _WIN32
    PWSTR localAppDataPath = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &localAppDataPath))) {
        std::filesystem::path appDir(localAppDataPath);
        CoTaskMemFree(localAppDataPath);
        appDir /= "Sentinel";
        return (appDir / "sentinel.db").string();
    }
#endif
    // Fallback to current directory or temp
    const char* appData = std::getenv("LOCALAPPDATA");
    if (appData) {
        std::filesystem::path p(appData);
        p /= "Sentinel";
        return (p / "sentinel.db").string();
    }
    return "sentinel.db";
}

core::Result<bool> DatabaseManager::initialize(const std::string& customPath) {
    if (m_db != nullptr) {
        return core::Result<bool>::success(true);
    }

    m_dbPath = customPath.empty() ? getDefaultDatabasePath() : customPath;

    // Ensure directory exists if not in-memory
    if (m_dbPath != ":memory:") {
        try {
            std::filesystem::path p(m_dbPath);
            if (p.has_parent_path()) {
                std::filesystem::create_directories(p.parent_path());
            }
        } catch (const std::exception& e) {
            LOG_ERROR(std::string("Failed to create database directory: ") + e.what());
            return core::Result<bool>::failure(core::ErrorCode::SystemError, "Failed to create database directory: " + std::string(e.what()));
        }
    }

    int rc = sqlite3_open_v2(
        m_dbPath.c_str(),
        &m_db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
        nullptr
    );

    if (rc != SQLITE_OK) {
        std::string err = m_db ? sqlite3_errmsg(m_db) : "Failed to open sqlite3 database";
        LOG_ERROR("SQLite open failed: " + err);
        if (m_db) {
            sqlite3_close(m_db);
            m_db = nullptr;
        }
        return core::Result<bool>::failure(core::ErrorCode::SystemError, "SQLite open error: " + err);
    }

    // Enable foreign keys and set WAL journal mode for concurrency & integrity
    char* zErrMsg = nullptr;
    rc = sqlite3_exec(m_db, "PRAGMA foreign_keys = ON;", nullptr, nullptr, &zErrMsg);
    if (rc != SQLITE_OK) {
        std::string err = zErrMsg ? zErrMsg : "Failed to enable foreign keys";
        sqlite3_free(zErrMsg);
        LOG_WARNING("SQLite pragma foreign_keys error: " + err);
    }

    if (m_dbPath != ":memory:") {
        sqlite3_exec(m_db, "PRAGMA journal_mode = WAL;", nullptr, nullptr, nullptr);
    }

    m_initialized = true;
    LOG_INFO("SQLite database initialized successfully at: " + m_dbPath);
    return core::Result<bool>::success(true);
}

void DatabaseManager::close() {
    if (m_db != nullptr) {
        sqlite3_close(m_db);
        m_db = nullptr;
        m_initialized = false;
        LOG_INFO("SQLite database closed: " + m_dbPath);
    }
}

bool DatabaseManager::isOpen() const noexcept {
    return m_db != nullptr;
}

} // namespace sentinel::storage
