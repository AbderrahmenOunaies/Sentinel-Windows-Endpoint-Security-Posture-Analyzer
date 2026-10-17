#pragma once

#include "core/Result.h"
#include <string>
#include <memory>
#include <sqlite3.h>

namespace sentinel::storage {

class DatabaseManager {
public:
    static DatabaseManager& instance();

    ~DatabaseManager();

    // Prevent copy/move
    DatabaseManager(const DatabaseManager&) = delete;
    DatabaseManager& operator=(const DatabaseManager&) = delete;
    DatabaseManager(DatabaseManager&&) = delete;
    DatabaseManager& operator=(DatabaseManager&&) = delete;

    [[nodiscard]] core::Result<bool> initialize(const std::string& customPath = "");
    [[nodiscard]] core::Result<bool> close();

    [[nodiscard]] bool isOpen() const noexcept;
    [[nodiscard]] sqlite3* handle() const noexcept { return m_db; }
    [[nodiscard]] const std::string& databasePath() const noexcept { return m_dbPath; }

    [[nodiscard]] static std::string getDefaultDatabasePath();

private:
    DatabaseManager() = default;

    sqlite3* m_db{nullptr};
    std::string m_dbPath;
    bool m_initialized{false};
};

} // namespace sentinel::storage
