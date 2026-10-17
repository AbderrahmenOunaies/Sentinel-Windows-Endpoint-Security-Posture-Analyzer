#include "SettingsRepository.h"
#include <chrono>

namespace sentinel::storage {

SettingsRepository::SettingsRepository(sqlite3* db)
    : m_db(db) {}

core::Result<bool> SettingsRepository::setString(const std::string& key, const std::string& value) {
    if (!m_db) {
        return core::Result<bool>::failure(core::ErrorCode::SystemError, "Null database pointer");
    }

    const char* sql = R"SQL(
        INSERT INTO app_settings (key, value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            updated_at = excluded.updated_at;
    )SQL";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return core::Result<bool>::failure(core::ErrorCode::SystemError, sqlite3_errmsg(m_db));
    }

    auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();

    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, value.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(nowMs));

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        return core::Result<bool>::failure(core::ErrorCode::SystemError, sqlite3_errmsg(m_db));
    }

    return core::Result<bool>::success(true);
}

core::Result<std::optional<std::string>> SettingsRepository::getString(const std::string& key) {
    if (!m_db) {
        return core::Result<std::optional<std::string>>::failure(core::ErrorCode::SystemError, "Null database pointer");
    }

    const char* sql = "SELECT value FROM app_settings WHERE key = ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return core::Result<std::optional<std::string>>::failure(core::ErrorCode::SystemError, sqlite3_errmsg(m_db));
    }

    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return core::Result<std::optional<std::string>>::success(std::nullopt);
    }

    std::string val = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    sqlite3_finalize(stmt);
    return core::Result<std::optional<std::string>>::success(val);
}

core::Result<bool> SettingsRepository::setInt(const std::string& key, int value) {
    return setString(key, std::to_string(value));
}

core::Result<std::optional<int>> SettingsRepository::getInt(const std::string& key) {
    auto res = getString(key);
    if (!res.isSuccess()) {
        return core::Result<std::optional<int>>::failure(res.code(), res.errorMessage());
    }
    if (!res.value().has_value()) {
        return core::Result<std::optional<int>>::success(std::nullopt);
    }
    try {
        int v = std::stoi(res.value().value());
        return core::Result<std::optional<int>>::success(v);
    } catch (...) {
        return core::Result<std::optional<int>>::failure(core::ErrorCode::SystemError, "Failed to parse setting as int");
    }
}

} // namespace sentinel::storage
