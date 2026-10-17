#pragma once

#include "core/Result.h"
#include <sqlite3.h>
#include <string>
#include <optional>

namespace sentinel::storage {

class SettingsRepository {
public:
    explicit SettingsRepository(sqlite3* db);

    [[nodiscard]] core::Result<bool> setString(const std::string& key, const std::string& value);
    [[nodiscard]] core::Result<std::optional<std::string>> getString(const std::string& key);

    [[nodiscard]] core::Result<bool> setInt(const std::string& key, int value);
    [[nodiscard]] core::Result<std::optional<int>> getInt(const std::string& key);

private:
    sqlite3* m_db{nullptr};
};

} // namespace sentinel::storage
