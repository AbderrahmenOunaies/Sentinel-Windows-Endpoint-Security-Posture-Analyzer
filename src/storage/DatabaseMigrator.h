#pragma once

#include "core/Result.h"
#include <sqlite3.h>

namespace sentinel::storage {

class DatabaseMigrator {
public:
    static constexpr int CURRENT_SCHEMA_VERSION = 1;

    static core::Result<bool> migrate(sqlite3* db);
    static core::Result<int> getSchemaVersion(sqlite3* db);

private:
    static core::Result<bool> applyMigrationV1(sqlite3* db);
};

} // namespace sentinel::storage
