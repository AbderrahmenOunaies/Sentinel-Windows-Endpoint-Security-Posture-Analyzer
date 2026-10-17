#include "DatabaseMigrator.h"
#include "core/Logger.h"
#include <string>
#include <format>

namespace sentinel::storage {

core::Result<int> DatabaseMigrator::getSchemaVersion(sqlite3* db) {
    if (!db) {
        return core::Result<int>::failure(core::ErrorCode::SystemError, "Null database pointer");
    }

    sqlite3_stmt* stmt = nullptr;
    const char* sql = "PRAGMA user_version;";
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        return core::Result<int>::failure(core::ErrorCode::SystemError, sqlite3_errmsg(db));
    }

    int version = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        version = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);

    return core::Result<int>::success(version);
}

core::Result<bool> DatabaseMigrator::migrate(sqlite3* db) {
    if (!db) {
        return core::Result<bool>::failure(core::ErrorCode::SystemError, "Null database pointer");
    }

    auto verRes = getSchemaVersion(db);
    if (!verRes.isSuccess()) {
        return core::Result<bool>::failure(verRes.code(), verRes.errorMessage());
    }

    int currentVersion = verRes.value();
    LOG_INFO(std::format("Current database user_version: {}", currentVersion));

    if (currentVersion > CURRENT_SCHEMA_VERSION) {
        std::string err = std::format("Database schema version {} is newer than supported version {}. Aborting to prevent corruption.",
                                      currentVersion, CURRENT_SCHEMA_VERSION);
        LOG_ERROR(err);
        return core::Result<bool>::failure(core::ErrorCode::NotSupported, err);
    }

    if (currentVersion == 0) {
        LOG_INFO("Applying Initial Schema Migration V1...");
        auto v1Res = applyMigrationV1(db);
        if (!v1Res.isSuccess()) {
            return v1Res;
        }
        currentVersion = 1;
    }

    LOG_INFO(std::format("Database schema is up to date (version {})", currentVersion));
    return core::Result<bool>::success(true);
}

core::Result<bool> DatabaseMigrator::applyMigrationV1(sqlite3* db) {
    const char* v1SchemaSql = R"SQL(
        BEGIN TRANSACTION;

        -- 1. Scans table
        CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY,
            started_at INTEGER NOT NULL,
            completed_at INTEGER NOT NULL,
            duration_ms INTEGER NOT NULL,
            profile_name TEXT NOT NULL,
            base_score INTEGER NOT NULL,
            final_score INTEGER NOT NULL,
            score_classification TEXT NOT NULL,
            passed_count INTEGER NOT NULL,
            failed_count INTEGER NOT NULL,
            unknown_count INTEGER NOT NULL,
            findings_count INTEGER NOT NULL,
            completed_successfully INTEGER NOT NULL,
            status_message TEXT NOT NULL
        );

        -- 2. Findings table
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            impact TEXT,
            recommendation TEXT NOT NULL,
            remediation_available INTEGER NOT NULL,
            remediation_id TEXT,
            detected_at INTEGER NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_rule_id ON findings(rule_id);
        CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

        -- 3. Evidence table
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id TEXT NOT NULL,
            source TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_evidence_finding_id ON evidence(finding_id);

        -- 4. Settings table
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );

        -- 5. Collector status table
        CREATE TABLE IF NOT EXISTS collector_status_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            collector_id TEXT NOT NULL,
            status_code INTEGER NOT NULL,
            message TEXT,
            native_error_code INTEGER,
            FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_collector_scan_id ON collector_status_records(scan_id);

        -- Set schema version to 1
        PRAGMA user_version = 1;

        COMMIT;
    )SQL";

    char* zErrMsg = nullptr;
    int rc = sqlite3_exec(db, v1SchemaSql, nullptr, nullptr, &zErrMsg);
    if (rc != SQLITE_OK) {
        std::string err = zErrMsg ? zErrMsg : "Error applying V1 migration";
        sqlite3_free(zErrMsg);
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        LOG_ERROR("Migration V1 failed: " + err);
        return core::Result<bool>::failure(core::ErrorCode::SystemError, "Migration V1 failed: " + err);
    }

    LOG_INFO("Migration V1 completed successfully.");
    return core::Result<bool>::success(true);
}

} // namespace sentinel::storage
