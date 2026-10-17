#include "ScanRepository.h"
#include "FindingRepository.h"
#include "core/Logger.h"
#include <chrono>

namespace sentinel::storage {

ScanRepository::ScanRepository(sqlite3* db)
    : m_db(db) {}

core::Result<bool> ScanRepository::insertScan(const core::ScanResult& scan) {
    if (!m_db) {
        return core::Result<bool>::failure(core::ErrorCode::SystemError, "Null database pointer");
    }

    // Begin transaction for scan + findings + collector statuses
    char* zErrMsg = nullptr;
    if (sqlite3_exec(m_db, "BEGIN TRANSACTION;", nullptr, nullptr, &zErrMsg) != SQLITE_OK) {
        std::string err = zErrMsg ? zErrMsg : "Failed to begin transaction";
        sqlite3_free(zErrMsg);
        return core::Result<bool>::failure(core::ErrorCode::SystemError, err);
    }

    const char* scanSql = R"SQL(
        INSERT INTO scans (
            scan_id, started_at, completed_at, duration_ms, profile_name,
            base_score, final_score, score_classification, passed_count,
            failed_count, unknown_count, findings_count, completed_successfully, status_message
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    )SQL";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_db, scanSql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::string err = sqlite3_errmsg(m_db);
        sqlite3_exec(m_db, "ROLLBACK;", nullptr, nullptr, nullptr);
        return core::Result<bool>::failure(core::ErrorCode::SystemError, err);
    }

    auto startMs = std::chrono::duration_cast<std::chrono::milliseconds>(scan.startedAt.time_since_epoch()).count();
    auto endMs = std::chrono::duration_cast<std::chrono::milliseconds>(scan.completedAt.time_since_epoch()).count();
    auto durMs = scan.duration().count();

    std::string scoreClass = "MODERATE RISK";
    int fs = scan.scoreBreakdown.finalScore;
    if (fs >= 90) scoreClass = "EXCELLENT";
    else if (fs >= 75) scoreClass = "GOOD";
    else if (fs >= 50) scoreClass = "MODERATE RISK";
    else scoreClass = "HIGH RISK";

    sqlite3_bind_text(stmt, 1, scan.scanId.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(startMs));
    sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(endMs));
    sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(durMs));
    sqlite3_bind_text(stmt, 5, scan.profileName.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 6, scan.scoreBreakdown.baseScore);
    sqlite3_bind_int(stmt, 7, scan.scoreBreakdown.finalScore);
    sqlite3_bind_text(stmt, 8, scoreClass.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 9, static_cast<sqlite3_int64>(scan.passedCount()));
    sqlite3_bind_int64(stmt, 10, static_cast<sqlite3_int64>(scan.failedCount()));
    sqlite3_bind_int64(stmt, 11, static_cast<sqlite3_int64>(scan.unknownCount()));
    sqlite3_bind_int64(stmt, 12, static_cast<sqlite3_int64>(scan.findings.size()));
    sqlite3_bind_int(stmt, 13, scan.completedSuccessfully ? 1 : 0);
    sqlite3_bind_text(stmt, 14, scan.statusMessage.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::string err = sqlite3_errmsg(m_db);
        sqlite3_finalize(stmt);
        sqlite3_exec(m_db, "ROLLBACK;", nullptr, nullptr, nullptr);
        return core::Result<bool>::failure(core::ErrorCode::SystemError, "Failed to insert scan: " + err);
    }
    sqlite3_finalize(stmt);

    // Insert findings
    FindingRepository findingRepo(m_db);
    auto fRes = findingRepo.insertFindings(scan.scanId, scan.findings);
    if (!fRes.isSuccess()) {
        sqlite3_exec(m_db, "ROLLBACK;", nullptr, nullptr, nullptr);
        return fRes;
    }

    // Insert collector statuses
    const char* colSql = R"SQL(
        INSERT INTO collector_status_records (
            scan_id, collector_id, status_code, message, native_error_code
        ) VALUES (?, ?, ?, ?, ?);
    )SQL";

    sqlite3_stmt* colStmt = nullptr;
    if (sqlite3_prepare_v2(m_db, colSql, -1, &colStmt, nullptr) == SQLITE_OK) {
        for (const auto& col : scan.collectorStatuses) {
            sqlite3_reset(colStmt);
            sqlite3_clear_bindings(colStmt);

            sqlite3_bind_text(colStmt, 1, scan.scanId.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(colStmt, 2, col.collectorId.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(colStmt, 3, static_cast<int>(col.status));
            sqlite3_bind_text(colStmt, 4, col.message.c_str(), -1, SQLITE_TRANSIENT);
            if (col.nativeErrorCode.has_value()) {
                sqlite3_bind_int64(colStmt, 5, col.nativeErrorCode.value());
            } else {
                sqlite3_bind_null(colStmt, 5);
            }
            sqlite3_step(colStmt);
        }
        sqlite3_finalize(colStmt);
    }

    // Commit transaction
    if (sqlite3_exec(m_db, "COMMIT;", nullptr, nullptr, &zErrMsg) != SQLITE_OK) {
        std::string err = zErrMsg ? zErrMsg : "Failed to commit transaction";
        sqlite3_free(zErrMsg);
        sqlite3_exec(m_db, "ROLLBACK;", nullptr, nullptr, nullptr);
        return core::Result<bool>::failure(core::ErrorCode::SystemError, err);
    }

    LOG_INFO("Scan record and findings persisted successfully for scanId: " + scan.scanId);
    return core::Result<bool>::success(true);
}

core::Result<std::vector<ScanRecordSummary>> ScanRepository::getRecentScans(int limit) {
    if (!m_db) {
        return core::Result<std::vector<ScanRecordSummary>>::failure(core::ErrorCode::SystemError, "Null database pointer");
    }

    const char* sql = R"SQL(
        SELECT scan_id, started_at, completed_at, duration_ms, profile_name,
               final_score, score_classification, passed_count, failed_count,
               unknown_count, findings_count, completed_successfully, status_message
        FROM scans
        ORDER BY completed_at DESC
        LIMIT ?;
    )SQL";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return core::Result<std::vector<ScanRecordSummary>>::failure(core::ErrorCode::SystemError, sqlite3_errmsg(m_db));
    }

    sqlite3_bind_int(stmt, 1, limit);

    std::vector<ScanRecordSummary> list;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ScanRecordSummary s;
        s.scanId = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        s.startedAt = std::chrono::system_clock::time_point(std::chrono::milliseconds(sqlite3_column_int64(stmt, 1)));
        s.completedAt = std::chrono::system_clock::time_point(std::chrono::milliseconds(sqlite3_column_int64(stmt, 2)));
        s.durationMs = sqlite3_column_int64(stmt, 3);
        s.profileName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        s.finalScore = sqlite3_column_int(stmt, 5);
        s.scoreClassification = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        s.passedCount = static_cast<size_t>(sqlite3_column_int64(stmt, 7));
        s.failedCount = static_cast<size_t>(sqlite3_column_int64(stmt, 8));
        s.unknownCount = static_cast<size_t>(sqlite3_column_int64(stmt, 9));
        s.findingsCount = static_cast<size_t>(sqlite3_column_int64(stmt, 10));
        s.completedSuccessfully = sqlite3_column_int(stmt, 11) != 0;
        
        const char* msg = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 12));
        if (msg) s.statusMessage = msg;

        list.push_back(std::move(s));
    }

    sqlite3_finalize(stmt);
    return core::Result<std::vector<ScanRecordSummary>>::success(std::move(list));
}

core::Result<std::optional<core::ScanResult>> ScanRepository::getScanById(const std::string& scanId) {
    if (!m_db) {
        return core::Result<std::optional<core::ScanResult>>::failure(core::ErrorCode::SystemError, "Null database pointer");
    }

    const char* sql = R"SQL(
        SELECT scan_id, started_at, completed_at, profile_name,
               base_score, final_score, completed_successfully, status_message
        FROM scans
        WHERE scan_id = ?;
    )SQL";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return core::Result<std::optional<core::ScanResult>>::failure(core::ErrorCode::SystemError, sqlite3_errmsg(m_db));
    }

    sqlite3_bind_text(stmt, 1, scanId.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return core::Result<std::optional<core::ScanResult>>::success(std::nullopt);
    }

    core::ScanResult result;
    result.scanId = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    result.startedAt = std::chrono::system_clock::time_point(std::chrono::milliseconds(sqlite3_column_int64(stmt, 1)));
    result.completedAt = std::chrono::system_clock::time_point(std::chrono::milliseconds(sqlite3_column_int64(stmt, 2)));
    result.profileName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
    
    int baseScore = sqlite3_column_int(stmt, 4);
    result.completedSuccessfully = sqlite3_column_int(stmt, 6) != 0;
    const char* msg = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
    if (msg) result.statusMessage = msg;

    sqlite3_finalize(stmt);

    // Fetch findings
    FindingRepository findingRepo(m_db);
    auto fRes = findingRepo.getFindingsForScan(scanId);
    if (!fRes.isSuccess()) {
        return core::Result<std::optional<core::ScanResult>>::failure(fRes.code(), fRes.errorMessage());
    }
    result.findings = fRes.value();

    // Reconstruct score breakdown deterministically from findings
    result.scoreBreakdown = core::SecurityScoreCalculator::calculate(result.findings, baseScore);

    // Fetch collector statuses
    const char* colSql = R"SQL(
        SELECT collector_id, status_code, message, native_error_code
        FROM collector_status_records
        WHERE scan_id = ?
        ORDER BY id ASC;
    )SQL";

    sqlite3_stmt* colStmt = nullptr;
    if (sqlite3_prepare_v2(m_db, colSql, -1, &colStmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(colStmt, 1, scanId.c_str(), -1, SQLITE_TRANSIENT);
        while (sqlite3_step(colStmt) == SQLITE_ROW) {
            core::CollectorStatus st;
            st.collectorId = reinterpret_cast<const char*>(sqlite3_column_text(colStmt, 0));
            st.status = static_cast<core::ErrorCode>(sqlite3_column_int(colStmt, 1));
            const char* cmsg = reinterpret_cast<const char*>(sqlite3_column_text(colStmt, 2));
            if (cmsg) st.message = cmsg;
            if (sqlite3_column_type(colStmt, 3) != SQLITE_NULL) {
                st.nativeErrorCode = sqlite3_column_int64(colStmt, 3);
            }
            result.collectorStatuses.push_back(std::move(st));
        }
        sqlite3_finalize(colStmt);
    }

    return core::Result<std::optional<core::ScanResult>>::success(std::move(result));
}

core::Result<bool> ScanRepository::deleteScan(const std::string& scanId) {
    if (!m_db) {
        return core::Result<bool>::failure(core::ErrorCode::SystemError, "Null database pointer");
    }

    const char* sql = "DELETE FROM scans WHERE scan_id = ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return core::Result<bool>::failure(core::ErrorCode::SystemError, sqlite3_errmsg(m_db));
    }

    sqlite3_bind_text(stmt, 1, scanId.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        return core::Result<bool>::failure(core::ErrorCode::SystemError, sqlite3_errmsg(m_db));
    }

    LOG_INFO("Deleted scan record: " + scanId);
    return core::Result<bool>::success(true);
}

core::Result<bool> ScanRepository::clearAllScans() {
    if (!m_db) {
        return core::Result<bool>::failure(core::ErrorCode::SystemError, "Null database pointer");
    }

    char* zErrMsg = nullptr;
    int rc = sqlite3_exec(m_db, "DELETE FROM scans;", nullptr, nullptr, &zErrMsg);
    if (rc != SQLITE_OK) {
        std::string err = zErrMsg ? zErrMsg : "Error clearing scans";
        sqlite3_free(zErrMsg);
        return core::Result<bool>::failure(core::ErrorCode::SystemError, err);
    }

    LOG_INFO("All scan records cleared from database.");
    return core::Result<bool>::success(true);
}

} // namespace sentinel::storage
