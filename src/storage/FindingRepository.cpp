#include "FindingRepository.h"
#include "core/Logger.h"
#include <chrono>

namespace sentinel::storage {

FindingRepository::FindingRepository(sqlite3* db)
    : m_db(db) {}

core::Result<bool> FindingRepository::insertFindings(const std::string& scanId, const std::vector<core::Finding>& findings) {
    if (!m_db) {
        return core::Result<bool>::failure(core::ErrorCode::SystemError, "Null database pointer");
    }

    const char* findSql = R"SQL(
        INSERT INTO findings (
            id, scan_id, rule_id, title, severity, category, description,
            impact, recommendation, remediation_available, remediation_id, detected_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    )SQL";

    const char* evSql = R"SQL(
        INSERT INTO evidence (finding_id, source, key, value)
        VALUES (?, ?, ?, ?);
    )SQL";

    sqlite3_stmt* findStmt = nullptr;
    sqlite3_stmt* evStmt = nullptr;

    if (sqlite3_prepare_v2(m_db, findSql, -1, &findStmt, nullptr) != SQLITE_OK) {
        return core::Result<bool>::failure(core::ErrorCode::SystemError, sqlite3_errmsg(m_db));
    }

    if (sqlite3_prepare_v2(m_db, evSql, -1, &evStmt, nullptr) != SQLITE_OK) {
        sqlite3_finalize(findStmt);
        return core::Result<bool>::failure(core::ErrorCode::SystemError, sqlite3_errmsg(m_db));
    }

    for (const auto& f : findings) {
        sqlite3_reset(findStmt);
        sqlite3_clear_bindings(findStmt);

        auto detectedMs = std::chrono::duration_cast<std::chrono::milliseconds>(f.detectedAt.time_since_epoch()).count();
        std::string sevStr(core::severityToString(f.severity));

        sqlite3_bind_text(findStmt, 1, f.id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(findStmt, 2, scanId.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(findStmt, 3, f.ruleId.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(findStmt, 4, f.title.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(findStmt, 5, sevStr.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(findStmt, 6, f.category.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(findStmt, 7, f.description.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(findStmt, 8, f.impact.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(findStmt, 9, f.recommendation.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(findStmt, 10, f.remediationAvailable ? 1 : 0);
        sqlite3_bind_text(findStmt, 11, f.remediationId.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(findStmt, 12, static_cast<sqlite3_int64>(detectedMs));

        if (sqlite3_step(findStmt) != SQLITE_DONE) {
            std::string err = sqlite3_errmsg(m_db);
            sqlite3_finalize(findStmt);
            sqlite3_finalize(evStmt);
            return core::Result<bool>::failure(core::ErrorCode::SystemError, "Failed to insert finding: " + err);
        }

        // Insert associated evidence
        for (const auto& ev : f.evidence) {
            sqlite3_reset(evStmt);
            sqlite3_clear_bindings(evStmt);

            sqlite3_bind_text(evStmt, 1, f.id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(evStmt, 2, ev.source.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(evStmt, 3, ev.key.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(evStmt, 4, ev.value.c_str(), -1, SQLITE_TRANSIENT);

            if (sqlite3_step(evStmt) != SQLITE_DONE) {
                std::string err = sqlite3_errmsg(m_db);
                sqlite3_finalize(findStmt);
                sqlite3_finalize(evStmt);
                return core::Result<bool>::failure(core::ErrorCode::SystemError, "Failed to insert evidence: " + err);
            }
        }
    }

    sqlite3_finalize(findStmt);
    sqlite3_finalize(evStmt);
    return core::Result<bool>::success(true);
}

core::Result<std::vector<core::Finding>> FindingRepository::getFindingsForScan(const std::string& scanId) {
    if (!m_db) {
        return core::Result<std::vector<core::Finding>>::failure(core::ErrorCode::SystemError, "Null database pointer");
    }

    const char* findSql = R"SQL(
        SELECT id, rule_id, title, severity, category, description,
               impact, recommendation, remediation_available, remediation_id, detected_at
        FROM findings
        WHERE scan_id = ?
        ORDER BY detected_at ASC;
    )SQL";

    const char* evSql = R"SQL(
        SELECT source, key, value
        FROM evidence
        WHERE finding_id = ?
        ORDER BY id ASC;
    )SQL";

    sqlite3_stmt* findStmt = nullptr;
    if (sqlite3_prepare_v2(m_db, findSql, -1, &findStmt, nullptr) != SQLITE_OK) {
        return core::Result<std::vector<core::Finding>>::failure(core::ErrorCode::SystemError, sqlite3_errmsg(m_db));
    }

    sqlite3_stmt* evStmt = nullptr;
    if (sqlite3_prepare_v2(m_db, evSql, -1, &evStmt, nullptr) != SQLITE_OK) {
        sqlite3_finalize(findStmt);
        return core::Result<std::vector<core::Finding>>::failure(core::ErrorCode::SystemError, sqlite3_errmsg(m_db));
    }

    sqlite3_bind_text(findStmt, 1, scanId.c_str(), -1, SQLITE_TRANSIENT);

    std::vector<core::Finding> findings;
    while (sqlite3_step(findStmt) == SQLITE_ROW) {
        core::Finding f;
        f.id = reinterpret_cast<const char*>(sqlite3_column_text(findStmt, 0));
        f.ruleId = reinterpret_cast<const char*>(sqlite3_column_text(findStmt, 1));
        f.title = reinterpret_cast<const char*>(sqlite3_column_text(findStmt, 2));

        const char* sevText = reinterpret_cast<const char*>(sqlite3_column_text(findStmt, 3));
        if (sevText) {
            f.severity = core::severityFromString(sevText);
        }

        f.category = reinterpret_cast<const char*>(sqlite3_column_text(findStmt, 4));
        f.description = reinterpret_cast<const char*>(sqlite3_column_text(findStmt, 5));
        
        const char* impactText = reinterpret_cast<const char*>(sqlite3_column_text(findStmt, 6));
        if (impactText) f.impact = impactText;

        const char* recText = reinterpret_cast<const char*>(sqlite3_column_text(findStmt, 7));
        if (recText) f.recommendation = recText;

        f.remediationAvailable = sqlite3_column_int(findStmt, 8) != 0;

        const char* remId = reinterpret_cast<const char*>(sqlite3_column_text(findStmt, 9));
        if (remId) f.remediationId = remId;

        sqlite3_int64 detectedMs = sqlite3_column_int64(findStmt, 10);
        f.detectedAt = std::chrono::system_clock::time_point(std::chrono::milliseconds(detectedMs));

        // Query evidence for this finding
        sqlite3_reset(evStmt);
        sqlite3_clear_bindings(evStmt);
        sqlite3_bind_text(evStmt, 1, f.id.c_str(), -1, SQLITE_TRANSIENT);

        while (sqlite3_step(evStmt) == SQLITE_ROW) {
            core::Evidence ev;
            ev.source = reinterpret_cast<const char*>(sqlite3_column_text(evStmt, 0));
            ev.key = reinterpret_cast<const char*>(sqlite3_column_text(evStmt, 1));
            ev.value = reinterpret_cast<const char*>(sqlite3_column_text(evStmt, 2));
            f.evidence.push_back(std::move(ev));
        }

        findings.push_back(std::move(f));
    }

    sqlite3_finalize(findStmt);
    sqlite3_finalize(evStmt);

    return core::Result<std::vector<core::Finding>>::success(std::move(findings));
}

} // namespace sentinel::storage
