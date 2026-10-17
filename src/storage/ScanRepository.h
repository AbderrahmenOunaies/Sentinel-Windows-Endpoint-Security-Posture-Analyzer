#pragma once

#include "core/ScanResult.h"
#include "core/Result.h"
#include <sqlite3.h>
#include <vector>
#include <optional>

namespace sentinel::storage {

struct ScanRecordSummary {
    std::string scanId;
    std::chrono::system_clock::time_point startedAt;
    std::chrono::system_clock::time_point completedAt;
    long long durationMs{0};
    std::string profileName;
    int finalScore{100};
    std::string scoreClassification;
    size_t passedCount{0};
    size_t failedCount{0};
    size_t unknownCount{0};
    size_t findingsCount{0};
    bool completedSuccessfully{true};
    std::string statusMessage;
};

class ScanRepository {
public:
    explicit ScanRepository(sqlite3* db);

    [[nodiscard]] core::Result<bool> insertScan(const core::ScanResult& scan);
    [[nodiscard]] core::Result<std::vector<ScanRecordSummary>> getRecentScans(int limit = 50);
    [[nodiscard]] core::Result<std::optional<core::ScanResult>> getScanById(const std::string& scanId);
    [[nodiscard]] core::Result<bool> deleteScan(const std::string& scanId);
    [[nodiscard]] core::Result<bool> clearAllScans();

private:
    sqlite3* m_db{nullptr};
};

} // namespace sentinel::storage
