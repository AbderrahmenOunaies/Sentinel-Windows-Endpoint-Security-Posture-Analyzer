#pragma once

#include "DatabaseManager.h"
#include "DatabaseMigrator.h"
#include "ScanRepository.h"
#include "FindingRepository.h"
#include "SettingsRepository.h"
#include "core/Result.h"

#include <memory>
#include <mutex>

namespace sentinel::storage {

class PersistenceService {
public:
    static PersistenceService& instance();

    ~PersistenceService() = default;

    // Prevent copy/move
    PersistenceService(const PersistenceService&) = delete;
    PersistenceService& operator=(const PersistenceService&) = delete;
    PersistenceService(PersistenceService&&) = delete;
    PersistenceService& operator=(PersistenceService&&) = delete;

    [[nodiscard]] core::Result<bool> initialize(const std::string& customPath = "");
    void shutdown();

    [[nodiscard]] bool isAvailable() const noexcept;

    // Repositories
    [[nodiscard]] core::Result<bool> saveScan(const core::ScanResult& scan);
    [[nodiscard]] core::Result<std::vector<ScanRecordSummary>> getRecentScans(int limit = 50);
    [[nodiscard]] core::Result<std::optional<core::ScanResult>> getScanById(const std::string& scanId);
    [[nodiscard]] core::Result<bool> deleteScan(const std::string& scanId);
    [[nodiscard]] core::Result<bool> clearAllScans();

    [[nodiscard]] core::Result<bool> setSetting(const std::string& key, const std::string& value);
    [[nodiscard]] core::Result<std::optional<std::string>> getSetting(const std::string& key);

private:
    PersistenceService() = default;

    mutable std::mutex m_mutex;
    bool m_initialized{false};
};

} // namespace sentinel::storage
