#include "PersistenceService.h"
#include "core/Logger.h"

namespace sentinel::storage {

PersistenceService& PersistenceService::instance() {
    static PersistenceService instance;
    return instance;
}

core::Result<bool> PersistenceService::initialize(const std::string& customPath) {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto initRes = DatabaseManager::instance().initialize(customPath);
    if (!initRes.isSuccess()) {
        LOG_ERROR("PersistenceService initialization failed: " + initRes.errorMessage());
        return initRes;
    }

    auto migRes = DatabaseMigrator::migrate(DatabaseManager::instance().handle());
    if (!migRes.isSuccess()) {
        LOG_ERROR("PersistenceService schema migration failed: " + migRes.errorMessage());
        DatabaseManager::instance().close();
        return migRes;
    }

    m_initialized = true;
    LOG_INFO("PersistenceService ready and verified.");
    return core::Result<bool>::success(true);
}

void PersistenceService::shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_initialized) {
        DatabaseManager::instance().close();
        m_initialized = false;
        LOG_INFO("PersistenceService shutdown complete.");
    }
}

bool PersistenceService::isAvailable() const noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_initialized && DatabaseManager::instance().isOpen();
}

core::Result<bool> PersistenceService::saveScan(const core::ScanResult& scan) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_initialized || !DatabaseManager::instance().isOpen()) {
        return core::Result<bool>::failure(core::ErrorCode::SystemError, "Persistence database not available");
    }

    ScanRepository repo(DatabaseManager::instance().handle());
    return repo.insertScan(scan);
}

core::Result<std::vector<ScanRecordSummary>> PersistenceService::getRecentScans(int limit) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_initialized || !DatabaseManager::instance().isOpen()) {
        return core::Result<std::vector<ScanRecordSummary>>::failure(core::ErrorCode::SystemError, "Persistence database not available");
    }

    ScanRepository repo(DatabaseManager::instance().handle());
    return repo.getRecentScans(limit);
}

core::Result<std::optional<core::ScanResult>> PersistenceService::getScanById(const std::string& scanId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_initialized || !DatabaseManager::instance().isOpen()) {
        return core::Result<std::optional<core::ScanResult>>::failure(core::ErrorCode::SystemError, "Persistence database not available");
    }

    ScanRepository repo(DatabaseManager::instance().handle());
    return repo.getScanById(scanId);
}

core::Result<bool> PersistenceService::deleteScan(const std::string& scanId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_initialized || !DatabaseManager::instance().isOpen()) {
        return core::Result<bool>::failure(core::ErrorCode::SystemError, "Persistence database not available");
    }

    ScanRepository repo(DatabaseManager::instance().handle());
    return repo.deleteScan(scanId);
}

core::Result<bool> PersistenceService::clearAllScans() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_initialized || !DatabaseManager::instance().isOpen()) {
        return core::Result<bool>::failure(core::ErrorCode::SystemError, "Persistence database not available");
    }

    ScanRepository repo(DatabaseManager::instance().handle());
    return repo.clearAllScans();
}

core::Result<bool> PersistenceService::setSetting(const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_initialized || !DatabaseManager::instance().isOpen()) {
        return core::Result<bool>::failure(core::ErrorCode::SystemError, "Persistence database not available");
    }

    SettingsRepository repo(DatabaseManager::instance().handle());
    return repo.setString(key, value);
}

core::Result<std::optional<std::string>> PersistenceService::getSetting(const std::string& key) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_initialized || !DatabaseManager::instance().isOpen()) {
        return core::Result<std::optional<std::string>>::failure(core::ErrorCode::SystemError, "Persistence database not available");
    }

    SettingsRepository repo(DatabaseManager::instance().handle());
    return repo.getString(key);
}

} // namespace sentinel::storage
