#include "ScanController.h"
#include "core/Logger.h"
#include "core/SecurityScore.h"
#include "collectors/SystemCollector.h"
#include "collectors/NetworkCollector.h"
#include "collectors/ServiceCollector.h"
#include "collectors/FirewallCollector.h"
#include "collectors/DefenderCollector.h"
#include "collectors/AccountCollector.h"
#include "collectors/AuthenticationCollector.h"
#include "collectors/EncryptionCollector.h"
#include "collectors/UpdateCollector.h"

#include <chrono>
#include <format>

namespace sentinel::app {

class ScanWorker : public QObject {
    Q_OBJECT

public:
    explicit ScanWorker(core::ScanConfiguration config)
        : m_config(std::move(config)) {}

    void requestCancellation() {
        m_cancelled.store(true, std::memory_order_relaxed);
    }

signals:
    void progress(int percentage, const QString& stage);
    void completed(const core::ScanResult& result);
    void failed(const QString& error);
    void cancelled();

public slots:
    void execute() {
        LOG_INFO(std::format("Scan started profile={}", m_config.profile.name));
        auto startTime = std::chrono::system_clock::now();

        core::ScanResult result;
        result.scanId = "SCAN-" + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(startTime.time_since_epoch()).count());
        result.startedAt = startTime;
        result.profileName = m_config.profile.name;

        core::SecurityContext context;

        // Check cancellation helper
        auto isCancelled = [this]() -> bool {
            return m_cancelled.load(std::memory_order_relaxed);
        };

        if (isCancelled()) {
            LOG_INFO("Scan cancelled prior to collector execution.");
            emit cancelled();
            return;
        }

        // Stage 1: System (10%)
        emit progress(10, "Collecting system facts...");
        LOG_INFO("Collector started: SystemCollector");
        collectors::SystemCollector sysCol;
        auto sysRes = sysCol.collect();
        result.collectorStatuses.push_back({
            .collectorId = "SystemCollector",
            .status = sysRes.code(),
            .message = sysRes.errorMessage(),
            .nativeErrorCode = std::nullopt
        });
        if (sysRes.isSuccess()) {
            context.system = sysRes.value();
            LOG_INFO("Collector completed: SystemCollector");
        } else {
            LOG_WARNING("Collector failed: SystemCollector: " + sysRes.errorMessage());
        }

        if (isCancelled()) { emit cancelled(); return; }

        // Stage 2: Network (20%)
        emit progress(20, "Collecting network endpoints...");
        LOG_INFO("Collector started: NetworkCollector");
        collectors::NetworkCollector netCol;
        auto netRes = netCol.collect();
        result.collectorStatuses.push_back({
            .collectorId = "NetworkCollector",
            .status = netRes.code(),
            .message = netRes.errorMessage(),
            .nativeErrorCode = std::nullopt
        });
        if (netRes.isSuccess()) {
            context.network = netRes.value();
            LOG_INFO(std::format("Collector completed: NetworkCollector endpoints={}",
                                 netRes.value().tcpEndpoints.size() + netRes.value().udpEndpoints.size()));
        } else {
            LOG_WARNING("Collector failed: NetworkCollector: " + netRes.errorMessage());
        }

        if (isCancelled()) { emit cancelled(); return; }

        // Stage 3: Services (30%)
        emit progress(30, "Collecting services...");
        LOG_INFO("Collector started: ServiceCollector");
        collectors::ServiceCollector svcCol;
        auto svcRes = svcCol.collect();
        result.collectorStatuses.push_back({
            .collectorId = "ServiceCollector",
            .status = svcRes.code(),
            .message = svcRes.errorMessage(),
            .nativeErrorCode = std::nullopt
        });
        if (svcRes.isSuccess()) {
            context.services = svcRes.value();
            LOG_INFO(std::format("Collector completed: ServiceCollector services={}", svcRes.value().services.size()));
        } else {
            LOG_WARNING("Collector failed: ServiceCollector: " + svcRes.errorMessage());
        }

        if (isCancelled()) { emit cancelled(); return; }

        // Stage 4: Firewall (40%)
        emit progress(40, "Collecting firewall profile state...");
        LOG_INFO("Collector started: FirewallCollector");
        collectors::FirewallCollector fwCol;
        auto fwRes = fwCol.collect();
        result.collectorStatuses.push_back({
            .collectorId = "FirewallCollector",
            .status = fwRes.code(),
            .message = fwRes.errorMessage(),
            .nativeErrorCode = std::nullopt
        });
        if (fwRes.isSuccess()) {
            context.firewall = fwRes.value();
            LOG_INFO("Collector completed: FirewallCollector");
        } else {
            LOG_WARNING("Collector failed: FirewallCollector: " + fwRes.errorMessage());
        }

        if (isCancelled()) { emit cancelled(); return; }

        // Stage 5: Defender (50%)
        emit progress(50, "Collecting Microsoft Defender posture...");
        LOG_INFO("Collector started: DefenderCollector");
        collectors::DefenderCollector defCol;
        auto defRes = defCol.collect();
        result.collectorStatuses.push_back({
            .collectorId = "DefenderCollector",
            .status = defRes.code(),
            .message = defRes.errorMessage(),
            .nativeErrorCode = std::nullopt
        });
        if (defRes.isSuccess()) {
            context.defender = defRes.value();
            LOG_INFO("Collector completed: DefenderCollector");
        } else {
            LOG_WARNING("Collector failed: DefenderCollector: " + defRes.errorMessage());
        }

        if (isCancelled()) { emit cancelled(); return; }

        // Stage 6: Accounts (60%)
        emit progress(60, "Collecting local account telemetry...");
        LOG_INFO("Collector started: AccountCollector");
        collectors::AccountCollector accCol;
        auto accRes = accCol.collect();
        result.collectorStatuses.push_back({
            .collectorId = "AccountCollector",
            .status = accRes.code(),
            .message = accRes.errorMessage(),
            .nativeErrorCode = std::nullopt
        });
        if (accRes.isSuccess()) {
            context.accounts = accRes.value();
            LOG_INFO(std::format("Collector completed: AccountCollector accounts={}", accRes.value().accounts.size()));
        } else {
            LOG_WARNING("Collector failed: AccountCollector: " + accRes.errorMessage());
        }

        if (isCancelled()) { emit cancelled(); return; }

        // Stage 7: Authentication (70%)
        emit progress(70, "Collecting password and lockout policies...");
        LOG_INFO("Collector started: AuthenticationCollector");
        collectors::AuthenticationCollector authCol;
        auto authRes = authCol.collect();
        result.collectorStatuses.push_back({
            .collectorId = "AuthenticationCollector",
            .status = authRes.code(),
            .message = authRes.errorMessage(),
            .nativeErrorCode = std::nullopt
        });
        if (authRes.isSuccess()) {
            context.authentication = authRes.value();
            LOG_INFO("Collector completed: AuthenticationCollector");
        } else {
            LOG_WARNING("Collector failed: AuthenticationCollector: " + authRes.errorMessage());
        }

        if (isCancelled()) { emit cancelled(); return; }

        // Stage 8: Encryption (78%)
        emit progress(78, "Collecting storage encryption status...");
        LOG_INFO("Collector started: EncryptionCollector");
        collectors::EncryptionCollector encCol;
        auto encRes = encCol.collect();
        result.collectorStatuses.push_back({
            .collectorId = "EncryptionCollector",
            .status = encRes.code(),
            .message = encRes.errorMessage(),
            .nativeErrorCode = std::nullopt
        });
        if (encRes.isSuccess()) {
            context.encryption = encRes.value();
            LOG_INFO("Collector completed: EncryptionCollector");
        } else {
            LOG_WARNING("Collector failed: EncryptionCollector: " + encRes.errorMessage());
        }

        if (isCancelled()) { emit cancelled(); return; }

        // Stage 9: Updates (86%)
        emit progress(86, "Collecting system update state...");
        LOG_INFO("Collector started: UpdateCollector");
        collectors::UpdateCollector updCol;
        auto updRes = updCol.collect();
        result.collectorStatuses.push_back({
            .collectorId = "UpdateCollector",
            .status = updRes.code(),
            .message = updRes.errorMessage(),
            .nativeErrorCode = std::nullopt
        });
        if (updRes.isSuccess()) {
            context.updates = updRes.value();
            LOG_INFO("Collector completed: UpdateCollector");
        } else {
            LOG_WARNING("Collector failed: UpdateCollector: " + updRes.errorMessage());
        }

        if (isCancelled()) { emit cancelled(); return; }

        // Stage 10: Rule Evaluation (94%)
        emit progress(94, "Evaluating security rules...");
        LOG_INFO("Rule evaluation started");
        rules::RuleEngine engine;
        auto evalResult = engine.evaluate(context, m_config.profile);
        result.evaluations = std::move(evalResult.evaluations);
        result.findings = std::move(evalResult.findings);
        LOG_INFO(std::format("RuleEngine completed: rules={} findings={}",
                             result.evaluations.size(), result.findings.size()));

        if (isCancelled()) { emit cancelled(); return; }

        // Stage 11: Score Calculation & Finalize (98%)
        emit progress(98, "Calculating security score...");
        result.scoreBreakdown = core::SecurityScoreCalculator::calculate(result.findings);

        auto endTime = std::chrono::system_clock::now();
        result.completedAt = endTime;
        result.completedSuccessfully = true;
        result.statusMessage = "Scan completed successfully.";

        auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
        LOG_INFO(std::format("Scan completed score={} findings={} duration_ms={}",
                             result.scoreBreakdown.finalScore, result.findings.size(), durationMs));

        emit progress(100, "Scan complete.");
        emit completed(result);
    }

private:
    core::ScanConfiguration m_config;
    std::atomic<bool> m_cancelled{false};
};

ScanController::ScanController(QObject *parent)
    : QObject(parent) {
    qRegisterMetaType<core::ScanResult>("core::ScanResult");
}

ScanController::~ScanController() {
    cancelScan();
    cleanupThread();
}

bool ScanController::isRunning() const noexcept {
    return m_running.load(std::memory_order_relaxed);
}

void ScanController::startScan(const core::ScanConfiguration& config) {
    if (m_running.load(std::memory_order_relaxed)) {
        LOG_WARNING("ScanController::startScan ignored: a scan is already running.");
        return;
    }

    m_running.store(true, std::memory_order_relaxed);
    emit scanStarted();

    cleanupThread();

    m_workerThread = new QThread(this);
    m_worker = new ScanWorker(config);
    m_worker->moveToThread(m_workerThread);

    connect(m_workerThread, &QThread::started, m_worker, &ScanWorker::execute);
    connect(m_worker, &ScanWorker::progress, this, &ScanController::handleWorkerProgress);
    connect(m_worker, &ScanWorker::completed, this, &ScanController::handleWorkerCompleted);
    connect(m_worker, &ScanWorker::failed, this, &ScanController::handleWorkerFailed);
    connect(m_worker, &ScanWorker::cancelled, this, &ScanController::handleWorkerCancelled);

    connect(m_worker, &ScanWorker::completed, m_workerThread, &QThread::quit);
    connect(m_worker, &ScanWorker::failed, m_workerThread, &QThread::quit);
    connect(m_worker, &ScanWorker::cancelled, m_workerThread, &QThread::quit);

    m_workerThread->start();
}

void ScanController::cancelScan() {
    if (m_running.load(std::memory_order_relaxed) && m_worker) {
        LOG_INFO("ScanController: Cancellation requested.");
        m_worker->requestCancellation();
    }
}

void ScanController::handleWorkerProgress(int percentage, const QString& stage) {
    emit progressChanged(percentage);
    emit stageChanged(stage);
}

void ScanController::handleWorkerCompleted(const core::ScanResult& result) {
    m_running.store(false, std::memory_order_relaxed);
    emit scanCompleted(result);
}

void ScanController::handleWorkerFailed(const QString& error) {
    m_running.store(false, std::memory_order_relaxed);
    emit scanFailed(error);
}

void ScanController::handleWorkerCancelled() {
    m_running.store(false, std::memory_order_relaxed);
    emit scanCancelled();
}

void ScanController::cleanupThread() {
    if (m_workerThread) {
        if (m_workerThread->isRunning()) {
            m_workerThread->quit();
            m_workerThread->wait(1500);
        }
        delete m_worker;
        m_worker = nullptr;
        delete m_workerThread;
        m_workerThread = nullptr;
    }
}

} // namespace sentinel::app

#include "ScanController.moc"
