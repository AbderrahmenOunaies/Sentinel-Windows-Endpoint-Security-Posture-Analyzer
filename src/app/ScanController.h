#pragma once

#include "core/ScanResult.h"
#include "core/SecurityContext.h"
#include "rules/RuleEngine.h"

#include <QObject>
#include <QString>
#include <QThread>
#include <atomic>
#include <memory>

namespace sentinel::app {

class ScanWorker;

class ScanController : public QObject {
    Q_OBJECT

public:
    explicit ScanController(QObject *parent = nullptr);
    ~ScanController() override;

    [[nodiscard]] bool isRunning() const noexcept;
    void startScan(const core::ScanConfiguration& config);
    void cancelScan();

signals:
    void scanStarted();
    void progressChanged(int percentage);
    void stageChanged(const QString& stage);
    void scanCompleted(const core::ScanResult& result);
    void scanFailed(const QString& error);
    void scanCancelled();

private slots:
    void handleWorkerProgress(int percentage, const QString& stage);
    void handleWorkerCompleted(const core::ScanResult& result);
    void handleWorkerFailed(const QString& error);
    void handleWorkerCancelled();

private:
    void cleanupThread();

    std::atomic<bool> m_running{false};
    QThread* m_workerThread{nullptr};
    ScanWorker* m_worker{nullptr};
};

} // namespace sentinel::app
