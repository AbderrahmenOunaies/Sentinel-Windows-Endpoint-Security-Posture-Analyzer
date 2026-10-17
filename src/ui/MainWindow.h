#pragma once

#include "app/ScanController.h"
#include "DashboardWidget.h"
#include <QMainWindow>
#include <QLabel>
#include <memory>

namespace sentinel::ui {

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override = default;

private slots:
    void handleStartScan();
    void handleCancelScan();
    void handleScanStarted();
    void handleProgressChanged(int percentage);
    void handleStageChanged(const QString& stage);
    void handleScanCompleted(const core::ScanResult& result);
    void handleScanFailed(const QString& error);
    void handleScanCancelled();
    void handleViewHistory();
    void handleLoadHistoricalScan(const std::string& scanId);

private:
    void setupUi();
    void updatePrivilegeStatus();

    QLabel* m_privilegeBadge{nullptr};
    QLabel* m_hostLabel{nullptr};
    DashboardWidget* m_dashboard{nullptr};

    std::unique_ptr<app::ScanController> m_scanController;
};

} // namespace sentinel::ui
