#include "MainWindow.h"
#include "ScanHistoryDialog.h"
#include "storage/PersistenceService.h"
#include "platform/windows/SystemInfo.h"
#include "core/Logger.h"

#include <QWidget>
#include <QFrame>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFont>
#include <QTimer>
#include <QMessageBox>

namespace sentinel::ui {

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , m_scanController(std::make_unique<app::ScanController>(this)) {
    setupUi();

    connect(m_dashboard, &DashboardWidget::runScanRequested, this, &MainWindow::handleStartScan);
    connect(m_dashboard, &DashboardWidget::cancelScanRequested, this, &MainWindow::handleCancelScan);
    connect(m_dashboard, &DashboardWidget::viewHistoryRequested, this, &MainWindow::handleViewHistory);

    connect(m_scanController.get(), &app::ScanController::scanStarted, this, &MainWindow::handleScanStarted);
    connect(m_scanController.get(), &app::ScanController::progressChanged, this, &MainWindow::handleProgressChanged);
    connect(m_scanController.get(), &app::ScanController::stageChanged, this, &MainWindow::handleStageChanged);
    connect(m_scanController.get(), &app::ScanController::scanCompleted, this, &MainWindow::handleScanCompleted);
    connect(m_scanController.get(), &app::ScanController::scanFailed, this, &MainWindow::handleScanFailed);
    connect(m_scanController.get(), &app::ScanController::scanCancelled, this, &MainWindow::handleScanCancelled);

    LOG_INFO("MainWindow initialized with Milestone 8 SQLite Persistence and Scan History.");

    QTimer::singleShot(150, this, [this]() {
        updatePrivilegeStatus();
    });
}

void MainWindow::setupUi() {
    setWindowTitle("Sentinel - Endpoint Security Posture Analyzer");
    resize(1180, 840);
    setMinimumSize(960, 680);

    auto* centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    auto* rootLayout = new QVBoxLayout(centralWidget);
    rootLayout->setContentsMargins(0, 0, 0, 0);
    rootLayout->setSpacing(0);

    // Top Navigation / Header Bar
    auto* navBar = new QFrame(centralWidget);
    navBar->setStyleSheet(
        "background-color: #10141d; border-bottom: 1px solid #1e2433; padding: 12px 24px;"
    );
    auto* navLayout = new QHBoxLayout(navBar);
    navLayout->setContentsMargins(20, 10, 20, 10);

    auto* brandLayout = new QVBoxLayout();
    brandLayout->setSpacing(2);

    auto* brandLabel = new QLabel("SENTINEL", navBar);
    QFont brandFont("Segoe UI", 16, QFont::Bold);
    brandLabel->setFont(brandFont);
    brandLabel->setStyleSheet("color: #ffffff; letter-spacing: 1.5px;");

    auto* subLabel = new QLabel("ENDPOINT SECURITY POSTURE ANALYZER", navBar);
    subLabel->setStyleSheet("color: #718096; font-size: 10px; font-weight: bold; letter-spacing: 1px;");

    brandLayout->addWidget(brandLabel);
    brandLayout->addWidget(subLabel);
    navLayout->addLayout(brandLayout);

    navLayout->addStretch();

    // Workstation info
    m_hostLabel = new QLabel(QString("HOST: %1").arg(QString::fromStdString(platform::SystemInfo::getHostName())), navBar);
    m_hostLabel->setStyleSheet("color: #a0aec0; font-size: 12px; font-weight: 600; padding-right: 16px;");
    navLayout->addWidget(m_hostLabel);

    // Privilege badge
    m_privilegeBadge = new QLabel("DETECTING PRIVILEGE...", navBar);
    m_privilegeBadge->setStyleSheet(
        "background-color: #2d3748; color: #ecc94b; font-size: 11px; font-weight: bold; padding: 6px 12px; border-radius: 4px; letter-spacing: 0.5px;"
    );
    navLayout->addWidget(m_privilegeBadge);

    rootLayout->addWidget(navBar);

    // Main Dashboard Widget
    m_dashboard = new DashboardWidget(centralWidget);
    rootLayout->addWidget(m_dashboard, 1);

    setStyleSheet("background-color: #0b0e14; color: #e2e8f0;");
}

void MainWindow::updatePrivilegeStatus() {
    auto level = platform::SystemInfo::detectPrivilege();
    auto privStr = platform::SystemInfo::privilegeToString(level);

    if (level == platform::PrivilegeLevel::Administrator) {
        m_privilegeBadge->setText("ADMINISTRATOR");
        m_privilegeBadge->setStyleSheet(
            "background-color: #1c4532; color: #68d391; font-size: 11px; font-weight: bold; padding: 6px 12px; border-radius: 4px; letter-spacing: 0.5px;"
        );
        LOG_INFO("Privilege detected: ADMINISTRATOR");
    } else {
        m_privilegeBadge->setText("STANDARD USER");
        m_privilegeBadge->setStyleSheet(
            "background-color: #442a1b; color: #f6ad55; font-size: 11px; font-weight: bold; padding: 6px 12px; border-radius: 4px; letter-spacing: 0.5px;"
        );
        LOG_INFO("Privilege detected: STANDARD USER");
    }
}

void MainWindow::handleStartScan() {
    core::ScanConfiguration config;
    config.profile = core::SecurityProfile::createDefault(m_dashboard->selectedProfile());

    m_scanController->startScan(config);
}

void MainWindow::handleCancelScan() {
    m_scanController->cancelScan();
}

void MainWindow::handleScanStarted() {
    m_dashboard->setScanRunning(true);
}

void MainWindow::handleProgressChanged(int percentage) {
    // Keep stage synced
    m_dashboard->updateProgress(percentage, "");
}

void MainWindow::handleStageChanged(const QString& stage) {
    m_dashboard->updateProgress(0, stage);
}

void MainWindow::handleScanCompleted(const core::ScanResult& result) {
    m_dashboard->setScanRunning(false);
    m_dashboard->setScanResult(result);

    // Persist completed scan safely without blocking UI or corrupting in-memory result
    auto saveRes = storage::PersistenceService::instance().saveScan(result);
    if (saveRes.isSuccess()) {
        LOG_INFO("Scan result successfully saved to SQLite database.");
    } else {
        LOG_WARNING("Failed to persist scan result: " + saveRes.errorMessage());
    }
}

void MainWindow::handleScanFailed(const QString& error) {
    m_dashboard->setScanRunning(false);
    QMessageBox::critical(this, "Scan Failed", QString("The security scan failed: %1").arg(error));
}

void MainWindow::handleScanCancelled() {
    m_dashboard->setScanRunning(false);
    m_dashboard->reset();
    QMessageBox::information(this, "Scan Cancelled", "The security scan was cancelled by the user.");
}

void MainWindow::handleViewHistory() {
    ScanHistoryDialog dlg(this);
    connect(&dlg, &ScanHistoryDialog::loadScanRequested, this, &MainWindow::handleLoadHistoricalScan);
    dlg.exec();
}

void MainWindow::handleLoadHistoricalScan(const std::string& scanId) {
    auto res = storage::PersistenceService::instance().getScanById(scanId);
    if (!res.isSuccess()) {
        QMessageBox::critical(this, "Error", QString("Failed to load historical scan: %1")
                                                .arg(QString::fromStdString(res.errorMessage())));
        return;
    }

    if (!res.value().has_value()) {
        QMessageBox::warning(this, "Not Found", "The requested scan record was not found in the database.");
        return;
    }

    const auto& scan = res.value().value();
    m_dashboard->setScanResult(scan);
    LOG_INFO("Loaded historical scan into dashboard: " + scanId);
}

} // namespace sentinel::ui
