#include "DashboardWidget.h"
#include "core/Logger.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QDateTime>
#include <format>

namespace sentinel::ui {

DashboardWidget::DashboardWidget(QWidget *parent)
    : QWidget(parent) {
    setupUi();
}

void DashboardWidget::setupUi() {
    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(20, 20, 20, 20);
    mainLayout->setSpacing(18);

    // Control Bar
    auto* controlCard = new QFrame(this);
    controlCard->setStyleSheet(
        "background-color: #141721; border: 1px solid #232936; border-radius: 10px; padding: 12px 18px;"
    );
    auto* controlLayout = new QHBoxLayout(controlCard);
    controlLayout->setContentsMargins(12, 8, 12, 8);

    auto* profileLbl = new QLabel("Security Profile:", controlCard);
    profileLbl->setStyleSheet("color: #a0aec0; font-size: 13px; font-weight: 600;");

    m_profileCombo = new QComboBox(controlCard);
    m_profileCombo->addItem("Standard", static_cast<int>(core::ProfileType::Standard));
    m_profileCombo->addItem("Developer", static_cast<int>(core::ProfileType::Developer));
    m_profileCombo->addItem("High Security", static_cast<int>(core::ProfileType::HighSecurity));
    m_profileCombo->setStyleSheet(
        "QComboBox {"
        "  background-color: #1a202c;"
        "  color: #e2e8f0;"
        "  border: 1px solid #2d3748;"
        "  border-radius: 6px;"
        "  padding: 6px 12px;"
        "  font-size: 13px;"
        "  min-width: 140px;"
        "}"
        "QComboBox QAbstractItemView {"
        "  background-color: #1a202c;"
        "  color: #e2e8f0;"
        "  selection-background-color: #2b6cb0;"
        "}"
    );

    m_scanButton = new QPushButton("RUN SECURITY SCAN", controlCard);
    m_scanButton->setCursor(Qt::PointingHandCursor);
    m_scanButton->setStyleSheet(
        "QPushButton {"
        "  background-color: #2b6cb0;"
        "  color: #ffffff;"
        "  border: none;"
        "  border-radius: 6px;"
        "  padding: 10px 24px;"
        "  font-size: 13px;"
        "  font-weight: bold;"
        "  letter-spacing: 0.5px;"
        "}"
        "QPushButton:hover {"
        "  background-color: #3182ce;"
        "}"
        "QPushButton:disabled {"
        "  background-color: #1e2533;"
        "  color: #718096;"
        "}"
    );
    auto* historyButton = new QPushButton("SCAN HISTORY", controlCard);
    historyButton->setCursor(Qt::PointingHandCursor);
    historyButton->setStyleSheet(
        "QPushButton {"
        "  background-color: #1a202c;"
        "  color: #cbd5e0;"
        "  border: 1px solid #2d3748;"
        "  border-radius: 6px;"
        "  padding: 10px 18px;"
        "  font-size: 13px;"
        "  font-weight: bold;"
        "}"
        "QPushButton:hover {"
        "  background-color: #2d3748;"
        "  color: #ffffff;"
        "}"
    );
    connect(historyButton, &QPushButton::clicked, this, &DashboardWidget::viewHistoryRequested);

    controlLayout->addWidget(profileLbl);
    controlLayout->addWidget(m_profileCombo);
    controlLayout->addStretch();
    controlLayout->addWidget(historyButton);
    controlLayout->addWidget(m_scanButton);
    mainLayout->addWidget(controlCard);

    // Progress Bar
    m_progressWidget = new ScanProgressWidget(this);
    connect(m_progressWidget, &ScanProgressWidget::cancelRequested, this, &DashboardWidget::cancelScanRequested);
    mainLayout->addWidget(m_progressWidget);

    // Top Section: Score + Stats
    auto* topSection = new QHBoxLayout();
    topSection->setSpacing(16);

    m_scoreWidget = new ScoreWidget(this);
    m_scoreWidget->setFixedWidth(280);
    connect(m_scoreWidget, &ScoreWidget::breakdownRequested, this, &DashboardWidget::handleBreakdownRequested);
    topSection->addWidget(m_scoreWidget);

    // Stats Card
    auto* statsCard = new QFrame(this);
    statsCard->setStyleSheet("background-color: #141721; border: 1px solid #232936; border-radius: 12px; padding: 16px;");
    auto* statsLayout = new QVBoxLayout(statsCard);
    statsLayout->setContentsMargins(16, 16, 16, 16);

    auto* statsTitle = new QLabel("EVALUATION OUTCOMES", statsCard);
    statsTitle->setStyleSheet("color: #718096; font-size: 12px; font-weight: bold; letter-spacing: 1px;");
    statsLayout->addWidget(statsTitle);

    auto* countRow = new QHBoxLayout();
    countRow->setSpacing(20);

    auto createCountBox = [statsCard](const QString& title, const QString& initialVal, const QString& color) -> QLabel* {
        auto* box = new QFrame(statsCard);
        box->setStyleSheet("background-color: #0d1117; border: 1px solid #232936; border-radius: 8px; padding: 10px;");
        auto* boxLayout = new QVBoxLayout(box);
        boxLayout->setContentsMargins(8, 6, 8, 6);
        boxLayout->setSpacing(4);

        auto* valLbl = new QLabel(initialVal, box);
        valLbl->setStyleSheet(QString("color: %1; font-size: 22px; font-weight: bold;").arg(color));
        valLbl->setAlignment(Qt::AlignCenter);

        auto* titleLbl = new QLabel(title, box);
        titleLbl->setStyleSheet("color: #718096; font-size: 11px; font-weight: 600;");
        titleLbl->setAlignment(Qt::AlignCenter);

        boxLayout->addWidget(valLbl);
        boxLayout->addWidget(titleLbl);
        return valLbl;
    };

    m_passedLabel = createCountBox("PASSED", "0", "#48bb78");
    m_failedLabel = createCountBox("FAILED", "0", "#f56565");
    m_unknownLabel = createCountBox("UNKNOWN", "0", "#ecc94b");
    m_findingsCountLabel = createCountBox("FINDINGS", "0", "#ed8936");

    countRow->addWidget(m_passedLabel->parentWidget());
    countRow->addWidget(m_failedLabel->parentWidget());
    countRow->addWidget(m_unknownLabel->parentWidget());
    countRow->addWidget(m_findingsCountLabel->parentWidget());
    statsLayout->addLayout(countRow);

    m_metaLabel = new QLabel("Last scan: Never  |  Duration: --", statsCard);
    m_metaLabel->setStyleSheet("color: #718096; font-size: 12px; padding-top: 4px;");
    statsLayout->addWidget(m_metaLabel);

    topSection->addWidget(statsCard);
    mainLayout->addLayout(topSection);

    // Middle Section: Category Summary & Collector Status
    auto* midSection = new QHBoxLayout();
    midSection->setSpacing(16);

    m_categoryWidget = new CategorySummaryWidget(this);
    midSection->addWidget(m_categoryWidget, 2);

    m_collectorStatusWidget = new CollectorStatusWidget(this);
    m_collectorStatusWidget->setFixedWidth(320);
    midSection->addWidget(m_collectorStatusWidget, 1);

    mainLayout->addLayout(midSection);

    // Bottom Section: Findings Table
    m_findingsWidget = new FindingsWidget(this);
    connect(m_findingsWidget, &FindingsWidget::findingSelected, this, &DashboardWidget::handleFindingSelected);
    mainLayout->addWidget(m_findingsWidget, 1);
}

core::ProfileType DashboardWidget::selectedProfile() const {
    return static_cast<core::ProfileType>(m_profileCombo->currentData().toInt());
}

void DashboardWidget::setScanRunning(bool running) {
    m_scanButton->setEnabled(!running);
    m_profileCombo->setEnabled(!running);
    if (running) {
        m_scanButton->setText("SCANNING...");
    } else {
        m_scanButton->setText("RUN SECURITY SCAN");
    }
}

void DashboardWidget::updateProgress(int percentage, const QString& stage) {
    m_progressWidget->setProgress(percentage, stage);
}

void DashboardWidget::setScanResult(const core::ScanResult& result) {
    m_lastResult = result;
    m_progressWidget->reset();

    // 1. Update score widget
    m_scoreWidget->setScore(result.scoreBreakdown);

    // 2. Update stats
    m_passedLabel->setText(QString::number(result.passedCount()));
    m_failedLabel->setText(QString::number(result.failedCount()));
    m_unknownLabel->setText(QString::number(result.unknownCount()));
    m_findingsCountLabel->setText(QString::number(result.findings.size()));

    auto durationSec = static_cast<double>(result.duration().count()) / 1000.0;
    auto startMs = std::chrono::duration_cast<std::chrono::milliseconds>(result.startedAt.time_since_epoch()).count();
    auto startDt = QDateTime::fromMSecsSinceEpoch(startMs);
    m_metaLabel->setText(QString("Last scan: %1  |  Duration: %2s  |  Profile: %3")
                             .arg(startDt.toString("dd MMM yyyy hh:mm:ss"))
                             .arg(durationSec, 0, 'f', 2)
                             .arg(QString::fromStdString(result.profileName)));

    // 3. Update category breakdown
    m_categoryWidget->setEvaluations(result.evaluations);

    // 4. Update collector status
    m_collectorStatusWidget->setStatuses(result.collectorStatuses);

    // 5. Update findings
    m_findingsWidget->setFindings(result.findings);
}

void DashboardWidget::reset() {
    m_progressWidget->reset();
    m_scoreWidget->reset();
    m_passedLabel->setText("0");
    m_failedLabel->setText("0");
    m_unknownLabel->setText("0");
    m_findingsCountLabel->setText("0");
    m_metaLabel->setText("Last scan: Never  |  Duration: --");
    m_categoryWidget->reset();
    m_collectorStatusWidget->reset();
    m_findingsWidget->reset();
}

void DashboardWidget::handleBreakdownRequested() {
    ScoreBreakdownDialog dlg(m_lastResult.scoreBreakdown, this);
    dlg.exec();
}

void DashboardWidget::handleFindingSelected(const core::Finding& finding) {
    FindingDetailDialog dlg(finding, this);
    connect(&dlg, &FindingDetailDialog::remediationRequested, this, [](const core::Finding& f) {
        LOG_INFO(std::format("User requested remediation preview for finding {} (Remediation ID: {})", f.ruleId, f.remediationId));
    });
    dlg.exec();
}

} // namespace sentinel::ui
