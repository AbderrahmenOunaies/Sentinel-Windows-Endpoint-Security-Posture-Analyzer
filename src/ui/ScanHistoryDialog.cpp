#include "ScanHistoryDialog.h"
#include "core/Logger.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QDateTime>
#include <QMessageBox>
#include <QFont>

namespace sentinel::ui {

ScanHistoryDialog::ScanHistoryDialog(QWidget *parent)
    : QDialog(parent) {
    setupUi();
    loadScans();
}

void ScanHistoryDialog::setupUi() {
    setWindowTitle("Sentinel - Scan History & Audit Logs");
    resize(860, 520);
    setStyleSheet("background-color: #0b0e14; color: #e2e8f0;");

    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(20, 20, 20, 20);
    layout->setSpacing(16);

    auto* topRow = new QHBoxLayout();
    auto* title = new QLabel("PERSISTED AUDIT HISTORY", this);
    title->setStyleSheet("color: #63b3ed; font-size: 14px; font-weight: bold; letter-spacing: 1px;");
    topRow->addWidget(title);

    topRow->addStretch();

    m_statusLabel = new QLabel("Loading history...", this);
    m_statusLabel->setStyleSheet("color: #718096; font-size: 12px;");
    topRow->addWidget(m_statusLabel);

    layout->addLayout(topRow);

    m_table = new QTableWidget(0, 7, this);
    m_table->setHorizontalHeaderLabels({
        "Completed At", "Profile", "Score", "Posture", "Findings", "Passed", "Duration"
    });
    m_table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(6, QHeaderView::Stretch);
    m_table->verticalHeader()->setVisible(false);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setCursor(Qt::PointingHandCursor);
    m_table->setStyleSheet(
        "QTableWidget {"
        "  background-color: #0d1117;"
        "  border: 1px solid #232936;"
        "  gridline-color: #1e2433;"
        "  border-radius: 6px;"
        "}"
        "QHeaderView::section {"
        "  background-color: #161b22;"
        "  color: #718096;"
        "  padding: 8px;"
        "  font-weight: bold;"
        "  border: none;"
        "}"
        "QTableWidget::item {"
        "  padding: 8px;"
        "  color: #e2e8f0;"
        "}"
        "QTableWidget::item:selected {"
        "  background-color: #2b354f;"
        "}"
    );

    connect(m_table, &QTableWidget::cellDoubleClicked, this, &ScanHistoryDialog::handleRowDoubleClicked);
    layout->addWidget(m_table);

    // Button Row
    auto* btnRow = new QHBoxLayout();

    auto* refreshBtn = new QPushButton("Refresh", this);
    refreshBtn->setCursor(Qt::PointingHandCursor);
    refreshBtn->setStyleSheet(
        "QPushButton {"
        "  background-color: #1a202c;"
        "  color: #cbd5e0;"
        "  border: 1px solid #2d3748;"
        "  border-radius: 6px;"
        "  padding: 8px 16px;"
        "  font-weight: bold;"
        "}"
        "QPushButton:hover { background-color: #2d3748; }"
    );
    connect(refreshBtn, &QPushButton::clicked, this, &ScanHistoryDialog::handleRefresh);
    btnRow->addWidget(refreshBtn);

    m_clearBtn = new QPushButton("Clear History", this);
    m_clearBtn->setCursor(Qt::PointingHandCursor);
    m_clearBtn->setStyleSheet(
        "QPushButton {"
        "  background-color: #742a2a;"
        "  color: #fed7d7;"
        "  border: none;"
        "  border-radius: 6px;"
        "  padding: 8px 16px;"
        "  font-weight: bold;"
        "}"
        "QPushButton:hover { background-color: #9b2c2c; }"
    );
    connect(m_clearBtn, &QPushButton::clicked, this, &ScanHistoryDialog::handleClearHistory);
    btnRow->addWidget(m_clearBtn);

    btnRow->addStretch();

    m_viewBtn = new QPushButton("Inspect Historical Scan", this);
    m_viewBtn->setCursor(Qt::PointingHandCursor);
    m_viewBtn->setStyleSheet(
        "QPushButton {"
        "  background-color: #2b6cb0;"
        "  color: #ffffff;"
        "  border: none;"
        "  border-radius: 6px;"
        "  padding: 8px 20px;"
        "  font-weight: bold;"
        "}"
        "QPushButton:hover { background-color: #3182ce; }"
    );
    connect(m_viewBtn, &QPushButton::clicked, this, &ScanHistoryDialog::handleViewSelectedScan);
    btnRow->addWidget(m_viewBtn);

    auto* closeBtn = new QPushButton("Close", this);
    closeBtn->setCursor(Qt::PointingHandCursor);
    closeBtn->setStyleSheet(
        "QPushButton {"
        "  background-color: #2d3748;"
        "  color: #e2e8f0;"
        "  border: none;"
        "  border-radius: 6px;"
        "  padding: 8px 16px;"
        "}"
        "QPushButton:hover { background-color: #4a5568; }"
    );
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::accept);
    btnRow->addWidget(closeBtn);

    layout->addLayout(btnRow);
}

void ScanHistoryDialog::loadScans() {
    auto res = storage::PersistenceService::instance().getRecentScans(100);
    if (!res.isSuccess()) {
        m_statusLabel->setText("Error loading history: " + QString::fromStdString(res.errorMessage()));
        m_table->setRowCount(0);
        return;
    }

    m_records = res.value();
    m_table->setRowCount(static_cast<int>(m_records.size()));
    m_statusLabel->setText(QString("%1 scan record%2 found").arg(m_records.size()).arg(m_records.size() == 1 ? "" : "s"));

    for (int i = 0; i < static_cast<int>(m_records.size()); ++i) {
        const auto& rec = m_records[i];

        auto endMs = std::chrono::duration_cast<std::chrono::milliseconds>(rec.completedAt.time_since_epoch()).count();
        auto dt = QDateTime::fromMSecsSinceEpoch(endMs);

        auto* timeItem = new QTableWidgetItem(dt.toString("yyyy-MM-dd hh:mm:ss"));
        auto* profItem = new QTableWidgetItem(QString::fromStdString(rec.profileName));

        auto* scoreItem = new QTableWidgetItem(QString("%1 / 100").arg(rec.finalScore));
        if (rec.finalScore >= 90) scoreItem->setForeground(QColor("#48bb78"));
        else if (rec.finalScore >= 75) scoreItem->setForeground(QColor("#ecc94b"));
        else if (rec.finalScore >= 50) scoreItem->setForeground(QColor("#ed8936"));
        else scoreItem->setForeground(QColor("#f56565"));

        auto* classItem = new QTableWidgetItem(QString::fromStdString(rec.scoreClassification));
        auto* findItem = new QTableWidgetItem(QString::number(rec.findingsCount));
        if (rec.findingsCount > 0) findItem->setForeground(QColor("#ed8936"));
        else findItem->setForeground(QColor("#48bb78"));

        auto* passItem = new QTableWidgetItem(QString::number(rec.passedCount));
        passItem->setForeground(QColor("#48bb78"));

        double durSec = static_cast<double>(rec.durationMs) / 1000.0;
        auto* durItem = new QTableWidgetItem(QString("%1s").arg(durSec, 0, 'f', 2));
        durItem->setForeground(QColor("#a0aec0"));

        m_table->setItem(i, 0, timeItem);
        m_table->setItem(i, 1, profItem);
        m_table->setItem(i, 2, scoreItem);
        m_table->setItem(i, 3, classItem);
        m_table->setItem(i, 4, findItem);
        m_table->setItem(i, 5, passItem);
        m_table->setItem(i, 6, durItem);
    }
}

void ScanHistoryDialog::handleRefresh() {
    loadScans();
}

void ScanHistoryDialog::handleClearHistory() {
    auto reply = QMessageBox::question(
        this,
        "Clear Scan History",
        "Are you sure you want to permanently clear all historical scans, findings, and evidence records?\n\nThis will not affect your current workstation security posture or running system.",
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No
    );

    if (reply == QMessageBox::Yes) {
        auto res = storage::PersistenceService::instance().clearAllScans();
        if (res.isSuccess()) {
            loadScans();
            QMessageBox::information(this, "History Cleared", "Scan history cleared successfully.");
        } else {
            QMessageBox::critical(this, "Error", QString("Failed to clear history: %1").arg(QString::fromStdString(res.errorMessage())));
        }
    }
}

void ScanHistoryDialog::handleViewSelectedScan() {
    int row = m_table->currentRow();
    if (row >= 0 && row < static_cast<int>(m_records.size())) {
        emit loadScanRequested(m_records[row].scanId);
        accept();
    } else {
        QMessageBox::information(this, "Select Scan", "Please select a scan row to inspect.");
    }
}

void ScanHistoryDialog::handleRowDoubleClicked(int row, int /*column*/) {
    if (row >= 0 && row < static_cast<int>(m_records.size())) {
        emit loadScanRequested(m_records[row].scanId);
        accept();
    }
}

} // namespace sentinel::ui
