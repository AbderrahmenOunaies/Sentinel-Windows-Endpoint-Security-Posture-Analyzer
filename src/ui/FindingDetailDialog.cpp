#include "FindingDetailDialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QFont>
#include <QFrame>
#include <QDateTime>
#include <QGuiApplication>
#include <QClipboard>

namespace sentinel::ui {

FindingDetailDialog::FindingDetailDialog(const core::Finding& finding, QWidget *parent)
    : QDialog(parent) {
    setupUi(finding);
}

void FindingDetailDialog::setupUi(const core::Finding& finding) {
    setWindowTitle(QString("Finding Details - %1").arg(QString::fromStdString(finding.ruleId)));
    resize(680, 560);
    setStyleSheet("background-color: #0b0e14; color: #e2e8f0;");

    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(24, 24, 24, 24);
    mainLayout->setSpacing(18);

    // Header Card
    auto* headerCard = new QFrame(this);
    headerCard->setStyleSheet(
        "background-color: #141721; border: 1px solid #232936; border-radius: 8px; padding: 16px;"
    );
    auto* headerLayout = new QVBoxLayout(headerCard);

    auto* topRow = new QHBoxLayout();
    auto* idLabel = new QLabel(QString::fromStdString(finding.ruleId), headerCard);
    idLabel->setStyleSheet("color: #63b3ed; font-size: 16px; font-weight: bold;");

    auto* sevLabel = new QLabel(QString::fromStdString(std::string(core::severityToString(finding.severity))), headerCard);
    QString sevColor = "#a0aec0";
    if (finding.severity == core::Severity::Critical) sevColor = "#f56565";
    else if (finding.severity == core::Severity::High) sevColor = "#ed8936";
    else if (finding.severity == core::Severity::Medium) sevColor = "#ecc94b";
    else if (finding.severity == core::Severity::Low) sevColor = "#48bb78";
    sevLabel->setStyleSheet(QString("color: %1; font-weight: bold; font-size: 13px; padding: 2px 8px; background-color: #1a202c; border-radius: 4px;").arg(sevColor));

    auto* catLabel = new QLabel(QString("[%1]").arg(QString::fromStdString(finding.category)), headerCard);
    catLabel->setStyleSheet("color: #718096; font-size: 13px; font-weight: 500;");

    topRow->addWidget(idLabel);
    topRow->addWidget(catLabel);
    topRow->addStretch();
    topRow->addWidget(sevLabel);
    headerLayout->addLayout(topRow);

    auto* titleLabel = new QLabel(QString::fromStdString(finding.title), headerCard);
    QFont titleFont("Segoe UI", 15, QFont::Bold);
    titleLabel->setFont(titleFont);
    titleLabel->setStyleSheet("color: #ffffff; padding-top: 4px;");
    headerLayout->addWidget(titleLabel);

    mainLayout->addWidget(headerCard);

    // Description & Impact
    auto* descCard = new QFrame(this);
    descCard->setStyleSheet("background-color: #141721; border: 1px solid #232936; border-radius: 8px; padding: 14px;");
    auto* descLayout = new QVBoxLayout(descCard);
    descLayout->setSpacing(8);

    auto* descTitle = new QLabel("DESCRIPTION & IMPACT", descCard);
    descTitle->setStyleSheet("color: #718096; font-size: 11px; font-weight: bold; letter-spacing: 1px;");
    descLayout->addWidget(descTitle);

    auto* descText = new QLabel(QString::fromStdString(finding.description), descCard);
    descText->setWordWrap(true);
    descText->setStyleSheet("color: #cbd5e0; font-size: 13px;");
    descLayout->addWidget(descText);

    if (!finding.impact.empty()) {
        auto* impactText = new QLabel(QString("<b>Impact:</b> %1").arg(QString::fromStdString(finding.impact)), descCard);
        impactText->setWordWrap(true);
        impactText->setStyleSheet("color: #e2e8f0; font-size: 13px;");
        descLayout->addWidget(impactText);
    }
    mainLayout->addWidget(descCard);

    // Evidence Table
    auto* evCard = new QFrame(this);
    evCard->setStyleSheet("background-color: #141721; border: 1px solid #232936; border-radius: 8px; padding: 14px;");
    auto* evLayout = new QVBoxLayout(evCard);
    evLayout->setSpacing(8);

    auto* evTitle = new QLabel("AUDIT EVIDENCE", evCard);
    evTitle->setStyleSheet("color: #718096; font-size: 11px; font-weight: bold; letter-spacing: 1px;");
    evLayout->addWidget(evTitle);

    auto* table = new QTableWidget(static_cast<int>(finding.evidence.size()), 3, evCard);
    table->setHorizontalHeaderLabels({"Source", "Key", "Observed Value"});
    table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    table->verticalHeader()->setVisible(false);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setStyleSheet(
        "QTableWidget {"
        "  background-color: #0d1117;"
        "  border: 1px solid #232936;"
        "  gridline-color: #1e2433;"
        "  font-size: 12px;"
        "}"
        "QHeaderView::section {"
        "  background-color: #161b22;"
        "  color: #718096;"
        "  padding: 6px;"
        "  font-weight: bold;"
        "  border: none;"
        "}"
        "QTableWidget::item {"
        "  padding: 6px;"
        "  color: #e2e8f0;"
        "}"
    );

    for (int i = 0; i < static_cast<int>(finding.evidence.size()); ++i) {
        const auto& ev = finding.evidence[i];
        table->setItem(i, 0, new QTableWidgetItem(QString::fromStdString(ev.source)));
        table->setItem(i, 1, new QTableWidgetItem(QString::fromStdString(ev.key)));
        table->setItem(i, 2, new QTableWidgetItem(QString::fromStdString(ev.value)));
    }
    evLayout->addWidget(table);
    mainLayout->addWidget(evCard);

    // Recommendation & Remediation
    auto* recCard = new QFrame(this);
    recCard->setStyleSheet("background-color: #141721; border: 1px solid #232936; border-radius: 8px; padding: 14px;");
    auto* recLayout = new QVBoxLayout(recCard);
    recLayout->setSpacing(8);

    auto* recTitle = new QLabel("RECOMMENDED ACTION & REMEDIATION", recCard);
    recTitle->setStyleSheet("color: #718096; font-size: 11px; font-weight: bold; letter-spacing: 1px;");
    recLayout->addWidget(recTitle);

    auto* recText = new QLabel(QString::fromStdString(finding.recommendation), recCard);
    recText->setWordWrap(true);
    recText->setStyleSheet("color: #68d391; font-size: 13px; font-weight: 500;");
    recLayout->addWidget(recText);

    if (finding.remediationAvailable) {
        auto* remRow = new QHBoxLayout();
        auto* remLabel = new QLabel(QString("<b>Remediation ID:</b> %1 (Automated fix available)")
                                        .arg(QString::fromStdString(finding.remediationId)), recCard);
        remLabel->setStyleSheet("color: #63b3ed; font-size: 12px;");
        remRow->addWidget(remLabel);
        remRow->addStretch();

        auto* previewRemBtn = new QPushButton("Preview Remediation", recCard);
        previewRemBtn->setCursor(Qt::PointingHandCursor);
        previewRemBtn->setStyleSheet(
            "QPushButton {"
            "  background-color: #3182ce;"
            "  color: #ffffff;"
            "  border: none;"
            "  border-radius: 4px;"
            "  padding: 5px 12px;"
            "  font-weight: bold;"
            "  font-size: 12px;"
            "}"
            "QPushButton:hover {"
            "  background-color: #2b6cb0;"
            "}"
        );
        connect(previewRemBtn, &QPushButton::clicked, this, [this, finding]() {
            emit remediationRequested(finding);
        });
        remRow->addWidget(previewRemBtn);
        recLayout->addLayout(remRow);
    }

    mainLayout->addWidget(recCard);

    // Timestamp & Footer Row
    auto* footerRow = new QHBoxLayout();

    auto detectedMs = std::chrono::duration_cast<std::chrono::milliseconds>(finding.detectedAt.time_since_epoch()).count();
    auto detectedDt = QDateTime::fromMSecsSinceEpoch(detectedMs);
    auto* timeLabel = new QLabel(QString("Detected at: %1").arg(detectedDt.toString("yyyy-MM-dd hh:mm:ss")), this);
    timeLabel->setStyleSheet("color: #718096; font-size: 12px;");
    footerRow->addWidget(timeLabel);

    footerRow->addStretch();

    auto* copyEvBtn = new QPushButton("Copy Evidence", this);
    copyEvBtn->setCursor(Qt::PointingHandCursor);
    copyEvBtn->setStyleSheet(
        "QPushButton {"
        "  background-color: #2d3748;"
        "  color: #cbd5e0;"
        "  border: 1px solid #4a5568;"
        "  border-radius: 6px;"
        "  padding: 8px 16px;"
        "  font-weight: bold;"
        "  font-size: 12px;"
        "}"
        "QPushButton:hover {"
        "  background-color: #4a5568;"
        "}"
    );
    connect(copyEvBtn, &QPushButton::clicked, this, [finding]() {
        QString clipboardText = QString("Rule: %1 (%2)\nSeverity: %3\nTitle: %4\n\nEvidence:\n")
            .arg(QString::fromStdString(finding.ruleId))
            .arg(QString::fromStdString(finding.category))
            .arg(QString::fromStdString(std::string(core::severityToString(finding.severity))))
            .arg(QString::fromStdString(finding.title));
        for (const auto& ev : finding.evidence) {
            clipboardText += QString("  [%1] %2 = %3\n")
                .arg(QString::fromStdString(ev.source))
                .arg(QString::fromStdString(ev.key))
                .arg(QString::fromStdString(ev.value));
        }
        clipboardText += QString("\nRecommendation:\n  %1\n").arg(QString::fromStdString(finding.recommendation));
        QGuiApplication::clipboard()->setText(clipboardText);
    });
    footerRow->addWidget(copyEvBtn);

    auto* closeBtn = new QPushButton("Close", this);
    closeBtn->setCursor(Qt::PointingHandCursor);
    closeBtn->setStyleSheet(
        "QPushButton {"
        "  background-color: #2b6cb0;"
        "  color: #ffffff;"
        "  border: none;"
        "  border-radius: 6px;"
        "  padding: 8px 20px;"
        "  font-weight: bold;"
        "}"
        "QPushButton:hover {"
        "  background-color: #3182ce;"
        "}"
    );
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::accept);
    footerRow->addWidget(closeBtn);
    mainLayout->addLayout(footerRow);
}

} // namespace sentinel::ui
