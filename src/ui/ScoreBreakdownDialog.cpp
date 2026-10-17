#include "ScoreBreakdownDialog.h"
#include <QHBoxLayout>
#include <QFrame>
#include <QFont>

namespace sentinel::ui {

ScoreBreakdownDialog::ScoreBreakdownDialog(const core::SecurityScoreBreakdown& breakdown, QWidget *parent)
    : QDialog(parent) {
    setupUi(breakdown);
}

void ScoreBreakdownDialog::setupUi(const core::SecurityScoreBreakdown& breakdown) {
    setWindowTitle("Transparent Security Score Breakdown");
    resize(480, 420);
    setStyleSheet("background-color: #0b0e14; color: #e2e8f0;");

    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(24, 24, 24, 24);
    mainLayout->setSpacing(16);

    auto* titleLabel = new QLabel("DETERMINISTIC SCORE EXPLANATION", this);
    titleLabel->setStyleSheet("color: #718096; font-size: 11px; font-weight: bold; letter-spacing: 1px;");
    mainLayout->addWidget(titleLabel);

    auto* card = new QFrame(this);
    card->setStyleSheet("background-color: #141721; border: 1px solid #232936; border-radius: 8px; padding: 16px;");
    auto* cardLayout = new QVBoxLayout(card);
    cardLayout->setSpacing(12);

    auto addRow = [card, cardLayout](const QString& label, const QString& value, const QString& valColor, bool bold = false) {
        auto* row = new QHBoxLayout();
        auto* lbl = new QLabel(label, card);
        lbl->setStyleSheet(QString("color: #cbd5e0; font-size: 13px; font-weight: %1;").arg(bold ? "bold" : "normal"));

        auto* val = new QLabel(value, card);
        val->setStyleSheet(QString("color: %1; font-size: 13px; font-weight: %2;").arg(valColor).arg(bold ? "bold" : "normal"));

        row->addWidget(lbl);
        row->addStretch();
        row->addWidget(val);
        cardLayout->addLayout(row);
    };

    addRow("Baseline Workstation Score", QString::number(breakdown.baseScore), "#48bb78", true);

    auto* div1 = new QFrame(card);
    div1->setFrameShape(QFrame::HLine);
    div1->setStyleSheet("color: #232936;");
    cardLayout->addWidget(div1);

    addRow(QString("Critical Findings (%1 × -25)").arg(breakdown.criticalCount),
           QString("-%1").arg(breakdown.criticalDeductions), "#f56565");

    addRow(QString("High Findings (%1 × -10)").arg(breakdown.highCount),
           QString("-%1").arg(breakdown.highDeductions), "#ed8936");

    addRow(QString("Medium Findings (%1 × -5)").arg(breakdown.mediumCount),
           QString("-%1").arg(breakdown.mediumDeductions), "#ecc94b");

    addRow(QString("Low Findings (%1 × -2)").arg(breakdown.lowCount),
           QString("-%1").arg(breakdown.lowDeductions), "#48bb78");

    addRow(QString("Info Findings (%1 × 0)").arg(breakdown.infoCount), "0", "#a0aec0");

    auto* div2 = new QFrame(card);
    div2->setFrameShape(QFrame::HLine);
    div2->setStyleSheet("color: #232936;");
    cardLayout->addWidget(div2);

    int totalDeductions = breakdown.criticalDeductions + breakdown.highDeductions + breakdown.mediumDeductions + breakdown.lowDeductions;
    addRow("Total Score Deductions", QString("-%1").arg(totalDeductions), "#f56565", true);
    addRow("Final Clamped Score [0, 100]", QString("%1 / 100").arg(breakdown.finalScore), "#63b3ed", true);

    mainLayout->addWidget(card);

    auto* noteLabel = new QLabel("Scoring is fully transparent and deterministic based on evidence-backed finding penalties.", this);
    noteLabel->setWordWrap(true);
    noteLabel->setStyleSheet("color: #718096; font-size: 11px; font-style: italic;");
    mainLayout->addWidget(noteLabel);

    auto* btnRow = new QHBoxLayout();
    btnRow->addStretch();
    auto* closeBtn = new QPushButton("Close", this);
    closeBtn->setCursor(Qt::PointingHandCursor);
    closeBtn->setStyleSheet(
        "QPushButton {"
        "  background-color: #2b6cb0;"
        "  color: #ffffff;"
        "  border: none;"
        "  border-radius: 6px;"
        "  padding: 8px 18px;"
        "  font-weight: bold;"
        "}"
        "QPushButton:hover {"
        "  background-color: #3182ce;"
        "}"
    );
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::accept);
    btnRow->addWidget(closeBtn);
    mainLayout->addLayout(btnRow);
}

} // namespace sentinel::ui
