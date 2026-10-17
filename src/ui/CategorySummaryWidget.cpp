#include "CategorySummaryWidget.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <map>

namespace sentinel::ui {

CategorySummaryWidget::CategorySummaryWidget(QWidget *parent)
    : QFrame(parent) {
    setObjectName("categorySummaryWidget");
    setStyleSheet(
        "#categorySummaryWidget {"
        "  background-color: #141721;"
        "  border: 1px solid #232936;"
        "  border-radius: 12px;"
        "  padding: 16px;"
        "}"
    );

    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 16, 16, 16);
    layout->setSpacing(12);

    auto* titleLabel = new QLabel("CATEGORY BREAKDOWN", this);
    titleLabel->setStyleSheet("color: #718096; font-size: 12px; font-weight: bold; letter-spacing: 1px;");
    layout->addWidget(titleLabel);

    m_gridLayout = new QGridLayout();
    m_gridLayout->setSpacing(10);
    layout->addLayout(m_gridLayout);

    reset();
}

void CategorySummaryWidget::setEvaluations(const std::vector<core::RuleEvaluation>& evaluations) {
    // Clear layout
    QLayoutItem* item;
    while ((item = m_gridLayout->takeAt(0)) != nullptr) {
        delete item->widget();
        delete item;
    }

    std::map<std::string, CategoryStats> stats;
    // Map ruleId prefix to category
    for (const auto& ev : evaluations) {
        std::string cat = "General";
        if (ev.ruleId.rfind("FW-", 0) == 0) cat = "Firewall";
        else if (ev.ruleId.rfind("DEF-", 0) == 0) cat = "Endpoint Protection";
        else if (ev.ruleId.rfind("AUTH-", 0) == 0) cat = "Authentication";
        else if (ev.ruleId.rfind("ENC-", 0) == 0) cat = "Encryption";
        else if (ev.ruleId.rfind("UPD-", 0) == 0) cat = "Updates";

        if (ev.outcome == core::RuleOutcome::Pass) stats[cat].passed++;
        else if (ev.outcome == core::RuleOutcome::Fail) stats[cat].failed++;
        else stats[cat].unknown++;
    }

    int row = 0;
    int col = 0;
    for (const auto& [category, s] : stats) {
        auto* card = new QFrame(this);
        card->setStyleSheet("background-color: #0d1117; border: 1px solid #232936; border-radius: 6px; padding: 8px;");
        auto* cardLayout = new QVBoxLayout(card);
        cardLayout->setContentsMargins(8, 6, 8, 6);
        cardLayout->setSpacing(4);

        auto* catName = new QLabel(QString::fromStdString(category), card);
        catName->setStyleSheet("color: #cbd5e0; font-size: 12px; font-weight: bold;");
        cardLayout->addWidget(catName);

        auto* badgeRow = new QHBoxLayout();
        badgeRow->setSpacing(8);

        auto* passLbl = new QLabel(QString("%1 Pass").arg(s.passed), card);
        passLbl->setStyleSheet("color: #48bb78; font-size: 11px; font-weight: 600;");
        badgeRow->addWidget(passLbl);

        if (s.failed > 0) {
            auto* failLbl = new QLabel(QString("%1 Fail").arg(s.failed), card);
            failLbl->setStyleSheet("color: #f56565; font-size: 11px; font-weight: 600;");
            badgeRow->addWidget(failLbl);
        }

        if (s.unknown > 0) {
            auto* unkLbl = new QLabel(QString("%1 Unk").arg(s.unknown), card);
            unkLbl->setStyleSheet("color: #ecc94b; font-size: 11px; font-weight: 600;");
            badgeRow->addWidget(unkLbl);
        }

        badgeRow->addStretch();
        cardLayout->addLayout(badgeRow);

        m_gridLayout->addWidget(card, row, col);
        col++;
        if (col >= 3) {
            col = 0;
            row++;
        }
    }
}

void CategorySummaryWidget::reset() {
    QLayoutItem* item;
    while ((item = m_gridLayout->takeAt(0)) != nullptr) {
        delete item->widget();
        delete item;
    }

    auto* placeholder = new QLabel("Run a security scan to evaluate category posture.", this);
    placeholder->setStyleSheet("color: #718096; font-size: 12px; font-style: italic;");
    m_gridLayout->addWidget(placeholder, 0, 0);
}

} // namespace sentinel::ui
