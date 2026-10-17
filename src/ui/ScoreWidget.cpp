#include "ScoreWidget.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFont>

namespace sentinel::ui {

ScoreWidget::ScoreWidget(QWidget *parent)
    : QFrame(parent) {
    setObjectName("scoreWidget");
    setStyleSheet(
        "#scoreWidget {"
        "  background-color: #141721;"
        "  border: 1px solid #232936;"
        "  border-radius: 12px;"
        "  padding: 16px;"
        "}"
    );

    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 16, 16, 16);
    layout->setSpacing(8);

    auto* titleLabel = new QLabel("SECURITY SCORE", this);
    titleLabel->setStyleSheet("color: #718096; font-size: 12px; font-weight: bold; letter-spacing: 1px;");
    layout->addWidget(titleLabel, 0, Qt::AlignCenter);

    auto* scoreRow = new QHBoxLayout();
    scoreRow->setSpacing(4);
    scoreRow->setAlignment(Qt::AlignCenter);

    m_scoreValueLabel = new QLabel("--", this);
    QFont scoreFont("Segoe UI", 42, QFont::Bold);
    m_scoreValueLabel->setFont(scoreFont);
    m_scoreValueLabel->setStyleSheet("color: #a0aec0;");

    m_scoreMaxLabel = new QLabel("/ 100", this);
    QFont maxFont("Segoe UI", 16, QFont::DemiBold);
    m_scoreMaxLabel->setFont(maxFont);
    m_scoreMaxLabel->setStyleSheet("color: #718096; padding-top: 18px;");

    scoreRow->addWidget(m_scoreValueLabel);
    scoreRow->addWidget(m_scoreMaxLabel);
    layout->addLayout(scoreRow);

    m_postureLabel = new QLabel("NOT SCANNED", this);
    QFont postFont("Segoe UI", 13, QFont::Bold);
    m_postureLabel->setFont(postFont);
    m_postureLabel->setStyleSheet("color: #a0aec0; letter-spacing: 1px;");
    layout->addWidget(m_postureLabel, 0, Qt::AlignCenter);

    m_breakdownButton = new QPushButton("View Score Breakdown", this);
    m_breakdownButton->setCursor(Qt::PointingHandCursor);
    m_breakdownButton->setStyleSheet(
        "QPushButton {"
        "  background-color: #1e2433;"
        "  color: #63b3ed;"
        "  border: 1px solid #2d3748;"
        "  border-radius: 6px;"
        "  padding: 6px 12px;"
        "  font-size: 12px;"
        "  font-weight: 600;"
        "}"
        "QPushButton:hover {"
        "  background-color: #2b354f;"
        "  color: #90cdf4;"
        "}"
    );
    connect(m_breakdownButton, &QPushButton::clicked, this, &ScoreWidget::breakdownRequested);
    layout->addWidget(m_breakdownButton, 0, Qt::AlignCenter);
}

void ScoreWidget::setScore(const core::SecurityScoreBreakdown& breakdown) {
    m_breakdown = breakdown;
    m_scoreValueLabel->setText(QString::number(breakdown.finalScore));
    updateVisuals(breakdown.finalScore);
}

void ScoreWidget::reset() {
    m_scoreValueLabel->setText("--");
    m_scoreValueLabel->setStyleSheet("color: #a0aec0;");
    m_postureLabel->setText("NOT SCANNED");
    m_postureLabel->setStyleSheet("color: #a0aec0; letter-spacing: 1px;");
}

void ScoreWidget::updateVisuals(int score) {
    if (score >= 90) {
        m_scoreValueLabel->setStyleSheet("color: #48bb78;");
        m_postureLabel->setText("EXCELLENT POSTURE");
        m_postureLabel->setStyleSheet("color: #48bb78; letter-spacing: 1px; font-weight: bold;");
    } else if (score >= 75) {
        m_scoreValueLabel->setStyleSheet("color: #38b2ac;");
        m_postureLabel->setText("GOOD POSTURE");
        m_postureLabel->setStyleSheet("color: #38b2ac; letter-spacing: 1px; font-weight: bold;");
    } else if (score >= 50) {
        m_scoreValueLabel->setStyleSheet("color: #ecc94b;");
        m_postureLabel->setText("MODERATE RISK");
        m_postureLabel->setStyleSheet("color: #ecc94b; letter-spacing: 1px; font-weight: bold;");
    } else {
        m_scoreValueLabel->setStyleSheet("color: #f56565;");
        m_postureLabel->setText("HIGH RISK / CRITICAL");
        m_postureLabel->setStyleSheet("color: #f56565; letter-spacing: 1px; font-weight: bold;");
    }
}

} // namespace sentinel::ui
