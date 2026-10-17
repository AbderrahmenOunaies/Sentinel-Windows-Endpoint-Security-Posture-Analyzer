#include "ScanProgressWidget.h"
#include <QVBoxLayout>
#include <QHBoxLayout>

namespace sentinel::ui {

ScanProgressWidget::ScanProgressWidget(QWidget *parent)
    : QFrame(parent) {
    setObjectName("scanProgressWidget");
    setStyleSheet(
        "#scanProgressWidget {"
        "  background-color: #1a1e29;"
        "  border: 1px solid #2d3748;"
        "  border-radius: 8px;"
        "  padding: 12px 16px;"
        "}"
    );

    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(12, 10, 12, 10);
    layout->setSpacing(8);

    auto* topRow = new QHBoxLayout();
    m_stageLabel = new QLabel("Ready to scan", this);
    m_stageLabel->setStyleSheet("color: #cbd5e0; font-size: 13px; font-weight: 500;");

    m_percentLabel = new QLabel("0%", this);
    m_percentLabel->setStyleSheet("color: #63b3ed; font-size: 13px; font-weight: bold;");

    m_cancelButton = new QPushButton("Cancel", this);
    m_cancelButton->setCursor(Qt::PointingHandCursor);
    m_cancelButton->setStyleSheet(
        "QPushButton {"
        "  background-color: #742a2a;"
        "  color: #fed7d7;"
        "  border: 1px solid #9b2c2c;"
        "  border-radius: 4px;"
        "  padding: 4px 10px;"
        "  font-size: 12px;"
        "  font-weight: 600;"
        "}"
        "QPushButton:hover {"
        "  background-color: #9b2c2c;"
        "}"
    );
    connect(m_cancelButton, &QPushButton::clicked, this, &ScanProgressWidget::cancelRequested);

    topRow->addWidget(m_stageLabel);
    topRow->addStretch();
    topRow->addWidget(m_percentLabel);
    topRow->addWidget(m_cancelButton);
    layout->addLayout(topRow);

    m_progressBar = new QProgressBar(this);
    m_progressBar->setRange(0, 100);
    m_progressBar->setValue(0);
    m_progressBar->setTextVisible(false);
    m_progressBar->setFixedHeight(8);
    m_progressBar->setStyleSheet(
        "QProgressBar {"
        "  background-color: #0b0e14;"
        "  border: 1px solid #232936;"
        "  border-radius: 4px;"
        "}"
        "QProgressBar::chunk {"
        "  background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #3182ce, stop:1 #63b3ed);"
        "  border-radius: 3px;"
        "}"
    );
    layout->addWidget(m_progressBar);

    hide(); // initially hidden until scan starts
}

void ScanProgressWidget::setProgress(int percentage, const QString& stage) {
    m_stageLabel->setText(stage);
    m_percentLabel->setText(QString("%1%").arg(percentage));
    m_progressBar->setValue(percentage);
    show();
}

void ScanProgressWidget::reset() {
    m_progressBar->setValue(0);
    m_percentLabel->setText("0%");
    m_stageLabel->setText("Ready to scan");
    hide();
}

} // namespace sentinel::ui
