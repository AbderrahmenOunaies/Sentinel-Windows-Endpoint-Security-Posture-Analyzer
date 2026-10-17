#include "CollectorStatusWidget.h"
#include <QHBoxLayout>

namespace sentinel::ui {

CollectorStatusWidget::CollectorStatusWidget(QWidget *parent)
    : QFrame(parent) {
    setObjectName("collectorStatusWidget");
    setStyleSheet(
        "#collectorStatusWidget {"
        "  background-color: #141721;"
        "  border: 1px solid #232936;"
        "  border-radius: 12px;"
        "  padding: 16px;"
        "}"
    );

    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 16, 16, 16);
    layout->setSpacing(10);

    auto* titleLabel = new QLabel("COLLECTION TELEMETRY HEALTH", this);
    titleLabel->setStyleSheet("color: #718096; font-size: 12px; font-weight: bold; letter-spacing: 1px;");
    layout->addWidget(titleLabel);

    m_statusListLayout = new QVBoxLayout();
    m_statusListLayout->setSpacing(6);
    layout->addLayout(m_statusListLayout);

    reset();
}

void CollectorStatusWidget::setStatuses(const std::vector<core::CollectorStatus>& statuses) {
    QLayoutItem* item;
    while ((item = m_statusListLayout->takeAt(0)) != nullptr) {
        delete item->widget();
        delete item;
    }

    for (const auto& s : statuses) {
        auto* row = new QWidget(this);
        auto* rowLayout = new QHBoxLayout(row);
        rowLayout->setContentsMargins(0, 2, 0, 2);

        auto* nameLabel = new QLabel(QString::fromStdString(s.collectorId), row);
        nameLabel->setStyleSheet("color: #cbd5e0; font-size: 12px; font-weight: 500;");

        auto* statusLabel = new QLabel(row);
        if (s.status == core::ErrorCode::Success) {
            statusLabel->setText("Complete");
            statusLabel->setStyleSheet("color: #48bb78; font-size: 11px; font-weight: bold;");
        } else if (s.status == core::ErrorCode::PermissionDenied) {
            statusLabel->setText("Permission Denied");
            statusLabel->setStyleSheet("color: #ed8936; font-size: 11px; font-weight: bold;");
        } else if (s.status == core::ErrorCode::NotSupported) {
            statusLabel->setText("Not Supported");
            statusLabel->setStyleSheet("color: #a0aec0; font-size: 11px; font-weight: bold;");
        } else {
            statusLabel->setText(QString("Error: %1").arg(QString::fromStdString(std::string(core::errorCodeToString(s.status)))));
            statusLabel->setStyleSheet("color: #f56565; font-size: 11px; font-weight: bold;");
        }

        rowLayout->addWidget(nameLabel);
        rowLayout->addStretch();
        rowLayout->addWidget(statusLabel);

        m_statusListLayout->addWidget(row);
    }
}

void CollectorStatusWidget::reset() {
    QLayoutItem* item;
    while ((item = m_statusListLayout->takeAt(0)) != nullptr) {
        delete item->widget();
        delete item;
    }

    auto* placeholder = new QLabel("Collectors not executed yet.", this);
    placeholder->setStyleSheet("color: #718096; font-size: 12px; font-style: italic;");
    m_statusListLayout->addWidget(placeholder);
}

} // namespace sentinel::ui
