#pragma once

#include "core/CollectorStatus.h"
#include <QFrame>
#include <QLabel>
#include <QVBoxLayout>
#include <vector>

namespace sentinel::ui {

class CollectorStatusWidget : public QFrame {
    Q_OBJECT

public:
    explicit CollectorStatusWidget(QWidget *parent = nullptr);

    void setStatuses(const std::vector<core::CollectorStatus>& statuses);
    void reset();

private:
    QVBoxLayout* m_statusListLayout{nullptr};
};

} // namespace sentinel::ui
