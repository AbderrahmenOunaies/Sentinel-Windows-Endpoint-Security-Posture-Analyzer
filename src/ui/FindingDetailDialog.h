#pragma once

#include "core/Finding.h"
#include <QDialog>
#include <QLabel>
#include <QTableWidget>
#include <QPushButton>

namespace sentinel::ui {

class FindingDetailDialog : public QDialog {
    Q_OBJECT

public:
    explicit FindingDetailDialog(const core::Finding& finding, QWidget *parent = nullptr);

signals:
    void remediationRequested(const core::Finding& finding);

private:
    void setupUi(const core::Finding& finding);
};

} // namespace sentinel::ui

