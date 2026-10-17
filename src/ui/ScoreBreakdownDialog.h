#pragma once

#include "core/SecurityScore.h"
#include <QDialog>
#include <QLabel>
#include <QVBoxLayout>
#include <QPushButton>

namespace sentinel::ui {

class ScoreBreakdownDialog : public QDialog {
    Q_OBJECT

public:
    explicit ScoreBreakdownDialog(const core::SecurityScoreBreakdown& breakdown, QWidget *parent = nullptr);

private:
    void setupUi(const core::SecurityScoreBreakdown& breakdown);
};

} // namespace sentinel::ui
