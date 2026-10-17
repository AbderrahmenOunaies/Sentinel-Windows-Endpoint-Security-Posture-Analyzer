#pragma once

#include "core/SecurityScore.h"
#include <QFrame>
#include <QLabel>
#include <QPushButton>

namespace sentinel::ui {

class ScoreWidget : public QFrame {
    Q_OBJECT

public:
    explicit ScoreWidget(QWidget *parent = nullptr);

    void setScore(const core::SecurityScoreBreakdown& breakdown);
    void reset();

signals:
    void breakdownRequested();

private:
    void updateVisuals(int score);

    QLabel* m_scoreValueLabel{nullptr};
    QLabel* m_scoreMaxLabel{nullptr};
    QLabel* m_postureLabel{nullptr};
    QPushButton* m_breakdownButton{nullptr};
    core::SecurityScoreBreakdown m_breakdown;
};

} // namespace sentinel::ui
