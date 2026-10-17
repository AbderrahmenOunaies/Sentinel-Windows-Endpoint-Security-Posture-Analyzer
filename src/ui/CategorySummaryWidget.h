#pragma once

#include "core/RuleEvaluation.h"
#include <QFrame>
#include <QLabel>
#include <QGridLayout>
#include <vector>
#include <string>

namespace sentinel::ui {

class CategorySummaryWidget : public QFrame {
    Q_OBJECT

public:
    explicit CategorySummaryWidget(QWidget *parent = nullptr);

    void setEvaluations(const std::vector<core::RuleEvaluation>& evaluations);
    void reset();

private:
    struct CategoryStats {
        int passed{0};
        int failed{0};
        int unknown{0};
    };

    QGridLayout* m_gridLayout{nullptr};
};

} // namespace sentinel::ui
