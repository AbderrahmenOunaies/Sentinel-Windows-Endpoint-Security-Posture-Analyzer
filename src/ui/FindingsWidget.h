#pragma once

#include "core/Finding.h"
#include <QFrame>
#include <QTableWidget>
#include <QLabel>
#include <QLineEdit>
#include <QComboBox>
#include <vector>

namespace sentinel::ui {

class FindingsWidget : public QFrame {
    Q_OBJECT

public:
    explicit FindingsWidget(QWidget *parent = nullptr);

    void setFindings(const std::vector<core::Finding>& findings);
    void reset();

signals:
    void findingSelected(const core::Finding& finding);

private slots:
    void handleCellDoubleClicked(int row, int column);
    void applyFilter();

private:
    void populateTable();

    QLabel* m_countLabel{nullptr};
    QLineEdit* m_searchBox{nullptr};
    QComboBox* m_severityFilterCombo{nullptr};
    QComboBox* m_categoryFilterCombo{nullptr};
    QTableWidget* m_table{nullptr};

    std::vector<core::Finding> m_allFindings;
    std::vector<core::Finding> m_filteredFindings;
};

} // namespace sentinel::ui

