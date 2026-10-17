#pragma once

#include "storage/PersistenceService.h"
#include <QDialog>
#include <QTableWidget>
#include <QPushButton>
#include <QLabel>
#include <vector>

namespace sentinel::ui {

class ScanHistoryDialog : public QDialog {
    Q_OBJECT

public:
    explicit ScanHistoryDialog(QWidget *parent = nullptr);

signals:
    void loadScanRequested(const std::string& scanId);

private slots:
    void handleRefresh();
    void handleClearHistory();
    void handleViewSelectedScan();
    void handleRowDoubleClicked(int row, int column);

private:
    void setupUi();
    void loadScans();

    QTableWidget* m_table{nullptr};
    QLabel* m_statusLabel{nullptr};
    QPushButton* m_viewBtn{nullptr};
    QPushButton* m_clearBtn{nullptr};
    std::vector<storage::ScanRecordSummary> m_records;
};

} // namespace sentinel::ui
