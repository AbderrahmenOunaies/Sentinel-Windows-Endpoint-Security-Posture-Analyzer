#pragma once

#include "core/ScanResult.h"
#include "ScoreWidget.h"
#include "ScanProgressWidget.h"
#include "FindingsWidget.h"
#include "CategorySummaryWidget.h"
#include "CollectorStatusWidget.h"
#include "FindingDetailDialog.h"
#include "ScoreBreakdownDialog.h"

#include <QWidget>
#include <QPushButton>
#include <QComboBox>
#include <QLabel>

namespace sentinel::ui {

class DashboardWidget : public QWidget {
    Q_OBJECT

public:
    explicit DashboardWidget(QWidget *parent = nullptr);

    void setScanRunning(bool running);
    void updateProgress(int percentage, const QString& stage);
    void setScanResult(const core::ScanResult& result);
    void reset();

    [[nodiscard]] core::ProfileType selectedProfile() const;

signals:
    void runScanRequested();
    void cancelScanRequested();
    void viewHistoryRequested();

private slots:
    void handleBreakdownRequested();
    void handleFindingSelected(const core::Finding& finding);

private:
    void setupUi();

    QComboBox* m_profileCombo{nullptr};
    QPushButton* m_scanButton{nullptr};

    ScoreWidget* m_scoreWidget{nullptr};
    ScanProgressWidget* m_progressWidget{nullptr};

    // Stats Bar
    QLabel* m_passedLabel{nullptr};
    QLabel* m_failedLabel{nullptr};
    QLabel* m_unknownLabel{nullptr};
    QLabel* m_findingsCountLabel{nullptr};
    QLabel* m_metaLabel{nullptr};

    FindingsWidget* m_findingsWidget{nullptr};
    CategorySummaryWidget* m_categoryWidget{nullptr};
    CollectorStatusWidget* m_collectorStatusWidget{nullptr};

    core::ScanResult m_lastResult;
};

} // namespace sentinel::ui
