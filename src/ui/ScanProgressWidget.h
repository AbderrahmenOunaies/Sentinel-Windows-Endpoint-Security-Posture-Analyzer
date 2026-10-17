#pragma once

#include <QFrame>
#include <QLabel>
#include <QProgressBar>
#include <QPushButton>

namespace sentinel::ui {

class ScanProgressWidget : public QFrame {
    Q_OBJECT

public:
    explicit ScanProgressWidget(QWidget *parent = nullptr);

    void setProgress(int percentage, const QString& stage);
    void reset();

signals:
    void cancelRequested();

private:
    QLabel* m_stageLabel{nullptr};
    QLabel* m_percentLabel{nullptr};
    QProgressBar* m_progressBar{nullptr};
    QPushButton* m_cancelButton{nullptr};
};

} // namespace sentinel::ui
