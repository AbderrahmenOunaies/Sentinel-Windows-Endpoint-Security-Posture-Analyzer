#include "FindingsWidget.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <algorithm>
#include <set>

namespace sentinel::ui {

FindingsWidget::FindingsWidget(QWidget *parent)
    : QFrame(parent) {
    setObjectName("findingsWidget");
    setStyleSheet(
        "#findingsWidget {"
        "  background-color: #141721;"
        "  border: 1px solid #232936;"
        "  border-radius: 12px;"
        "  padding: 16px;"
        "}"
    );

    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 16, 16, 16);
    layout->setSpacing(12);

    auto* headerRow = new QHBoxLayout();
    auto* titleLabel = new QLabel("SECURITY FINDINGS", this);
    titleLabel->setStyleSheet("color: #718096; font-size: 12px; font-weight: bold; letter-spacing: 1px;");

    m_countLabel = new QLabel("0 findings", this);
    m_countLabel->setStyleSheet("color: #a0aec0; font-size: 12px; font-weight: bold;");

    headerRow->addWidget(titleLabel);
    headerRow->addStretch();
    headerRow->addWidget(m_countLabel);
    layout->addLayout(headerRow);

    // Search and Filter Bar
    auto* filterRow = new QHBoxLayout();
    filterRow->setSpacing(10);

    m_searchBox = new QLineEdit(this);
    m_searchBox->setPlaceholderText("Filter by title, rule ID, or description...");
    m_searchBox->setStyleSheet(
        "QLineEdit {"
        "  background-color: #0b0e14;"
        "  color: #e2e8f0;"
        "  border: 1px solid #232936;"
        "  border-radius: 6px;"
        "  padding: 6px 12px;"
        "  font-size: 12px;"
        "}"
        "QLineEdit:focus {"
        "  border: 1px solid #3182ce;"
        "}"
    );
    connect(m_searchBox, &QLineEdit::textChanged, this, &FindingsWidget::applyFilter);
    filterRow->addWidget(m_searchBox, 2);

    m_severityFilterCombo = new QComboBox(this);
    m_severityFilterCombo->addItem("All Severities", "All");
    m_severityFilterCombo->addItem("Critical", "Critical");
    m_severityFilterCombo->addItem("High", "High");
    m_severityFilterCombo->addItem("Medium", "Medium");
    m_severityFilterCombo->addItem("Low", "Low");
    m_severityFilterCombo->addItem("Info", "Info");
    m_severityFilterCombo->setStyleSheet(
        "QComboBox {"
        "  background-color: #0b0e14;"
        "  color: #cbd5e0;"
        "  border: 1px solid #232936;"
        "  border-radius: 6px;"
        "  padding: 6px 12px;"
        "  font-size: 12px;"
        "}"
    );
    connect(m_severityFilterCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &FindingsWidget::applyFilter);
    filterRow->addWidget(m_severityFilterCombo, 1);

    m_categoryFilterCombo = new QComboBox(this);
    m_categoryFilterCombo->addItem("All Categories", "All");
    m_categoryFilterCombo->setStyleSheet(
        "QComboBox {"
        "  background-color: #0b0e14;"
        "  color: #cbd5e0;"
        "  border: 1px solid #232936;"
        "  border-radius: 6px;"
        "  padding: 6px 12px;"
        "  font-size: 12px;"
        "}"
    );
    connect(m_categoryFilterCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &FindingsWidget::applyFilter);
    filterRow->addWidget(m_categoryFilterCombo, 1);

    layout->addLayout(filterRow);

    m_table = new QTableWidget(0, 5, this);
    m_table->setHorizontalHeaderLabels({"Severity", "Rule ID", "Category", "Finding Title", "Remediation"});
    m_table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    m_table->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    m_table->verticalHeader()->setVisible(false);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setCursor(Qt::PointingHandCursor);
    m_table->setStyleSheet(
        "QTableWidget {"
        "  background-color: #0b0e14;"
        "  border: 1px solid #232936;"
        "  gridline-color: #1e2433;"
        "  border-radius: 6px;"
        "}"
        "QHeaderView::section {"
        "  background-color: #161b22;"
        "  color: #718096;"
        "  padding: 8px;"
        "  font-weight: bold;"
        "  border: none;"
        "}"
        "QTableWidget::item {"
        "  padding: 8px;"
        "  color: #e2e8f0;"
        "}"
        "QTableWidget::item:selected {"
        "  background-color: #2b354f;"
        "}"
    );

    connect(m_table, &QTableWidget::cellDoubleClicked, this, &FindingsWidget::handleCellDoubleClicked);
    layout->addWidget(m_table);
}

void FindingsWidget::setFindings(const std::vector<core::Finding>& findings) {
    m_allFindings = findings;

    // Sort predictable: Critical, High, Medium, Low, Info, then by ruleId
    std::sort(m_allFindings.begin(), m_allFindings.end(), [](const core::Finding& a, const core::Finding& b) {
        if (a.severity != b.severity) {
            return static_cast<int>(a.severity) < static_cast<int>(b.severity);
        }
        return a.ruleId < b.ruleId;
    });

    // Populate category dropdown dynamically
    m_categoryFilterCombo->blockSignals(true);
    m_categoryFilterCombo->clear();
    m_categoryFilterCombo->addItem("All Categories", "All");
    std::set<std::string> cats;
    for (const auto& f : m_allFindings) {
        if (!f.category.empty()) {
            cats.insert(f.category);
        }
    }
    for (const auto& c : cats) {
        m_categoryFilterCombo->addItem(QString::fromStdString(c), QString::fromStdString(c));
    }
    m_categoryFilterCombo->blockSignals(false);

    applyFilter();
}

void FindingsWidget::reset() {
    m_allFindings.clear();
    m_filteredFindings.clear();
    m_searchBox->clear();
    m_severityFilterCombo->setCurrentIndex(0);
    m_categoryFilterCombo->clear();
    m_categoryFilterCombo->addItem("All Categories", "All");
    m_table->setRowCount(0);
    m_countLabel->setText("0 findings");
}

void FindingsWidget::applyFilter() {
    const QString searchText = m_searchBox->text().trimmed().toLower();
    const QString selectedSev = m_severityFilterCombo->currentData().toString();
    const QString selectedCat = m_categoryFilterCombo->currentData().toString();

    m_filteredFindings.clear();

    for (const auto& f : m_allFindings) {
        if (selectedSev != "All") {
            if (QString::fromStdString(std::string(core::severityToString(f.severity))) != selectedSev) {
                continue;
            }
        }

        if (selectedCat != "All") {
            if (QString::fromStdString(f.category) != selectedCat) {
                continue;
            }
        }

        if (!searchText.isEmpty()) {
            QString title = QString::fromStdString(f.title).toLower();
            QString ruleId = QString::fromStdString(f.ruleId).toLower();
            QString desc = QString::fromStdString(f.description).toLower();
            if (!title.contains(searchText) && !ruleId.contains(searchText) && !desc.contains(searchText)) {
                continue;
            }
        }

        m_filteredFindings.push_back(f);
    }

    populateTable();
}

void FindingsWidget::populateTable() {
    m_table->setRowCount(static_cast<int>(m_filteredFindings.size()));
    if (m_filteredFindings.size() == m_allFindings.size()) {
        m_countLabel->setText(QString("%1 finding%2").arg(m_filteredFindings.size()).arg(m_filteredFindings.size() == 1 ? "" : "s"));
    } else {
        m_countLabel->setText(QString("%1 of %2 findings").arg(m_filteredFindings.size()).arg(m_allFindings.size()));
    }

    for (int i = 0; i < static_cast<int>(m_filteredFindings.size()); ++i) {
        const auto& f = m_filteredFindings[i];

        auto* sevItem = new QTableWidgetItem(QString::fromStdString(std::string(core::severityToString(f.severity))));
        if (f.severity == core::Severity::Critical) sevItem->setForeground(QColor("#f56565"));
        else if (f.severity == core::Severity::High) sevItem->setForeground(QColor("#ed8936"));
        else if (f.severity == core::Severity::Medium) sevItem->setForeground(QColor("#ecc94b"));
        else if (f.severity == core::Severity::Low) sevItem->setForeground(QColor("#48bb78"));
        else sevItem->setForeground(QColor("#a0aec0"));

        auto* idItem = new QTableWidgetItem(QString::fromStdString(f.ruleId));
        idItem->setForeground(QColor("#63b3ed"));

        auto* catItem = new QTableWidgetItem(QString::fromStdString(f.category));
        catItem->setForeground(QColor("#a0aec0"));

        auto* titleItem = new QTableWidgetItem(QString::fromStdString(f.title));
        titleItem->setForeground(QColor("#ffffff"));

        auto* remItem = new QTableWidgetItem(f.remediationAvailable ? "Fix Available" : "--");
        remItem->setForeground(f.remediationAvailable ? QColor("#68d391") : QColor("#718096"));

        m_table->setItem(i, 0, sevItem);
        m_table->setItem(i, 1, idItem);
        m_table->setItem(i, 2, catItem);
        m_table->setItem(i, 3, titleItem);
        m_table->setItem(i, 4, remItem);
    }
}

void FindingsWidget::handleCellDoubleClicked(int row, int /*column*/) {
    if (row >= 0 && row < static_cast<int>(m_filteredFindings.size())) {
        emit findingSelected(m_filteredFindings[row]);
    }
}

} // namespace sentinel::ui
