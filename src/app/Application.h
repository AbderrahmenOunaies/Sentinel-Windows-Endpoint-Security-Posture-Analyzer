#pragma once

#include <memory>
#include <QApplication>

namespace sentinel::ui {
class MainWindow;
}

namespace sentinel::app {

class Application {
public:
    Application(int& argc, char** argv);
    ~Application();

    int run();

private:
    std::unique_ptr<QApplication> m_qtApp;
    std::unique_ptr<ui::MainWindow> m_mainWindow;
};

} // namespace sentinel::app
