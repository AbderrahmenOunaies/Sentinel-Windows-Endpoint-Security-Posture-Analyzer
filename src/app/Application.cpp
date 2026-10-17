#include "Application.h"
#include "../ui/MainWindow.h"
#include "../core/Logger.h"
#include "../storage/PersistenceService.h"

namespace sentinel::app {

Application::Application(int& argc, char** argv)
    : m_qtApp(std::make_unique<QApplication>(argc, argv)) {
    LOG_INFO("Initializing Sentinel Application runtime...");
    
    QApplication::setApplicationName("Sentinel");
    QApplication::setApplicationVersion("1.0.0");
    QApplication::setOrganizationName("SentinelSecurity");

    // Initialize SQLite persistence service
    auto initRes = storage::PersistenceService::instance().initialize();
    if (!initRes.isSuccess()) {
        LOG_WARNING("Persistence initialization failed: " + initRes.errorMessage() + " (running in memory-only mode)");
    }

    m_mainWindow = std::make_unique<ui::MainWindow>();
}

Application::~Application() {
    LOG_INFO("Terminating Sentinel Application...");
    storage::PersistenceService::instance().shutdown();
}

int Application::run() {
    LOG_INFO("Displaying Main Window...");
    m_mainWindow->show();
    return m_qtApp->exec();
}

} // namespace sentinel::app
