#include "app/Application.h"
#include "core/Logger.h"

int main(int argc, char* argv[]) {
    sentinel::core::Logger::instance().setLogFile("sentinel.log");
    LOG_INFO("Sentinel Endpoint Security Posture Analyzer starting up...");

    sentinel::app::Application app(argc, argv);
    return app.run();
}
