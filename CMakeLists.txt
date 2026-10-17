cmake_minimum_required(VERSION 3.22)

project(Sentinel
    VERSION 1.0.0
    DESCRIPTION "Windows Endpoint Security Posture Analyzer"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Enable strict warning flags
if (MSVC)
    add_compile_options(/W4 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Find Qt 6
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC OFF)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Core sources
set(SENTINEL_SOURCES
    src/main.cpp
    src/app/Application.h
    src/app/Application.cpp
    src/core/Logger.h
    src/platform/windows/SystemInfo.h
    src/platform/windows/SystemInfo.cpp
    src/platform/windows/WinRaii.h
    src/platform/windows/StringEncoding.h
    src/collectors/SystemCollector.h
    src/collectors/SystemCollector.cpp
    src/collectors/NetworkCollector.h
    src/collectors/NetworkCollector.cpp
    src/collectors/ServiceCollector.h
    src/collectors/ServiceCollector.cpp
    src/collectors/FirewallCollector.h
    src/collectors/FirewallCollector.cpp
    src/collectors/DefenderCollector.h
    src/collectors/DefenderCollector.cpp
    src/collectors/AccountCollector.h
    src/collectors/AccountCollector.cpp
    src/collectors/AuthenticationCollector.h
    src/collectors/AuthenticationCollector.cpp
    src/collectors/EncryptionCollector.h
    src/collectors/EncryptionCollector.cpp
    src/collectors/UpdateCollector.h
    src/collectors/UpdateCollector.cpp
    src/rules/DefaultRules.h
    src/rules/DefaultRules.cpp
    src/rules/RuleEngine.h
    src/rules/RuleEngine.cpp
    src/app/ScanController.h
    src/app/ScanController.cpp
    src/storage/DatabaseManager.h
    src/storage/DatabaseManager.cpp
    src/storage/DatabaseMigrator.h
    src/storage/DatabaseMigrator.cpp
    src/storage/ScanRepository.h
    src/storage/ScanRepository.cpp
    src/storage/FindingRepository.h
    src/storage/FindingRepository.cpp
    src/storage/SettingsRepository.h
    src/storage/SettingsRepository.cpp
    src/storage/PersistenceService.h
    src/storage/PersistenceService.cpp
    src/ui/ScanHistoryDialog.h
    src/ui/ScanHistoryDialog.cpp
    src/ui/ScoreWidget.h
    src/ui/ScoreWidget.cpp
    src/ui/ScanProgressWidget.h
    src/ui/ScanProgressWidget.cpp
    src/ui/FindingDetailDialog.h
    src/ui/FindingDetailDialog.cpp
    src/ui/FindingsWidget.h
    src/ui/FindingsWidget.cpp
    src/ui/CategorySummaryWidget.h
    src/ui/CategorySummaryWidget.cpp
    src/ui/CollectorStatusWidget.h
    src/ui/CollectorStatusWidget.cpp
    src/ui/ScoreBreakdownDialog.h
    src/ui/ScoreBreakdownDialog.cpp
    src/ui/DashboardWidget.h
    src/ui/DashboardWidget.cpp
    src/ui/MainWindow.h
    src/ui/MainWindow.cpp
)

# Main Executable target
add_executable(sentinel ${SENTINEL_SOURCES})

target_link_libraries(sentinel PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    sqlite3
)

if (WIN32)
    target_link_libraries(sentinel PRIVATE advapi32 iphlpapi ws2_32 ole32 oleaut32 netapi32 shell32)
endif()

# Unit testing target
enable_testing()

add_executable(sentinel_tests
    tests/unit/test_main.cpp
    src/platform/windows/SystemInfo.h
    src/platform/windows/SystemInfo.cpp
    src/platform/windows/WinRaii.h
    src/platform/windows/StringEncoding.h
    src/collectors/SystemCollector.h
    src/collectors/SystemCollector.cpp
    src/collectors/NetworkCollector.h
    src/collectors/NetworkCollector.cpp
    src/collectors/ServiceCollector.h
    src/collectors/ServiceCollector.cpp
    src/collectors/FirewallCollector.h
    src/collectors/FirewallCollector.cpp
    src/collectors/DefenderCollector.h
    src/collectors/DefenderCollector.cpp
    src/collectors/AccountCollector.h
    src/collectors/AccountCollector.cpp
    src/collectors/AuthenticationCollector.h
    src/collectors/AuthenticationCollector.cpp
    src/collectors/EncryptionCollector.h
    src/collectors/EncryptionCollector.cpp
    src/collectors/UpdateCollector.h
    src/collectors/UpdateCollector.cpp
    src/rules/DefaultRules.h
    src/rules/DefaultRules.cpp
    src/rules/RuleEngine.h
    src/rules/RuleEngine.cpp
    src/storage/DatabaseManager.h
    src/storage/DatabaseManager.cpp
    src/storage/DatabaseMigrator.h
    src/storage/DatabaseMigrator.cpp
    src/storage/ScanRepository.h
    src/storage/ScanRepository.cpp
    src/storage/FindingRepository.h
    src/storage/FindingRepository.cpp
    src/storage/SettingsRepository.h
    src/storage/SettingsRepository.cpp
    src/storage/PersistenceService.h
    src/storage/PersistenceService.cpp
    src/core/Logger.h
)

target_link_libraries(sentinel_tests PRIVATE
    sqlite3
)

if (MSVC)
    target_compile_options(sentinel_tests PRIVATE /UNDEBUG)
else()
    target_compile_options(sentinel_tests PRIVATE -UNDEBUG)
endif()

if (WIN32)
    target_link_libraries(sentinel_tests PRIVATE advapi32 iphlpapi ws2_32 ole32 oleaut32 netapi32 shell32)
endif()

add_test(NAME SentinelUnitTests COMMAND sentinel_tests)

get_target_property(SENTINEL_TEST_SOURCE_LIST sentinel_tests SOURCES)
add_executable(sentinel_integration_tests ${SENTINEL_TEST_SOURCE_LIST})
target_compile_definitions(sentinel_integration_tests PRIVATE SENTINEL_INTEGRATION_TESTS)
target_link_libraries(sentinel_integration_tests PRIVATE sqlite3)

if (MSVC)
    target_compile_options(sentinel_integration_tests PRIVATE /UNDEBUG)
else()
    target_compile_options(sentinel_integration_tests PRIVATE -UNDEBUG)
endif()

if (WIN32)
    target_link_libraries(sentinel_integration_tests PRIVATE advapi32 iphlpapi ws2_32 ole32 oleaut32 netapi32 shell32)
endif()

add_test(NAME SentinelWindowsIntegrationTests COMMAND sentinel_integration_tests)
