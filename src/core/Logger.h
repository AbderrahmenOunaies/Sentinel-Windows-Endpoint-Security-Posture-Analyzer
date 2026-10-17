#pragma once

#include <string>
#include <string_view>
#include <format>
#include <iostream>
#include <fstream>
#include <mutex>
#include <chrono>

namespace sentinel::core {

enum class LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Security
};

class Logger {
public:
    static Logger& instance() {
        static Logger s_instance;
        return s_instance;
    }

    void log(LogLevel level, std::string_view message) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);
        std::tm tm_buf{};
#if defined(_WIN32)
        localtime_s(&tm_buf, &time_t_now);
#else
        localtime_r(&time_t_now, &tm_buf);
#endif

        char time_str[32];
        std::strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);

        std::string line = std::format("[{}] [{}] {}\n", time_str, levelToString(level), message);
        std::cout << line;

        if (m_fileStream.is_open()) {
            m_fileStream << line;
            m_fileStream.flush();
        }
    }

    void setLogFile(const std::string& path) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_fileStream.is_open()) {
            m_fileStream.close();
        }
        m_fileStream.open(path, std::ios::out | std::ios::app);
    }

private:
    Logger() = default;
    ~Logger() {
        if (m_fileStream.is_open()) {
            m_fileStream.close();
        }
    }

    static constexpr std::string_view levelToString(LogLevel level) {
        switch (level) {
            case LogLevel::Debug:    return "DEBUG";
            case LogLevel::Info:     return "INFO";
            case LogLevel::Warning:  return "WARNING";
            case LogLevel::Error:    return "ERROR";
            case LogLevel::Security: return "SECURITY";
        }
        return "UNKNOWN";
    }

    std::mutex m_mutex;
    std::ofstream m_fileStream;
};

#define LOG_DEBUG(msg)    ::sentinel::core::Logger::instance().log(::sentinel::core::LogLevel::Debug, (msg))
#define LOG_INFO(msg)     ::sentinel::core::Logger::instance().log(::sentinel::core::LogLevel::Info, (msg))
#define LOG_WARNING(msg)  ::sentinel::core::Logger::instance().log(::sentinel::core::LogLevel::Warning, (msg))
#define LOG_ERROR(msg)    ::sentinel::core::Logger::instance().log(::sentinel::core::LogLevel::Error, (msg))
#define LOG_SECURITY(msg) ::sentinel::core::Logger::instance().log(::sentinel::core::LogLevel::Security, (msg))

} // namespace sentinel::core
