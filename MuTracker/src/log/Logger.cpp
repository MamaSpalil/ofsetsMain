/*
 * Logger.cpp - MuTracker Logging System Implementation
 */

#include "Logger.h"
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#endif

namespace MuTracker {

Logger& Logger::Instance()
{
    static Logger instance;
    return instance;
}

Logger::Logger()
    : m_initialized(false)
    , m_consoleOutput(true)
    , m_minLevel(LogLevel::Info)
#ifdef _WIN32
    , m_consoleHandle(nullptr)
#endif
{
}

Logger::~Logger()
{
    Shutdown();
}

bool Logger::Init(const char* logFile, bool consoleOutput, LogLevel minLevel)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    m_consoleOutput = consoleOutput;
    m_minLevel = minLevel;

#ifdef _WIN32
    if (consoleOutput) {
        m_consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);

        /* Set console buffer size */
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (GetConsoleScreenBufferInfo(static_cast<HANDLE>(m_consoleHandle), &csbi)) {
            COORD bufferSize;
            bufferSize.X = 180;
            bufferSize.Y = 9999;
            SetConsoleScreenBufferSize(static_cast<HANDLE>(m_consoleHandle), bufferSize);
        }
    }
#endif

    if (logFile) {
        m_logFile.open(logFile, std::ios::out | std::ios::trunc);
        if (m_logFile.is_open()) {
            /* Write header */
            std::string ts = GetTimestamp();
            m_logFile << "=== MuTracker Log Started: " << ts << " ===" << std::endl;
            m_logFile << "================================================" << std::endl;
        }
    }

    m_initialized = true;
    return true;
}

void Logger::Shutdown()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_logFile.is_open()) {
        std::string ts = GetTimestamp();
        m_logFile << "================================================" << std::endl;
        m_logFile << "=== MuTracker Log Ended: " << ts << " ===" << std::endl;
        m_logFile.close();
    }

    m_initialized = false;
}

/* ------------------------------------------------------------------ */
/*  Logging Functions                                                  */
/* ------------------------------------------------------------------ */

void Logger::Log(LogLevel level, const char* fmt, ...)
{
    if (!m_initialized || level < m_minLevel) return;

    char buffer[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    std::string ts = GetTimestamp();
    const char* lvl = GetLevelString(level);
    LogColor color = GetLevelColor(level);

    char fullMsg[2560];
    snprintf(fullMsg, sizeof(fullMsg), "[%s] [%s] %s\n", ts.c_str(), lvl, buffer);

    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_consoleOutput) {
        WriteToConsole(color, fullMsg);
    }
    WriteToFile(fullMsg);
}

void Logger::LogColored(LogColor color, const char* fmt, ...)
{
    if (!m_initialized) return;

    char buffer[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    /* Add newline */
    size_t len = strlen(buffer);
    if (len < sizeof(buffer) - 1 && (len == 0 || buffer[len-1] != '\n')) {
        buffer[len] = '\n';
        buffer[len+1] = '\0';
    }

    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_consoleOutput) {
        WriteToConsole(color, buffer);
    }
    WriteToFile(buffer);
}

void Logger::LogHeader(const char* title)
{
    if (!m_initialized) return;

    char line[256];
    size_t titleLen = strlen(title);
    size_t padLen = (60 > titleLen + 4) ? (60 - titleLen - 4) / 2 : 0;

    std::lock_guard<std::mutex> lock(m_mutex);

    /* Top separator */
    memset(line, '=', 64);
    line[64] = '\n';
    line[65] = '\0';
    WriteToConsole(LogColor::Yellow, line);
    WriteToFile(line);

    /* Title with padding */
    char titleLine[256];
    snprintf(titleLine, sizeof(titleLine), "%*s %s %*s\n",
             (int)padLen, "", title, (int)padLen, "");
    WriteToConsole(LogColor::Yellow, titleLine);
    WriteToFile(titleLine);

    /* Bottom separator */
    WriteToConsole(LogColor::Yellow, line);
    WriteToFile(line);
}

void Logger::LogOffset(uintptr_t va, uintptr_t offset,
                         const char* type, const char* name,
                         const char* extra)
{
    if (!m_initialized) return;

    char buffer[512];
    if (extra) {
        snprintf(buffer, sizeof(buffer),
                 "  0x%08X (+0x%06X) [%-4s] %-40s | %s\n",
                 static_cast<uint32_t>(va),
                 static_cast<uint32_t>(offset),
                 type, name, extra);
    } else {
        snprintf(buffer, sizeof(buffer),
                 "  0x%08X (+0x%06X) [%-4s] %s\n",
                 static_cast<uint32_t>(va),
                 static_cast<uint32_t>(offset),
                 type, name);
    }

    LogColor color = LogColor::Default;
    if (strcmp(type, "FUNC") == 0) color = LogColor::Blue;
    else if (strcmp(type, "CALL") == 0) color = LogColor::Green;
    else if (strcmp(type, "VAR") == 0) color = LogColor::Red;
    else if (strcmp(type, "IAT") == 0) color = LogColor::Magenta;

    std::lock_guard<std::mutex> lock(m_mutex);
    WriteToConsole(color, buffer);
    WriteToFile(buffer);
}

void Logger::LogCall(uintptr_t address, uintptr_t offset,
                       const char* name, uint32_t threadId,
                       uint64_t callCount,
                       const uintptr_t* args, uint8_t argCount)
{
    if (!m_initialized) return;

    std::string ts = GetTimestamp();
    char buffer[1024];

    /* Format: [TIME] [CALL] [TID:XXXX] 0xADDR (+0xOFFSET) Name | calls: N */
    int pos = snprintf(buffer, sizeof(buffer),
                       "[%s] [CALL] [TID:%04X] 0x%08X (+0x%06X) %-24s | calls: %-8llu",
                       ts.c_str(),
                       threadId,
                       static_cast<uint32_t>(address),
                       static_cast<uint32_t>(offset),
                       name ? name : "<unknown>",
                       static_cast<unsigned long long>(callCount));

    /* Append arguments if provided */
    if (args && argCount > 0 && pos >= 0 &&
        static_cast<size_t>(pos) < sizeof(buffer) - 32) {
        int written = snprintf(buffer + pos, sizeof(buffer) - pos, " | args: [");
        if (written > 0) pos += (static_cast<size_t>(pos + written) < sizeof(buffer)) ? written : 0;
        for (uint8_t i = 0; i < argCount && static_cast<size_t>(pos) < sizeof(buffer) - 16; ++i) {
            if (i > 0) {
                written = snprintf(buffer + pos, sizeof(buffer) - pos, ", ");
                if (written > 0 && static_cast<size_t>(pos + written) < sizeof(buffer)) pos += written;
            }
            written = snprintf(buffer + pos, sizeof(buffer) - pos,
                               "0x%X", static_cast<uint32_t>(args[i]));
            if (written > 0 && static_cast<size_t>(pos + written) < sizeof(buffer)) pos += written;
        }
        written = snprintf(buffer + pos, sizeof(buffer) - pos, "]");
        if (written > 0 && static_cast<size_t>(pos + written) < sizeof(buffer)) pos += written;
    }

    /* Add newline */
    if (pos < static_cast<int>(sizeof(buffer)) - 1) {
        buffer[pos++] = '\n';
        buffer[pos] = '\0';
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    WriteToConsole(LogColor::Green, buffer);
    WriteToFile(buffer);
}

/* ------------------------------------------------------------------ */
/*  Internal Helpers                                                   */
/* ------------------------------------------------------------------ */

std::string Logger::GetTimestamp() const
{
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    struct tm lt;
#ifdef _WIN32
    localtime_s(&lt, &time);
#else
    localtime_r(&time, &lt);
#endif

    char buf[32];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
             lt.tm_year + 1900, lt.tm_mon + 1, lt.tm_mday,
             lt.tm_hour, lt.tm_min, lt.tm_sec,
             static_cast<int>(ms.count()));
    return buf;
}

const char* Logger::GetLevelString(LogLevel level) const
{
    switch (level) {
    case LogLevel::Trace: return "TRACE";
    case LogLevel::Debug: return "DEBUG";
    case LogLevel::Info:  return "INFO ";
    case LogLevel::Warn:  return "WARN ";
    case LogLevel::Error: return "ERROR";
    case LogLevel::Fatal: return "FATAL";
    default:              return "?????";
    }
}

LogColor Logger::GetLevelColor(LogLevel level) const
{
    switch (level) {
    case LogLevel::Trace: return LogColor::Gray;
    case LogLevel::Debug: return LogColor::Cyan;
    case LogLevel::Info:  return LogColor::White;
    case LogLevel::Warn:  return LogColor::Yellow;
    case LogLevel::Error: return LogColor::Red;
    case LogLevel::Fatal: return LogColor::Red;
    default:              return LogColor::Default;
    }
}

void Logger::SetConsoleColor(LogColor color)
{
#ifdef _WIN32
    if (m_consoleHandle) {
        SetConsoleTextAttribute(static_cast<HANDLE>(m_consoleHandle),
                                static_cast<WORD>(color));
    }
#endif
}

void Logger::ResetConsoleColor()
{
    SetConsoleColor(LogColor::Default);
}

void Logger::WriteToConsole(LogColor color, const char* text)
{
#ifdef _WIN32
    SetConsoleColor(color);
    DWORD written;
    WriteConsoleA(static_cast<HANDLE>(m_consoleHandle),
                  text, static_cast<DWORD>(strlen(text)), &written, nullptr);
    ResetConsoleColor();
#else
    printf("%s", text);
#endif
}

void Logger::WriteToFile(const char* text)
{
    if (m_logFile.is_open()) {
        m_logFile << text;
        m_logFile.flush();
    }
}

} /* namespace MuTracker */
