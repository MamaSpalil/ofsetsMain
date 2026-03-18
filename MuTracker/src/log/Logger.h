/*
 * Logger.h - MuTracker Logging System
 *
 * Thread-safe logging to console (with colors) and file with
 * timestamps, log levels, and formatted output.
 */

#ifndef MUTRACKER_LOGGER_H
#define MUTRACKER_LOGGER_H

#include <cstdint>
#include <string>
#include <mutex>
#include <fstream>

namespace MuTracker {

/* Log levels */
enum class LogLevel {
    Trace,      /* Detailed debugging */
    Debug,      /* Debug information */
    Info,       /* General information */
    Warn,       /* Warnings */
    Error,      /* Errors */
    Fatal       /* Fatal errors */
};

/* Console colors (Windows) */
enum class LogColor : uint16_t {
    Default     = 0x07,     /* White on black */
    Gray        = 0x08,
    Blue        = 0x09,
    Green       = 0x0A,
    Cyan        = 0x0B,
    Red         = 0x0C,
    Magenta     = 0x0D,
    Yellow      = 0x0E,
    White       = 0x0F,
    BrightGreen = 0x2A,
    BrightCyan  = 0x3B
};

class Logger {
public:
    /*
     * Get the singleton logger instance.
     */
    static Logger& Instance();

    /*
     * Initialize logging.
     *
     * @param logFile       Path to log file (nullptr for no file)
     * @param consoleOutput Enable console output
     * @param minLevel      Minimum log level to output
     * @return              true if initialized
     */
    bool Init(const char* logFile = "MuTracker.log",
              bool consoleOutput = true,
              LogLevel minLevel = LogLevel::Info);

    /* Shutdown and close log file */
    void Shutdown();

    /*
     * Write a log message.
     *
     * @param level     Log level
     * @param fmt       Printf-style format string
     * @param ...       Format arguments
     */
    void Log(LogLevel level, const char* fmt, ...);

    /*
     * Write a colored message to console (no file output).
     *
     * @param color     Console color
     * @param fmt       Printf-style format string
     * @param ...       Format arguments
     */
    void LogColored(LogColor color, const char* fmt, ...);

    /*
     * Write a section header (decorative separator).
     *
     * @param title     Section title
     */
    void LogHeader(const char* title);

    /*
     * Write an offset entry in standard format.
     *
     * @param va        Virtual address
     * @param offset    Offset from base
     * @param type      Entry type (e.g., "FUNC", "CALL", "VAR")
     * @param name      Entry name
     * @param extra     Extra info (e.g., call count, args)
     */
    void LogOffset(uintptr_t va, uintptr_t offset,
                    const char* type, const char* name,
                    const char* extra = nullptr);

    /*
     * Write a call trace entry in standard format.
     *
     * [TIMESTAMP] [CALL] [TID:XXXX] 0xADDR (+0xOFFSET) Name | calls: N | args: [...]
     *
     * @param address       Function address
     * @param offset        Offset from module base
     * @param name          Function name
     * @param threadId      Thread ID
     * @param callCount     Total call count
     * @param args          Argument values (optional)
     * @param argCount      Number of arguments
     */
    void LogCall(uintptr_t address, uintptr_t offset,
                  const char* name, uint32_t threadId,
                  uint64_t callCount,
                  const uintptr_t* args = nullptr,
                  uint8_t argCount = 0);

    /* Set minimum log level */
    void SetMinLevel(LogLevel level) { m_minLevel = level; }

    /* Get current log level */
    LogLevel GetMinLevel() const { return m_minLevel; }

private:
    Logger();
    ~Logger();
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    bool            m_initialized;
    bool            m_consoleOutput;
    LogLevel        m_minLevel;
    std::mutex      m_mutex;
    std::ofstream   m_logFile;

    #ifdef _WIN32
    void*           m_consoleHandle;    /* HANDLE */
    #endif

    /* Internal: get current timestamp string */
    std::string GetTimestamp() const;

    /* Internal: get log level string */
    const char* GetLevelString(LogLevel level) const;

    /* Internal: get log level color */
    LogColor GetLevelColor(LogLevel level) const;

    /* Internal: set console color */
    void SetConsoleColor(LogColor color);

    /* Internal: reset console color */
    void ResetConsoleColor();

    /* Internal: write to console with color */
    void WriteToConsole(LogColor color, const char* text);

    /* Internal: write to file */
    void WriteToFile(const char* text);
};

/* Convenience macros */
#define MULOG_TRACE(fmt, ...) MuTracker::Logger::Instance().Log(MuTracker::LogLevel::Trace, fmt, ##__VA_ARGS__)
#define MULOG_DEBUG(fmt, ...) MuTracker::Logger::Instance().Log(MuTracker::LogLevel::Debug, fmt, ##__VA_ARGS__)
#define MULOG_INFO(fmt, ...)  MuTracker::Logger::Instance().Log(MuTracker::LogLevel::Info,  fmt, ##__VA_ARGS__)
#define MULOG_WARN(fmt, ...)  MuTracker::Logger::Instance().Log(MuTracker::LogLevel::Warn,  fmt, ##__VA_ARGS__)
#define MULOG_ERROR(fmt, ...) MuTracker::Logger::Instance().Log(MuTracker::LogLevel::Error, fmt, ##__VA_ARGS__)
#define MULOG_FATAL(fmt, ...) MuTracker::Logger::Instance().Log(MuTracker::LogLevel::Fatal, fmt, ##__VA_ARGS__)

} /* namespace MuTracker */

#endif /* MUTRACKER_LOGGER_H */
