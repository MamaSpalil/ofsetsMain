/*
 * Config.h - Configuration Parser
 *
 * Simple JSON-like configuration parser without external dependencies.
 * Reads the MuTracker config.json file and provides typed access to settings.
 *
 * Note: This is a lightweight parser for the first implementation step.
 * For production use, consider nlohmann/json or RapidJSON.
 */

#ifndef MUTRACKER_CONFIG_H
#define MUTRACKER_CONFIG_H

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

namespace MuTracker {

/* Pattern definition from config */
struct PatternConfig {
    std::string     name;       /* Pattern name (e.g., "PlayerMove") */
    std::string     signature;  /* IDA-style signature */
    int             offset;     /* Offset from pattern match to hook point */
};

/* Address range for exclusion */
struct AddressRange {
    uintptr_t       from;
    uintptr_t       to;
};

/* Complete configuration */
struct TrackerConfig {
    /* Target settings */
    std::string     processName;        /* Default: "main.exe" */
    std::string     windowTitle;        /* Default: "MU" */
    bool            autoAttach;         /* Default: true */
    uint32_t        reconnectIntervalMs;/* Default: 2000 */

    /* Hook settings */
    std::string     hookMode;           /* "inline", "iat", or "hardware" */
    bool            scanOnAttach;       /* Auto-scan patterns on attach */
    std::vector<PatternConfig> patterns;

    /* Filter settings */
    std::vector<std::string> includeModules;
    std::vector<AddressRange> excludeRanges;
    uint32_t        minCallFrequency;   /* Default: 1 */
    bool            captureArgs;        /* Default: true */
    bool            captureStack;       /* Default: false */
    uint8_t         stackDepth;         /* Default: 8 */

    /* Output settings */
    std::string     logFile;            /* Default: "trace_output.log" */
    bool            realTimeUI;         /* Default: true */
    std::string     logFormat;          /* "json", "csv", "log" */
    size_t          maxRecords;         /* Default: 100000 */

    TrackerConfig()
        : processName("main.exe")
        , windowTitle("MU")
        , autoAttach(true)
        , reconnectIntervalMs(2000)
        , hookMode("inline")
        , scanOnAttach(true)
        , minCallFrequency(1)
        , captureArgs(true)
        , captureStack(false)
        , stackDepth(8)
        , logFile("trace_output.log")
        , realTimeUI(true)
        , logFormat("log")
        , maxRecords(100000)
    {}
};

class Config {
public:
    Config();
    ~Config();

    /*
     * Load configuration from a JSON file.
     *
     * @param filename  Path to config.json
     * @return          true if loaded successfully
     */
    bool Load(const char* filename);

    /*
     * Save current configuration to a JSON file.
     *
     * @param filename  Path to write
     * @return          true if saved
     */
    bool Save(const char* filename) const;

    /*
     * Create default configuration file.
     *
     * @param filename  Path to write
     * @return          true if created
     */
    static bool CreateDefault(const char* filename);

    /*
     * Get the parsed configuration.
     */
    const TrackerConfig& Get() const { return m_config; }
    TrackerConfig& GetMutable() { return m_config; }

    /*
     * Get a string value by dot-separated key path.
     *
     * @param key       Key path (e.g., "target.process")
     * @param defValue  Default value if key not found
     * @return          Value
     */
    std::string GetString(const char* key, const char* defValue = "") const;

    /*
     * Get an integer value by key path.
     */
    int GetInt(const char* key, int defValue = 0) const;

    /*
     * Get a boolean value by key path.
     */
    bool GetBool(const char* key, bool defValue = false) const;

    /* Check if config was loaded */
    bool IsLoaded() const { return m_loaded; }

private:
    TrackerConfig   m_config;
    bool            m_loaded;

    /* Simple key-value store for raw parsed values */
    std::unordered_map<std::string, std::string> m_values;

    /* Internal: Parse simple JSON object */
    bool ParseJSON(const std::string& json);

    /* Internal: Extract string value from JSON */
    static std::string ExtractString(const std::string& json,
                                      const std::string& key);

    /* Internal: Extract number from JSON */
    static int ExtractInt(const std::string& json, const std::string& key,
                           int defValue);

    /* Internal: Extract boolean from JSON */
    static bool ExtractBool(const std::string& json, const std::string& key,
                             bool defValue);

    /* Internal: Trim whitespace */
    static std::string Trim(const std::string& str);
};

} /* namespace MuTracker */

#endif /* MUTRACKER_CONFIG_H */
