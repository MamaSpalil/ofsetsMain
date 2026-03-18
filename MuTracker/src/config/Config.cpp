/*
 * Config.cpp - Configuration Parser Implementation
 *
 * Simple JSON parser for MuTracker configuration.
 * Handles the config.json format without external dependencies.
 */

#include "Config.h"
#include <fstream>
#include <sstream>
#include <cstring>
#include <algorithm>
#include <cstdio>

namespace MuTracker {

Config::Config()
    : m_loaded(false)
{
}

Config::~Config()
{
}

/* ------------------------------------------------------------------ */
/*  JSON Helpers                                                       */
/* ------------------------------------------------------------------ */

std::string Config::Trim(const std::string& str)
{
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

std::string Config::ExtractString(const std::string& json, const std::string& key)
{
    /* Find "key" : "value" pattern */
    std::string searchKey = "\"" + key + "\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return "";

    pos = json.find(':', pos + searchKey.length());
    if (pos == std::string::npos) return "";

    pos = json.find('"', pos + 1);
    if (pos == std::string::npos) return "";

    size_t endPos = json.find('"', pos + 1);
    if (endPos == std::string::npos) return "";

    return json.substr(pos + 1, endPos - pos - 1);
}

int Config::ExtractInt(const std::string& json, const std::string& key, int defValue)
{
    std::string searchKey = "\"" + key + "\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return defValue;

    pos = json.find(':', pos + searchKey.length());
    if (pos == std::string::npos) return defValue;

    /* Skip whitespace after colon */
    pos++;
    while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t')) pos++;

    /* Parse number */
    if (pos >= json.length()) return defValue;

    /* Handle hex numbers (0x...) */
    if (pos + 1 < json.length() && json[pos] == '0' &&
        (json[pos+1] == 'x' || json[pos+1] == 'X')) {
        return static_cast<int>(strtoul(json.c_str() + pos, nullptr, 16));
    }

    return atoi(json.c_str() + pos);
}

bool Config::ExtractBool(const std::string& json, const std::string& key, bool defValue)
{
    std::string searchKey = "\"" + key + "\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return defValue;

    pos = json.find(':', pos + searchKey.length());
    if (pos == std::string::npos) return defValue;

    std::string rest = json.substr(pos + 1);
    rest = Trim(rest);

    if (rest.substr(0, 4) == "true") return true;
    if (rest.substr(0, 5) == "false") return false;

    return defValue;
}

/* ------------------------------------------------------------------ */
/*  JSON Parsing                                                       */
/* ------------------------------------------------------------------ */

bool Config::ParseJSON(const std::string& json)
{
    /* Extract target settings */
    m_config.processName = ExtractString(json, "process");
    if (m_config.processName.empty()) m_config.processName = "main.exe";

    m_config.windowTitle = ExtractString(json, "window_title");
    if (m_config.windowTitle.empty()) m_config.windowTitle = "MU";

    m_config.autoAttach = ExtractBool(json, "auto_attach", true);
    m_config.reconnectIntervalMs = static_cast<uint32_t>(
        ExtractInt(json, "reconnect_interval_ms", 2000));

    /* Extract hook settings */
    m_config.hookMode = ExtractString(json, "mode");
    if (m_config.hookMode.empty()) m_config.hookMode = "inline";

    m_config.scanOnAttach = ExtractBool(json, "scan_on_attach", true);

    /* Extract patterns from "patterns" array */
    size_t patternsPos = json.find("\"patterns\"");
    if (patternsPos != std::string::npos) {
        size_t arrStart = json.find('[', patternsPos);
        size_t arrEnd = json.find(']', arrStart);
        if (arrStart != std::string::npos && arrEnd != std::string::npos) {
            std::string patternsStr = json.substr(arrStart, arrEnd - arrStart + 1);

            /* Parse each pattern object {...} */
            size_t objStart = 0;
            while ((objStart = patternsStr.find('{', objStart)) != std::string::npos) {
                size_t objEnd = patternsStr.find('}', objStart);
                if (objEnd == std::string::npos) break;

                std::string patObj = patternsStr.substr(objStart, objEnd - objStart + 1);

                PatternConfig pat;
                pat.name = ExtractString(patObj, "name");
                pat.signature = ExtractString(patObj, "sig");
                pat.offset = ExtractInt(patObj, "offset", 0);

                if (!pat.name.empty() && !pat.signature.empty()) {
                    m_config.patterns.push_back(pat);
                }

                objStart = objEnd + 1;
            }
        }
    }

    /* Extract filter settings */
    m_config.minCallFrequency = static_cast<uint32_t>(
        ExtractInt(json, "min_call_frequency", 1));
    m_config.captureArgs = ExtractBool(json, "capture_args", true);
    m_config.captureStack = ExtractBool(json, "capture_stack", false);
    m_config.stackDepth = static_cast<uint8_t>(
        ExtractInt(json, "stack_depth", 8));

    /* Extract include_modules array */
    size_t modPos = json.find("\"include_modules\"");
    if (modPos != std::string::npos) {
        size_t arrStart = json.find('[', modPos);
        size_t arrEnd = json.find(']', arrStart);
        if (arrStart != std::string::npos && arrEnd != std::string::npos) {
            std::string modStr = json.substr(arrStart + 1, arrEnd - arrStart - 1);
            /* Parse comma-separated quoted strings */
            size_t qPos = 0;
            while ((qPos = modStr.find('"', qPos)) != std::string::npos) {
                size_t qEnd = modStr.find('"', qPos + 1);
                if (qEnd == std::string::npos) break;
                m_config.includeModules.push_back(
                    modStr.substr(qPos + 1, qEnd - qPos - 1));
                qPos = qEnd + 1;
            }
        }
    }

    /* Extract output settings */
    m_config.logFile = ExtractString(json, "log_file");
    if (m_config.logFile.empty()) m_config.logFile = "trace_output.log";

    m_config.realTimeUI = ExtractBool(json, "real_time_ui", true);

    m_config.logFormat = ExtractString(json, "log_format");
    if (m_config.logFormat.empty()) m_config.logFormat = "log";

    m_config.maxRecords = static_cast<size_t>(
        ExtractInt(json, "max_records", 100000));

    return true;
}

/* ------------------------------------------------------------------ */
/*  File I/O                                                           */
/* ------------------------------------------------------------------ */

bool Config::Load(const char* filename)
{
    std::ifstream file(filename);
    if (!file.is_open()) return false;

    std::stringstream ss;
    ss << file.rdbuf();
    std::string json = ss.str();

    if (json.empty()) return false;

    m_loaded = ParseJSON(json);
    return m_loaded;
}

bool Config::Save(const char* filename) const
{
    std::ofstream file(filename);
    if (!file.is_open()) return false;

    file << "{\n";
    file << "  \"target\": {\n";
    file << "    \"process\": \"" << m_config.processName << "\",\n";
    file << "    \"window_title\": \"" << m_config.windowTitle << "\",\n";
    file << "    \"auto_attach\": " << (m_config.autoAttach ? "true" : "false") << ",\n";
    file << "    \"reconnect_interval_ms\": " << m_config.reconnectIntervalMs << "\n";
    file << "  },\n";

    file << "  \"hooks\": {\n";
    file << "    \"mode\": \"" << m_config.hookMode << "\",\n";
    file << "    \"scan_on_attach\": " << (m_config.scanOnAttach ? "true" : "false") << ",\n";
    file << "    \"patterns\": [\n";
    for (size_t i = 0; i < m_config.patterns.size(); ++i) {
        const auto& pat = m_config.patterns[i];
        file << "      { \"name\": \"" << pat.name
             << "\", \"sig\": \"" << pat.signature
             << "\", \"offset\": " << pat.offset << " }";
        if (i + 1 < m_config.patterns.size()) file << ",";
        file << "\n";
    }
    file << "    ]\n";
    file << "  },\n";

    file << "  \"filter\": {\n";
    file << "    \"include_modules\": [";
    for (size_t i = 0; i < m_config.includeModules.size(); ++i) {
        if (i > 0) file << ", ";
        file << "\"" << m_config.includeModules[i] << "\"";
    }
    file << "],\n";
    file << "    \"min_call_frequency\": " << m_config.minCallFrequency << ",\n";
    file << "    \"capture_args\": " << (m_config.captureArgs ? "true" : "false") << ",\n";
    file << "    \"capture_stack\": " << (m_config.captureStack ? "true" : "false") << ",\n";
    file << "    \"stack_depth\": " << static_cast<int>(m_config.stackDepth) << "\n";
    file << "  },\n";

    file << "  \"output\": {\n";
    file << "    \"log_file\": \"" << m_config.logFile << "\",\n";
    file << "    \"real_time_ui\": " << (m_config.realTimeUI ? "true" : "false") << ",\n";
    file << "    \"log_format\": \"" << m_config.logFormat << "\",\n";
    file << "    \"max_records\": " << m_config.maxRecords << "\n";
    file << "  }\n";
    file << "}\n";

    return true;
}

bool Config::CreateDefault(const char* filename)
{
    Config cfg;
    /* Add some default MuOnline patterns */
    cfg.m_config.patterns.push_back({
        "FuncPrologue", "55 8B EC", 0 });
    cfg.m_config.patterns.push_back({
        "PlayerMove", "55 8B EC 83 EC ?? 56 57 8B F9", 0 });
    cfg.m_config.patterns.push_back({
        "AttackFunc", "55 8B EC 53 8B 5D 08 56", 0 });
    cfg.m_config.patterns.push_back({
        "RenderFrame", "55 8B EC 83 E4 F8 81 EC", 0 });

    cfg.m_config.includeModules.push_back("main.exe");

    return cfg.Save(filename);
}

/* ------------------------------------------------------------------ */
/*  Key-Value Access                                                   */
/* ------------------------------------------------------------------ */

std::string Config::GetString(const char* key, const char* defValue) const
{
    auto it = m_values.find(key);
    return (it != m_values.end()) ? it->second : defValue;
}

int Config::GetInt(const char* key, int defValue) const
{
    auto it = m_values.find(key);
    if (it == m_values.end()) return defValue;
    return atoi(it->second.c_str());
}

bool Config::GetBool(const char* key, bool defValue) const
{
    auto it = m_values.find(key);
    if (it == m_values.end()) return defValue;
    return it->second == "true" || it->second == "1";
}

} /* namespace MuTracker */
