/*
 * CallTracer.cpp - Function Call Tracer Implementation
 */

#include "CallTracer.h"
#include "HookEngine.h"
#include "MemoryUtils.h"
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>

namespace MuTracker {

CallTracer::CallTracer()
    : m_hookEngine(nullptr)
    , m_memory(nullptr)
    , m_mode(TraceMode::Frequency)
    , m_initialized(false)
    , m_maxRecentCalls(10000)
    , m_recentCallIndex(0)
    , m_totalCalls(0)
    , m_startTime(0)
    , m_lastUpdateTime(0)
    , m_eventsDropped(0)
{
}

CallTracer::~CallTracer()
{
    Shutdown();
}

bool CallTracer::Init(HookEngine* hookEngine, MemoryUtils* memory,
                       TraceMode mode)
{
    if (!hookEngine || !memory) return false;

    std::lock_guard<std::mutex> lock(m_mutex);
    m_hookEngine = hookEngine;
    m_memory = memory;
    m_mode = mode;
    m_startTime = GetTimestamp();
    m_lastUpdateTime = m_startTime;
    m_initialized = true;

    if (mode == TraceMode::Full) {
        m_recentCalls.resize(m_maxRecentCalls);
    }

    return true;
}

void CallTracer::Shutdown()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_functions.clear();
    m_recentCalls.clear();
    m_initialized = false;
}

void CallTracer::SetFilter(const TraceFilter& filter)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_filter = filter;
}

/* ------------------------------------------------------------------ */
/*  Call Recording                                                     */
/* ------------------------------------------------------------------ */

void CallTracer::RecordCall(uintptr_t address, uintptr_t caller,
                              uint32_t threadId, uintptr_t stackPtr)
{
    if (!m_initialized) return;

    /* Check filter */
    if (!PassesFilter(address)) {
        m_eventsDropped++;
        return;
    }

    m_totalCalls++;
    uint64_t now = GetTimestamp();

    std::lock_guard<std::mutex> lock(m_mutex);

    /* Update or create tracked function entry */
    auto it = m_functions.find(address);
    if (it == m_functions.end()) {
        TrackedFunction func;
        func.address = address;
        func.name = "";
        func.moduleName = "";
        func.totalCalls = 1;
        func.firstSeen = now;
        func.lastSeen = now;
        func.hookId = 0;
        func.callsPerSecond = 0.0;
        func.isNew = true;

        /* Calculate offset from module base */
        for (const auto& mod : m_moduleBases) {
            if (address >= mod.second) {
                func.offset = address - mod.second;
                func.moduleName = mod.first;
                break;
            }
        }

        m_functions[address] = func;
    } else {
        it->second.totalCalls++;
        it->second.lastSeen = now;
        it->second.isNew = false;
    }

    /* Record full call details in Full trace mode */
    if (m_mode == TraceMode::Full && !m_recentCalls.empty()) {
        FunctionCallRecord record;
        record.address = address;
        record.offset = 0;
        record.callCount = m_functions[address].totalCalls.load();
        record.timestamp = now;
        record.threadId = threadId;
        record.callerAddress = caller;

        /* Calculate offset */
        auto funcIt = m_functions.find(address);
        if (funcIt != m_functions.end()) {
            record.offset = funcIt->second.offset;
            record.moduleName = funcIt->second.moduleName;
            record.symbolName = funcIt->second.name;
        }

        /* Capture arguments from stack */
        if (m_filter.captureArgs && stackPtr != 0 && m_memory) {
            for (uint8_t i = 0; i < m_filter.argCount; ++i) {
                uintptr_t arg = 0;
                /* In x86 cdecl/stdcall, args are at ESP+4, ESP+8, etc. */
                if (m_memory->ReadValue<uintptr_t>(
                        stackPtr + 4 + (i * sizeof(uintptr_t)), arg)) {
                    record.args.push_back(arg);
                }
            }
        }

        /* Circular buffer write */
        size_t idx = m_recentCallIndex % m_maxRecentCalls;
        m_recentCalls[idx] = record;
        m_recentCallIndex++;
    }
}

/* ------------------------------------------------------------------ */
/*  Query Functions                                                    */
/* ------------------------------------------------------------------ */

const TrackedFunction* CallTracer::GetFunction(uintptr_t address) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_functions.find(address);
    return (it != m_functions.end()) ? &it->second : nullptr;
}

std::vector<TrackedFunction> CallTracer::GetAllFunctions() const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    std::vector<TrackedFunction> result;
    result.reserve(m_functions.size());

    for (const auto& pair : m_functions) {
        result.push_back(pair.second);
    }

    /* Sort by call count (descending) */
    std::sort(result.begin(), result.end(),
              [](const TrackedFunction& a, const TrackedFunction& b) {
                  return a.totalCalls.load() > b.totalCalls.load();
              });

    return result;
}

std::vector<FunctionCallRecord> CallTracer::GetRecentCalls(size_t maxRecords) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    std::vector<FunctionCallRecord> result;
    if (m_recentCalls.empty()) return result;

    size_t count = std::min(maxRecords,
                             std::min(m_recentCallIndex, m_maxRecentCalls));
    result.reserve(count);

    /* Read from circular buffer, most recent first */
    for (size_t i = 0; i < count; ++i) {
        size_t idx = (m_recentCallIndex - 1 - i) % m_maxRecentCalls;
        if (m_recentCalls[idx].address != 0) {
            result.push_back(m_recentCalls[idx]);
        }
    }

    return result;
}

/* ------------------------------------------------------------------ */
/*  Statistics                                                         */
/* ------------------------------------------------------------------ */

void CallTracer::UpdateStats()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    uint64_t now = GetTimestamp();
    double elapsed = 0.0;

#ifdef _WIN32
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    elapsed = static_cast<double>(now - m_lastUpdateTime) /
              static_cast<double>(freq.QuadPart);
#endif

    if (elapsed <= 0.0) elapsed = 1.0;

    /* Update per-function call rates */
    for (auto& pair : m_functions) {
        TrackedFunction& func = pair.second;
        /* Simple rate calculation based on total calls / total time */
        double totalElapsed = static_cast<double>(now - func.firstSeen);
#ifdef _WIN32
        totalElapsed /= static_cast<double>(freq.QuadPart);
#endif
        if (totalElapsed > 0.0) {
            func.callsPerSecond = static_cast<double>(func.totalCalls.load()) /
                                  totalElapsed;
        }
    }

    m_lastUpdateTime = now;
}

TraceStats CallTracer::GetStats() const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    TraceStats stats;
    stats.totalCalls = m_totalCalls.load();
    stats.uniqueFunctions = m_functions.size();
    stats.eventsDropped = m_eventsDropped;
    stats.startTimestamp = m_startTime;

    uint64_t now = GetTimestamp();
    stats.elapsedSeconds = 0.0;

#ifdef _WIN32
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    stats.elapsedSeconds = static_cast<double>(now - m_startTime) /
                            static_cast<double>(freq.QuadPart);
#endif

    if (stats.elapsedSeconds > 0.0) {
        stats.avgCallsPerSec = static_cast<double>(stats.totalCalls) /
                                stats.elapsedSeconds;
    } else {
        stats.avgCallsPerSec = 0.0;
    }

    return stats;
}

void CallTracer::Reset()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_functions.clear();
    m_recentCallIndex = 0;
    m_totalCalls = 0;
    m_eventsDropped = 0;
    m_startTime = GetTimestamp();
    m_lastUpdateTime = m_startTime;

    if (m_mode == TraceMode::Full) {
        std::fill(m_recentCalls.begin(), m_recentCalls.end(),
                  FunctionCallRecord{});
    }
}

/* ------------------------------------------------------------------ */
/*  Export                                                             */
/* ------------------------------------------------------------------ */

bool CallTracer::Export(const char* filename, const char* format) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    std::ofstream file(filename);
    if (!file.is_open()) return false;

    std::string fmt = format;

    if (fmt == "json" || fmt == "jsonl") {
        /* JSON Lines format */
        for (const auto& pair : m_functions) {
            const TrackedFunction& func = pair.second;
            char buf[512];
            snprintf(buf, sizeof(buf),
                     "{\"address\":\"0x%08X\",\"offset\":\"0x%08X\","
                     "\"name\":\"%s\",\"module\":\"%s\","
                     "\"calls\":%" PRIu64 ",\"rate\":%.2f}",
                     static_cast<uint32_t>(func.address),
                     static_cast<uint32_t>(func.offset),
                     func.name.c_str(),
                     func.moduleName.c_str(),
                     func.totalCalls.load(),
                     func.callsPerSecond);
            file << buf << "\n";
        }
    } else if (fmt == "csv") {
        /* CSV format */
        file << "Address,Offset,Name,Module,TotalCalls,CallsPerSec\n";
        for (const auto& pair : m_functions) {
            const TrackedFunction& func = pair.second;
            char buf[512];
            snprintf(buf, sizeof(buf),
                     "0x%08X,0x%08X,%s,%s,%" PRIu64 ",%.2f",
                     static_cast<uint32_t>(func.address),
                     static_cast<uint32_t>(func.offset),
                     func.name.c_str(),
                     func.moduleName.c_str(),
                     func.totalCalls.load(),
                     func.callsPerSecond);
            file << buf << "\n";
        }
    } else {
        /* Log format (default) */
        time_t now = time(nullptr);
        struct tm* lt = localtime(&now);
        char timeStr[32];
        strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", lt);

        file << "=== MuTracker Call Trace Export ===\n";
        file << "Date: " << timeStr << "\n";
        file << "Total calls: " << m_totalCalls.load() << "\n";
        file << "Unique functions: " << m_functions.size() << "\n";
        file << "==========================================\n\n";

        /* Get sorted functions */
        std::vector<std::pair<uintptr_t, TrackedFunction>> sorted(
            m_functions.begin(), m_functions.end());
        std::sort(sorted.begin(), sorted.end(),
                  [](const auto& a, const auto& b) {
                      return a.second.totalCalls.load() > b.second.totalCalls.load();
                  });

        for (const auto& pair : sorted) {
            const TrackedFunction& func = pair.second;
            char buf[512];
            snprintf(buf, sizeof(buf),
                     "0x%08X (+0x%06X) %-30s | calls: %-8" PRIu64 " | rate: %.1f/s",
                     static_cast<uint32_t>(func.address),
                     static_cast<uint32_t>(func.offset),
                     func.name.empty() ? "<unknown>" : func.name.c_str(),
                     func.totalCalls.load(),
                     func.callsPerSecond);
            file << buf << "\n";
        }
    }

    return true;
}

void CallTracer::SetModuleBase(const std::string& moduleName,
                                uintptr_t baseAddress)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_moduleBases[moduleName] = baseAddress;
}

/* ------------------------------------------------------------------ */
/*  Internal Helpers                                                   */
/* ------------------------------------------------------------------ */

uint64_t CallTracer::GetTimestamp() const
{
#ifdef _WIN32
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    return static_cast<uint64_t>(counter.QuadPart);
#else
    return 0;
#endif
}

bool CallTracer::PassesFilter(uintptr_t address) const
{
    /* Address range filter */
    if (address < m_filter.rangeStart || address > m_filter.rangeEnd) {
        return false;
    }

    /* Module filter (if specified) */
    if (!m_filter.includeModules.empty()) {
        /* Check if address belongs to any included module */
        bool found = false;
        for (const auto& mod : m_moduleBases) {
            for (const auto& includeMod : m_filter.includeModules) {
                if (mod.first == includeMod) {
                    /* Simple check: address >= base (more precise would need size) */
                    if (address >= mod.second) {
                        found = true;
                        break;
                    }
                }
            }
            if (found) break;
        }
        if (!found) return false;
    }

    return true;
}

} /* namespace MuTracker */
