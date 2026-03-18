/*
 * CallTracer.h - Function Call Tracer
 *
 * Tracks function calls in real-time with counters, timestamps,
 * thread IDs, caller addresses, and argument capture.
 *
 * Provides multiple tracking modes:
 *   - Full trace: log every call with all details
 *   - Frequency: count calls per function
 *   - Filtered: track only specific address ranges
 *   - Differential: log only new/changed functions
 */

#ifndef MUTRACKER_CALL_TRACER_H
#define MUTRACKER_CALL_TRACER_H

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>

#ifdef _WIN32
#include <windows.h>
#endif

namespace MuTracker {

/* Forward declarations */
class HookEngine;
class MemoryUtils;

/* Tracing mode */
enum class TraceMode {
    Full,           /* Log every call with all details */
    Frequency,      /* Only count call frequency */
    Filtered,       /* Only functions matching filter */
    Differential    /* Only new/changed functions */
};

/* Single function call record */
struct FunctionCallRecord {
    uintptr_t       address;        /* Absolute function address */
    uintptr_t       offset;         /* Offset relative to module base */
    std::string     moduleName;     /* Module name */
    std::string     symbolName;     /* Symbol name (if available) */
    uint64_t        callCount;      /* Total call count */
    uint64_t        timestamp;      /* High-resolution timestamp (QPC) */
    uint32_t        threadId;       /* Thread that made the call */
    uintptr_t       callerAddress;  /* Return address (caller) */
    std::vector<uintptr_t> args;    /* Captured arguments (from stack) */
};

/* Function tracking entry (aggregated stats) */
struct TrackedFunction {
    uintptr_t       address;
    uintptr_t       offset;
    std::string     name;
    std::string     moduleName;
    std::atomic<uint64_t> totalCalls;
    uint64_t        firstSeen;      /* Timestamp of first call */
    uint64_t        lastSeen;       /* Timestamp of last call */
    uint32_t        hookId;         /* Associated hook ID */
    double          callsPerSecond; /* Computed call rate */
    bool            isNew;          /* Flag for differential mode */

    TrackedFunction()
        : address(0), offset(0), totalCalls(0), firstSeen(0),
          lastSeen(0), hookId(0), callsPerSecond(0.0), isNew(false) {}

    TrackedFunction(const TrackedFunction& other)
        : address(other.address), offset(other.offset), name(other.name),
          moduleName(other.moduleName), totalCalls(other.totalCalls.load()),
          firstSeen(other.firstSeen), lastSeen(other.lastSeen),
          hookId(other.hookId), callsPerSecond(other.callsPerSecond),
          isNew(other.isNew) {}

    TrackedFunction& operator=(const TrackedFunction& other) {
        if (this != &other) {
            address = other.address;
            offset = other.offset;
            name = other.name;
            moduleName = other.moduleName;
            totalCalls.store(other.totalCalls.load());
            firstSeen = other.firstSeen;
            lastSeen = other.lastSeen;
            hookId = other.hookId;
            callsPerSecond = other.callsPerSecond;
            isNew = other.isNew;
        }
        return *this;
    }
};

/* Filter specification */
struct TraceFilter {
    std::vector<std::string> includeModules;    /* Only these modules */
    uintptr_t       rangeStart;     /* Address range filter start */
    uintptr_t       rangeEnd;       /* Address range filter end */
    uint32_t        minCallFreq;    /* Minimum calls to report */
    bool            captureArgs;    /* Capture function arguments */
    uint8_t         argCount;       /* Number of args to capture */
    bool            captureStack;   /* Capture stack trace */
    uint8_t         stackDepth;     /* Stack trace depth */

    TraceFilter()
        : rangeStart(0), rangeEnd(0xFFFFFFFF), minCallFreq(0),
          captureArgs(false), argCount(4), captureStack(false),
          stackDepth(8) {}
};

/* Trace statistics */
struct TraceStats {
    uint64_t    totalCalls;
    uint64_t    uniqueFunctions;
    uint64_t    eventsDropped;
    double      avgCallsPerSec;
    uint64_t    startTimestamp;
    double      elapsedSeconds;
};

class CallTracer {
public:
    CallTracer();
    ~CallTracer();

    /*
     * Initialize the call tracer.
     *
     * @param hookEngine    Pointer to hook engine
     * @param memory        Pointer to memory utils
     * @param mode          Tracing mode
     * @return              true if initialized
     */
    bool Init(HookEngine* hookEngine, MemoryUtils* memory,
              TraceMode mode = TraceMode::Frequency);

    /* Shutdown and clean up */
    void Shutdown();

    /*
     * Set the trace filter.
     */
    void SetFilter(const TraceFilter& filter);

    /*
     * Record a function call.
     * Called from hook detour functions.
     *
     * @param address       Function address
     * @param caller        Caller return address
     * @param threadId      Calling thread ID
     * @param stackPtr      Stack pointer (for arg capture)
     */
    void RecordCall(uintptr_t address, uintptr_t caller,
                     uint32_t threadId, uintptr_t stackPtr = 0);

    /*
     * Get the current call record for a function.
     *
     * @param address   Function address
     * @return          Tracked function info, or nullptr if not tracked
     */
    const TrackedFunction* GetFunction(uintptr_t address) const;

    /*
     * Get all tracked functions, sorted by call count (descending).
     */
    std::vector<TrackedFunction> GetAllFunctions() const;

    /*
     * Get recent call records (full trace mode only).
     *
     * @param maxRecords    Maximum number of records to return
     * @return              Recent call records
     */
    std::vector<FunctionCallRecord> GetRecentCalls(size_t maxRecords = 100) const;

    /*
     * Update computed statistics (call rates, etc.)
     * Should be called periodically (e.g., once per second).
     */
    void UpdateStats();

    /*
     * Get overall trace statistics.
     */
    TraceStats GetStats() const;

    /*
     * Clear all recorded data.
     */
    void Reset();

    /*
     * Export trace data to a file.
     *
     * @param filename  Output file path
     * @param format    "json", "csv", or "log"
     * @return          true if exported
     */
    bool Export(const char* filename, const char* format = "log") const;

    /*
     * Set the module base address for offset calculation.
     *
     * @param moduleName    Module name
     * @param baseAddress   Module base address
     */
    void SetModuleBase(const std::string& moduleName, uintptr_t baseAddress);

private:
    HookEngine*     m_hookEngine;
    MemoryUtils*    m_memory;
    TraceMode       m_mode;
    TraceFilter     m_filter;
    bool            m_initialized;
    mutable std::mutex m_mutex;

    /* Tracked functions: address -> tracking info */
    std::unordered_map<uintptr_t, TrackedFunction> m_functions;

    /* Recent call log (circular buffer for full trace mode) */
    std::vector<FunctionCallRecord> m_recentCalls;
    size_t          m_maxRecentCalls;
    size_t          m_recentCallIndex;

    /* Statistics */
    std::atomic<uint64_t> m_totalCalls;
    uint64_t        m_startTime;
    uint64_t        m_lastUpdateTime;
    uint64_t        m_eventsDropped;

    /* Module bases for offset calculation */
    std::unordered_map<std::string, uintptr_t> m_moduleBases;

    /* Get high-resolution timestamp */
    uint64_t GetTimestamp() const;

    /* Check if address passes the current filter */
    bool PassesFilter(uintptr_t address) const;
};

} /* namespace MuTracker */

#endif /* MUTRACKER_CALL_TRACER_H */
