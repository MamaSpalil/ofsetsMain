/*
 * TraceViewer.h - SharedMemory reader and trace data manager
 *
 * Reads function call data from SharedMemory (populated by MuTrackerDLL)
 * and provides it to the MainWindow for display in the ListView.
 *
 * Compile: MSVC 2019+ (v142), C++17, Win32/x64
 */

#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <mutex>

#include "../../Shared/SharedStructs.h"

namespace MuTracker {

/* ================================================================== */
/*  Trace View Data (for GUI display)                                  */
/* ================================================================== */

struct TraceViewEntry {
    uintptr_t   address;
    uintptr_t   offset;
    std::string name;
    std::string moduleName;
    uint64_t    totalCalls;
    uint32_t    callsPerSec;
    uint32_t    threadId;
    bool        hooked;
};

struct TraceViewStats {
    uint32_t    hookedFunctions;
    uint64_t    totalCalls;
    uint32_t    droppedRecords;
    uint64_t    uptimeMs;
    bool        dllConnected;
    bool        tracingActive;
    DWORD       targetPid;
    std::string statusText;
    uint32_t    moduleCount;
    uint32_t    variableCount;
    uint32_t    functionCount;
    uint32_t    changedVariables;
};

/* ================================================================== */
/*  TraceViewer Class                                                   */
/* ================================================================== */

class TraceViewer {
public:
    TraceViewer();
    ~TraceViewer();

    /* Connect to / disconnect from shared memory */
    bool Connect();
    void Disconnect();
    bool IsConnected() const { return m_connected; }

    /* Read latest data from shared memory */
    bool Update();

    /* Get current view data (thread-safe) */
    std::vector<TraceViewEntry> GetEntries() const;
    TraceViewStats GetStats() const;

    /* Export to CSV file */
    bool ExportCSV(const std::wstring& filePath) const;

    /* Clear all entries */
    void Clear();

private:
    HANDLE              m_hMapping;
    SharedMemHeader*    m_pHeader;
    bool                m_connected;

    std::vector<TraceViewEntry> m_entries;
    TraceViewStats              m_stats;
    mutable std::mutex          m_mutex;
};

} /* namespace MuTracker */
