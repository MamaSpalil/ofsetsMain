/*
 * TraceViewer.cpp - SharedMemory reader implementation
 *
 * Compile: MSVC 2019+ (v142), C++17, Win32/x64
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>

#include "TraceViewer.h"

#include <cstdio>
#include <algorithm>

namespace MuTracker {

/* ================================================================== */
/*  Constructor / Destructor                                           */
/* ================================================================== */

TraceViewer::TraceViewer()
    : m_hMapping(nullptr)
    , m_pHeader(nullptr)
    , m_connected(false)
    , m_stats{}
{
}

TraceViewer::~TraceViewer()
{
    Disconnect();
}

/* ================================================================== */
/*  Connect / Disconnect                                               */
/* ================================================================== */

bool TraceViewer::Connect()
{
    if (m_connected) {
        return true;
    }

    m_hMapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE,
                                   MUTRACKER_SHMEM_NAME);
    if (!m_hMapping) {
        return false;
    }

    void* pView = MapViewOfFile(m_hMapping, FILE_MAP_ALL_ACCESS,
                                 0, 0, MUTRACKER_SHMEM_SIZE);
    if (!pView) {
        CloseHandle(m_hMapping);
        m_hMapping = nullptr;
        return false;
    }

    m_pHeader = static_cast<SharedMemHeader*>(pView);

    /* Validate magic */
    if (!IsSharedMemValid(m_pHeader)) {
        UnmapViewOfFile(m_pHeader);
        CloseHandle(m_hMapping);
        m_pHeader = nullptr;
        m_hMapping = nullptr;
        return false;
    }

    m_connected = true;
    return true;
}

void TraceViewer::Disconnect()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_pHeader) {
        UnmapViewOfFile(m_pHeader);
        m_pHeader = nullptr;
    }
    if (m_hMapping) {
        CloseHandle(m_hMapping);
        m_hMapping = nullptr;
    }
    m_connected = false;
    m_entries.clear();
    m_gameEvents.clear();
}

/* ================================================================== */
/*  Update - Read latest data from shared memory                       */
/* ================================================================== */

bool TraceViewer::Update()
{
    if (!m_connected || !m_pHeader) {
        /* Try reconnecting */
        if (!Connect()) {
            return false;
        }
    }

    std::lock_guard<std::mutex> lock(m_mutex);

    /* Read stats */
    m_stats.hookedFunctions = m_pHeader->activeHookCount;
    m_stats.totalCalls      = m_pHeader->totalCalls;
    m_stats.droppedRecords  = m_pHeader->droppedRecords;
    m_stats.uptimeMs        = m_pHeader->uptimeMs;
    m_stats.dllConnected    = m_pHeader->dllReady;
    m_stats.tracingActive   = m_pHeader->tracingEnabled;
    m_stats.targetPid       = m_pHeader->injectedPid;
    m_stats.functionCount   = m_pHeader->functionCount;
    m_stats.moduleCount     = m_pHeader->moduleCount;
    m_stats.variableCount   = m_pHeader->variableCount;
    m_stats.totalGameActions = m_pHeader->totalGameActions;
    m_stats.recentGameEvents = m_pHeader->gameEventCount;

    /* Copy database file path */
    char dbBuf[256];
    strncpy(dbBuf, (const char*)m_pHeader->dbFilePath, sizeof(dbBuf) - 1);
    dbBuf[sizeof(dbBuf) - 1] = '\0';
    m_stats.dbFilePath = dbBuf;

    /* Count changed variables */
    m_stats.changedVariables = 0;
    uint32_t varCount = m_pHeader->variableCount;
    if (varCount > MUTRACKER_MAX_VARIABLES) {
        varCount = MUTRACKER_MAX_VARIABLES;
    }
    for (uint32_t v = 0; v < varCount; ++v) {
        if (m_pHeader->variables[v].changed) {
            m_stats.changedVariables++;
        }
    }

    /* Copy status text safely */
    char buf[256];
    strncpy(buf, (const char*)m_pHeader->statusText, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    m_stats.statusText = buf;

    /* Read function entries */
    uint32_t count = m_pHeader->functionCount;
    if (count > MUTRACKER_MAX_FUNCTIONS) {
        count = MUTRACKER_MAX_FUNCTIONS;
    }

    m_entries.clear();
    m_entries.reserve(count);

    for (uint32_t i = 0; i < count; ++i) {
        const auto& src = m_pHeader->functions[i];
        TraceViewEntry entry;
        entry.address     = src.address;
        entry.offset      = src.offset;
        entry.totalCalls  = src.totalCalls;
        entry.callsPerSec = src.callsPerSecond;
        entry.threadId    = src.lastThreadId;
        entry.hooked      = src.isHooked;

        /* Safe string copy */
        char nameBuf[128];
        strncpy(nameBuf, src.name, sizeof(nameBuf) - 1);
        nameBuf[sizeof(nameBuf) - 1] = '\0';
        entry.name = nameBuf;

        char modBuf[64];
        strncpy(modBuf, src.moduleName, sizeof(modBuf) - 1);
        modBuf[sizeof(modBuf) - 1] = '\0';
        entry.moduleName = modBuf;

        m_entries.push_back(entry);
    }

    /* Sort by total calls (descending) */
    std::sort(m_entries.begin(), m_entries.end(),
        [](const TraceViewEntry& a, const TraceViewEntry& b) {
            return a.totalCalls > b.totalCalls;
        });

    /* Read game action events */
    uint32_t evtCount = m_pHeader->gameEventCount;
    if (evtCount > MUTRACKER_MAX_GAME_EVENTS) {
        evtCount = MUTRACKER_MAX_GAME_EVENTS;
    }

    m_gameEvents.clear();
    m_gameEvents.reserve(evtCount);

    for (uint32_t i = 0; i < evtCount; ++i) {
        const auto& src = m_pHeader->gameEvents[i];
        GameActionViewEntry ge;
        ge.actionType = src.actionType;
        ge.timestamp  = src.timestamp;
        ge.offset     = src.offset;
        ge.offsetFound   = src.offsetFound;
        ge.functionFound = src.functionFound;
        ge.variableFound = src.variableFound;
        ge.moduleFound   = src.moduleFound;

        char descBuf[256];
        strncpy(descBuf, src.description, sizeof(descBuf) - 1);
        descBuf[sizeof(descBuf) - 1] = '\0';
        ge.description = descBuf;

        char fnBuf[128];
        strncpy(fnBuf, src.functionName, sizeof(fnBuf) - 1);
        fnBuf[sizeof(fnBuf) - 1] = '\0';
        ge.functionName = fnBuf;

        char vnBuf[128];
        strncpy(vnBuf, src.variableName, sizeof(vnBuf) - 1);
        vnBuf[sizeof(vnBuf) - 1] = '\0';
        ge.variableName = vnBuf;

        char mnBuf[64];
        strncpy(mnBuf, src.moduleName, sizeof(mnBuf) - 1);
        mnBuf[sizeof(mnBuf) - 1] = '\0';
        ge.moduleName = mnBuf;

        m_gameEvents.push_back(ge);
    }

    return true;
}

/* ================================================================== */
/*  Getters (thread-safe)                                              */
/* ================================================================== */

std::vector<TraceViewEntry> TraceViewer::GetEntries() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_entries;
}

TraceViewStats TraceViewer::GetStats() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_stats;
}

std::vector<GameActionViewEntry> TraceViewer::GetGameEvents() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_gameEvents;
}

/* ================================================================== */
/*  Export CSV                                                          */
/* ================================================================== */

bool TraceViewer::ExportCSV(const std::wstring& filePath) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    FILE* fp = nullptr;
    _wfopen_s(&fp, filePath.c_str(), L"w");
    if (!fp) {
        return false;
    }

    /* Functions header */
    fprintf(fp, "=== Functions (starting base = 0, populated from main.exe) ===\n");
    fprintf(fp, "Offset,Address,Name,Module,TotalCalls,Calls/sec,ThreadID,Hooked\n");

    /* Data rows */
    for (const auto& e : m_entries) {
        fprintf(fp, "0x%08X,0x%08X,%s,%s,%llu,%u,%u,%s\n",
                static_cast<uint32_t>(e.offset),
                static_cast<uint32_t>(e.address),
                e.name.c_str(),
                e.moduleName.c_str(),
                static_cast<unsigned long long>(e.totalCalls),
                e.callsPerSec,
                e.threadId,
                e.hooked ? "Yes" : "No");
    }

    /* Modules section */
    if (m_pHeader && m_pHeader->moduleCount > 0) {
        fprintf(fp, "\n=== Modules ===\n");
        fprintf(fp, "BaseAddress,Size,Name,Path,IsMain\n");
        uint32_t modCount = m_pHeader->moduleCount;
        if (modCount > MUTRACKER_MAX_MODULES) modCount = MUTRACKER_MAX_MODULES;
        for (uint32_t i = 0; i < modCount; ++i) {
            const auto& mod = m_pHeader->modules[i];
            fprintf(fp, "0x%08X,0x%08X,%s,%s,%s\n",
                    static_cast<uint32_t>(mod.baseAddress),
                    mod.sizeOfImage,
                    mod.moduleName,
                    mod.modulePath,
                    mod.isMainExe ? "Yes" : "No");
        }
    }

    /* Variables section */
    if (m_pHeader && m_pHeader->variableCount > 0) {
        fprintf(fp, "\n=== Variables (tracked from .data section) ===\n");
        fprintf(fp, "Address,Offset,Name,Module,CurrentValue,PreviousValue,Changed\n");
        uint32_t varCount = m_pHeader->variableCount;
        if (varCount > MUTRACKER_MAX_VARIABLES) varCount = MUTRACKER_MAX_VARIABLES;
        for (uint32_t i = 0; i < varCount; ++i) {
            const auto& var = m_pHeader->variables[i];
            fprintf(fp, "0x%08X,0x%08X,%s,%s,0x%08X,0x%08X,%s\n",
                    static_cast<uint32_t>(var.address),
                    static_cast<uint32_t>(var.offset),
                    var.name,
                    var.moduleName,
                    var.currentValue,
                    var.previousValue,
                    var.changed ? "Yes" : "No");
        }
    }

    /* Game Action Events section */
    if (!m_gameEvents.empty()) {
        fprintf(fp, "\n=== Game Action Events (total: %llu) ===\n",
                static_cast<unsigned long long>(m_stats.totalGameActions));
        fprintf(fp, "Timestamp,ActionType,Description,Offset,Function,Variable,Module,"
                    "OffsetFound,FuncFound,VarFound,ModFound\n");
        for (const auto& ge : m_gameEvents) {
            fprintf(fp, "%llu,%u,%s,0x%08X,%s,%s,%s,%s,%s,%s,%s\n",
                    static_cast<unsigned long long>(ge.timestamp),
                    ge.actionType,
                    ge.description.c_str(),
                    static_cast<uint32_t>(ge.offset),
                    ge.functionName.c_str(),
                    ge.variableName.c_str(),
                    ge.moduleName.c_str(),
                    ge.offsetFound   ? "Yes" : "No",
                    ge.functionFound ? "Yes" : "No",
                    ge.variableFound ? "Yes" : "No",
                    ge.moduleFound   ? "Yes" : "No");
        }
    }

    fclose(fp);
    return true;
}

/* ================================================================== */
/*  Clear                                                              */
/* ================================================================== */

void TraceViewer::Clear()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_entries.clear();
    m_gameEvents.clear();
    m_stats = {};
}

} /* namespace MuTracker */
