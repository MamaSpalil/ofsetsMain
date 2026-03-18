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

    /* Header */
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
    m_stats = {};
}

} /* namespace MuTracker */
