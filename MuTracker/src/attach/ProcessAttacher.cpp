/*
 * ProcessAttacher.cpp - Game Process Attachment Implementation
 */

#include "ProcessAttacher.h"
#include <cstring>
#include <algorithm>
#include <thread>
#include <chrono>

#ifdef _WIN32
#include <tlhelp32.h>
#endif

namespace MuTracker {

ProcessAttacher::ProcessAttacher()
    : m_watching(false)
    , m_watchPid(0)
{
}

ProcessAttacher::~ProcessAttacher()
{
    StopWatching();
}

/* ------------------------------------------------------------------ */
/*  Process Finding                                                    */
/* ------------------------------------------------------------------ */

uint32_t ProcessAttacher::FindProcessByName(const char* processName)
{
#ifdef _WIN32
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    uint32_t pid = 0;

    if (Process32First(snap, &pe)) {
        do {
            /* Case-insensitive comparison */
            if (_stricmp(pe.szExeFile, processName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
#else
    return 0;
#endif
}

std::vector<ProcessInfo> ProcessAttacher::FindAllProcesses(const char* processName)
{
    std::vector<ProcessInfo> result;

#ifdef _WIN32
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return result;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, processName) == 0) {
                ProcessInfo info;
                info.pid = pe.th32ProcessID;
                info.name = pe.szExeFile;
                info.moduleBase = GetModuleBase(info.pid, processName);
                info.moduleSize = GetModuleSize(info.pid, processName);
                info.is32bit = true; /* MuOnline is always 32-bit */
                result.push_back(info);
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
#endif

    return result;
}

/* ------------------------------------------------------------------ */
/*  Window Finding                                                     */
/* ------------------------------------------------------------------ */

#ifdef _WIN32

BOOL CALLBACK ProcessAttacher::EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
    EnumWindowsData* data = reinterpret_cast<EnumWindowsData*>(lParam);

    char title[256];
    GetWindowTextA(hwnd, title, sizeof(title));

    if (IsWindowVisible(hwnd) && strlen(title) > 0) {
        if (_stricmp(title, data->title) == 0 ||
            strstr(title, data->title) != nullptr) {
            data->result = hwnd;
            return FALSE; /* Stop enumeration */
        }
    }
    return TRUE;
}

HWND ProcessAttacher::FindGameWindow(const char* windowTitle)
{
    EnumWindowsData data;
    data.title = windowTitle;
    data.result = nullptr;

    EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&data));
    return data.result;
}

BOOL CALLBACK ProcessAttacher::EnumWindowsClassProc(HWND hwnd, LPARAM lParam)
{
    EnumWindowsClassData* data = reinterpret_cast<EnumWindowsClassData*>(lParam);

    char className[256];
    GetClassNameA(hwnd, className, sizeof(className));

    if (_stricmp(className, data->className) == 0) {
        data->result = hwnd;
        return FALSE;
    }
    return TRUE;
}

HWND ProcessAttacher::FindGameWindowByClass(const char* className)
{
    EnumWindowsClassData data;
    data.className = className;
    data.result = nullptr;

    EnumWindows(EnumWindowsClassProc, reinterpret_cast<LPARAM>(&data));
    return data.result;
}

uint32_t ProcessAttacher::GetWindowProcessId(HWND hwnd)
{
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    return pid;
}

#endif

/* ------------------------------------------------------------------ */
/*  Module Information                                                 */
/* ------------------------------------------------------------------ */

uintptr_t ProcessAttacher::GetModuleBase(uint32_t pid, const char* moduleName)
{
#ifdef _WIN32
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32 me;
    me.dwSize = sizeof(me);

    uintptr_t base = 0;

    if (Module32First(snap, &me)) {
        do {
            if (_stricmp(me.szModule, moduleName) == 0) {
                base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                break;
            }
        } while (Module32Next(snap, &me));
    }

    CloseHandle(snap);
    return base;
#else
    return 0;
#endif
}

size_t ProcessAttacher::GetModuleSize(uint32_t pid, const char* moduleName)
{
#ifdef _WIN32
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32 me;
    me.dwSize = sizeof(me);

    size_t size = 0;

    if (Module32First(snap, &me)) {
        do {
            if (_stricmp(me.szModule, moduleName) == 0) {
                size = me.modBaseSize;
                break;
            }
        } while (Module32Next(snap, &me));
    }

    CloseHandle(snap);
    return size;
#else
    return 0;
#endif
}

/* ------------------------------------------------------------------ */
/*  Process Watching                                                   */
/* ------------------------------------------------------------------ */

void ProcessAttacher::WatchProcess(uint32_t pid,
                                    std::function<void()> onExit,
                                    uint32_t pollIntervalMs)
{
    m_watching = true;
    m_watchPid = pid;

    /* Launch watcher in a separate thread */
    std::thread([this, pid, onExit, pollIntervalMs]() {
        while (m_watching) {
            if (!IsProcessAlive(pid)) {
                if (onExit) {
                    onExit();
                }
                break;
            }
            std::this_thread::sleep_for(
                std::chrono::milliseconds(pollIntervalMs));
        }
        m_watching = false;
    }).detach();
}

void ProcessAttacher::StopWatching()
{
    m_watching = false;
    m_watchPid = 0;
}

bool ProcessAttacher::IsProcessAlive(uint32_t pid)
{
#ifdef _WIN32
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return false;

    DWORD exitCode = 0;
    BOOL result = GetExitCodeProcess(process, &exitCode);
    CloseHandle(process);

    return result && exitCode == STILL_ACTIVE;
#else
    return false;
#endif
}

uint32_t ProcessAttacher::WaitForProcess(const char* processName,
                                           uint32_t timeoutMs)
{
    auto start = std::chrono::steady_clock::now();

    while (true) {
        uint32_t pid = FindProcessByName(processName);
        if (pid != 0) return pid;

        if (timeoutMs > 0) {
            auto elapsed = std::chrono::steady_clock::now() - start;
            auto elapsedMs = std::chrono::duration_cast<
                std::chrono::milliseconds>(elapsed).count();
            if (static_cast<uint32_t>(elapsedMs) >= timeoutMs) {
                return 0; /* Timeout */
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

} /* namespace MuTracker */
