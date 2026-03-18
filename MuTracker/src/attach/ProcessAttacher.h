/*
 * ProcessAttacher.h - Game Process Attachment
 *
 * Finds and attaches to the MuOnline (main.exe) process.
 * Supports finding by process name and window title.
 */

#ifndef MUTRACKER_PROCESS_ATTACHER_H
#define MUTRACKER_PROCESS_ATTACHER_H

#include <cstdint>
#include <string>
#include <vector>
#include <functional>

#ifdef _WIN32
#include <windows.h>
#endif

namespace MuTracker {

/* Process information */
struct ProcessInfo {
    uint32_t    pid;
    std::string name;
    std::string windowTitle;
    uintptr_t   moduleBase;
    size_t      moduleSize;
    bool        is32bit;
};

class ProcessAttacher {
public:
    ProcessAttacher();
    ~ProcessAttacher();

    /*
     * Find process by executable name.
     *
     * @param processName   Process name (e.g., "main.exe")
     * @return              PID, or 0 if not found
     */
    uint32_t FindProcessByName(const char* processName);

    /*
     * Find all processes with a given name.
     *
     * @param processName   Process name
     * @return              Vector of process info structures
     */
    std::vector<ProcessInfo> FindAllProcesses(const char* processName);

    /*
     * Find game window by title.
     *
     * @param windowTitle   Window title (e.g., "MU")
     * @return              Window handle, or NULL if not found
     */
    #ifdef _WIN32
    HWND FindGameWindow(const char* windowTitle);
    #endif

    /*
     * Find game window by class name.
     *
     * @param className     Window class name
     * @return              Window handle, or NULL if not found
     */
    #ifdef _WIN32
    HWND FindGameWindowByClass(const char* className);
    #endif

    /*
     * Get the base address of the main module in a process.
     *
     * @param pid           Process ID
     * @param moduleName    Module name (e.g., "main.exe")
     * @return              Base address, or 0 if not found
     */
    uintptr_t GetModuleBase(uint32_t pid, const char* moduleName);

    /*
     * Get the size of a module in a process.
     *
     * @param pid           Process ID
     * @param moduleName    Module name
     * @return              Module size, or 0 if not found
     */
    size_t GetModuleSize(uint32_t pid, const char* moduleName);

    /*
     * Watch a process and call callback when it exits.
     *
     * @param pid           Process ID to watch
     * @param onExit        Callback function called when process exits
     * @param pollIntervalMs Polling interval in milliseconds
     */
    void WatchProcess(uint32_t pid, std::function<void()> onExit,
                       uint32_t pollIntervalMs = 1000);

    /*
     * Stop watching a process.
     */
    void StopWatching();

    /*
     * Check if a process is still running.
     *
     * @param pid   Process ID
     * @return      true if process is alive
     */
    bool IsProcessAlive(uint32_t pid);

    /*
     * Get the PID of the process owning a window.
     *
     * @param hwnd  Window handle
     * @return      Process ID
     */
    #ifdef _WIN32
    uint32_t GetWindowProcessId(HWND hwnd);
    #endif

    /*
     * Wait for a process to start (blocking).
     *
     * @param processName   Process name to wait for
     * @param timeoutMs     Timeout in milliseconds (0 = infinite)
     * @return              PID when found, or 0 on timeout
     */
    uint32_t WaitForProcess(const char* processName,
                             uint32_t timeoutMs = 0);

private:
    bool            m_watching;
    uint32_t        m_watchPid;

    #ifdef _WIN32
    /* Helper for EnumWindows callback */
    struct EnumWindowsData {
        const char* title;
        HWND        result;
    };
    static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);

    struct EnumWindowsClassData {
        const char* className;
        HWND        result;
    };
    static BOOL CALLBACK EnumWindowsClassProc(HWND hwnd, LPARAM lParam);
    #endif
};

} /* namespace MuTracker */

#endif /* MUTRACKER_PROCESS_ATTACHER_H */
