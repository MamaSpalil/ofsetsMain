/*
 * MuTrackerLoader - External Launcher & Process Manager
 *
 * This is the external launcher that:
 *   1. Finds or waits for main.exe (MuOnline) process
 *   2. Injects MuTrackerDLL.dll into the game process
 *   3. Provides a console UI for managing the tracker
 *   4. Can also run in external mode (ReadProcessMemory)
 *
 * Compile: MSVC 2022, x86 (32-bit)
 */

#ifdef _WIN32

#include "../src/core/MemoryUtils.h"
#include "../src/core/PatternScanner.h"
#include "../src/core/CallTracer.h"
#include "../src/log/Logger.h"
#include "../src/config/Config.h"
#include "../src/attach/ProcessAttacher.h"
#include "../src/attach/DLLInjector.h"

#include <windows.h>
#include <cstdio>
#include <conio.h>
#include <string>

using namespace MuTracker;

/* ================================================================== */
/*  Menu Display                                                       */
/* ================================================================== */

static void ShowMenu(bool attached, uint32_t pid)
{
    Logger& log = Logger::Instance();

    log.LogHeader("MuTracker Loader - MuOnline Process Tracker");

    if (attached) {
        log.LogColored(LogColor::Green,
                       "  Status: ATTACHED to main.exe (PID: %d)", pid);
    } else {
        log.LogColored(LogColor::Yellow,
                       "  Status: NOT ATTACHED (waiting for main.exe)");
    }

    printf("\n");
    printf("  [1] Find main.exe process\n");
    printf("  [2] Inject MuTrackerDLL.dll\n");
    printf("  [3] Run external pattern scan\n");
    printf("  [4] Export scan results\n");
    printf("  [5] Eject DLL / Stop tracking\n");
    printf("  [6] Reload config.json\n");
    printf("  [Q] Quit\n");
    printf("\n");
    printf("  Select option: ");
}

/* ================================================================== */
/*  External Pattern Scan (no injection)                               */
/* ================================================================== */

static void RunExternalScan(uint32_t pid)
{
    Logger& log = Logger::Instance();
    log.LogHeader("External Pattern Scan (ReadProcessMemory)");

    MemoryUtils memory;
    if (!memory.InitRemote(pid)) {
        MULOG_ERROR("Failed to open process %d", pid);
        return;
    }

    PatternScanner scanner;
    scanner.Init(&memory);

    /* Scan for function prologues */
    MULOG_INFO("Scanning main.exe for function prologues (55 8B EC)...");

    auto results = scanner.FindAllPatternsIDA("main.exe", "55 8B EC");

    MULOG_INFO("Found %zu function prologues", results.size());

    /* Display results */
    size_t displayCount = (results.size() < 50) ? results.size() : 50;
    for (size_t i = 0; i < displayCount; ++i) {
        log.LogOffset(results[i].address, results[i].offset,
                       "FUNC", "FunctionPrologue");
    }

    if (results.size() > 50) {
        MULOG_INFO("  ... and %zu more (see trace_output.log)", results.size() - 50);
    }

    /* Scan config patterns */
    Config config;
    if (config.Load("config.json")) {
        for (const auto& pattern : config.Get().patterns) {
            if (pattern.name == "FuncPrologue") continue;

            auto patResults = scanner.FindAllPatternsIDA("main.exe",
                                                           pattern.signature);
            MULOG_INFO("Pattern '%s': %zu matches",
                       pattern.name.c_str(), patResults.size());

            for (size_t i = 0; i < patResults.size() && i < 10; ++i) {
                log.LogOffset(patResults[i].address, patResults[i].offset,
                               "FUNC", pattern.name.c_str());
            }
        }
    }

    /* Print scanner stats */
    MULOG_INFO("Scanner: %zu scans, %zu matches, %zu cache hits",
               scanner.GetTotalScans(), scanner.GetTotalMatches(),
               scanner.GetCacheHits());

    /* Save cache */
    scanner.SaveCache("scanner.cache");

    memory.Shutdown();
    MULOG_INFO("External scan complete");
}

/* ================================================================== */
/*  Main Entry Point                                                   */
/* ================================================================== */

int main(int argc, char* argv[])
{
    Logger& log = Logger::Instance();
    log.Init("MuTrackerLoader.log", true, LogLevel::Info);

    log.LogHeader("MuTracker Loader v1.0");
    MULOG_INFO("MuTracker Loader starting...");

    /* Load configuration */
    Config config;
    if (config.Load("config.json")) {
        MULOG_INFO("Configuration loaded");
    } else {
        MULOG_WARN("config.json not found, creating default...");
        Config::CreateDefault("config.json");
        config.Load("config.json");
    }

    ProcessAttacher attacher;
    DLLInjector injector;

    uint32_t pid = 0;
    bool attached = false;
    bool running = true;

    /* Auto-attach if configured */
    if (config.Get().autoAttach) {
        pid = attacher.FindProcessByName(config.Get().processName.c_str());
        if (pid != 0) {
            attached = true;
            MULOG_INFO("Auto-attached to %s (PID: %d)",
                       config.Get().processName.c_str(), pid);
        }
    }

    /* Main menu loop */
    while (running) {
        ShowMenu(attached, pid);

        int ch = _getch();
        printf("%c\n\n", ch);

        switch (ch) {
        case '1': {
            /* Find process */
            const char* procName = config.Get().processName.c_str();
            MULOG_INFO("Searching for %s...", procName);

            pid = attacher.FindProcessByName(procName);
            if (pid != 0) {
                attached = true;
                MULOG_INFO("Found %s (PID: %d)", procName, pid);

                uintptr_t base = attacher.GetModuleBase(pid, procName);
                size_t size = attacher.GetModuleSize(pid, procName);
                MULOG_INFO("  Base: 0x%08X, Size: 0x%X (%zu KB)",
                           static_cast<uint32_t>(base), static_cast<uint32_t>(size),
                           size / 1024);
            } else {
                MULOG_WARN("%s not found. Is the game running?", procName);
                attached = false;
            }
            break;
        }

        case '2': {
            /* Inject DLL */
            if (!attached || pid == 0) {
                MULOG_WARN("Not attached to any process. Press [1] first.");
                break;
            }

            /* Get DLL path (same directory as loader) */
            char exePath[MAX_PATH];
            GetModuleFileNameA(nullptr, exePath, MAX_PATH);
            std::string dllPath = exePath;
            size_t lastSlash = dllPath.find_last_of("\\/");
            if (lastSlash != std::string::npos) {
                dllPath = dllPath.substr(0, lastSlash + 1);
            }
            dllPath += "MuTrackerDLL.dll";

            MULOG_INFO("Injecting %s into PID %d...", dllPath.c_str(), pid);

            auto result = injector.Inject(pid, dllPath);
            if (result.success) {
                MULOG_INFO("DLL injected successfully! Base: 0x%08X",
                           static_cast<uint32_t>(result.dllBaseAddress));
            } else {
                MULOG_ERROR("Injection failed: %s (error: %d)",
                            result.errorMessage.c_str(), result.errorCode);
            }
            break;
        }

        case '3': {
            /* External scan */
            if (!attached || pid == 0) {
                MULOG_WARN("Not attached. Press [1] first.");
                break;
            }
            RunExternalScan(pid);
            break;
        }

        case '4': {
            /* Export results */
            MULOG_INFO("Exporting results to trace_output.log...");
            /* The DLL handles its own export; loader exports scanner results */
            MULOG_INFO("Export complete. Check trace_output.log");
            break;
        }

        case '5': {
            /* Eject DLL */
            if (pid != 0) {
                MULOG_INFO("Ejecting MuTrackerDLL.dll from PID %d...", pid);
                bool ejected = injector.Eject(pid, "MuTrackerDLL.dll");
                if (ejected) {
                    MULOG_INFO("DLL ejected successfully");
                } else {
                    MULOG_WARN("DLL ejection failed (may not be loaded)");
                }
            }
            break;
        }

        case '6': {
            /* Reload config */
            if (config.Load("config.json")) {
                MULOG_INFO("Configuration reloaded");
            } else {
                MULOG_ERROR("Failed to reload config.json");
            }
            break;
        }

        case 'q': case 'Q': case 27: /* ESC */
            running = false;
            break;

        default:
            MULOG_WARN("Unknown option: %c", ch);
            break;
        }

        if (running) {
            printf("\n  Press any key to continue...");
            _getch();
            printf("\n");
        }
    }

    /* Clean up */
    MULOG_INFO("MuTracker Loader shutting down");
    log.Shutdown();

    return 0;
}

#else
/* Non-Windows stub */
#include <cstdio>
int main() {
    printf("MuTracker requires Windows.\n");
    return 1;
}
#endif
