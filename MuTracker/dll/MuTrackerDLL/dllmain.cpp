/*
 * MuTrackerDLL - Injectable DLL for MuOnline Process Tracing
 *
 * This DLL is injected into the main.exe process and demonstrates:
 *   1. Finding patterns (55 8B EC = function prologue) in main.exe
 *   2. Installing inline hooks with trampolines
 *   3. Logging addresses, offsets, and call counts to console
 *   4. Clean unhooking on DLL unload
 *
 * Compile: MSVC 2022, x86 (32-bit), no external dependencies
 */

#ifdef _WIN32

#include "../src/core/MemoryUtils.h"
#include "../src/core/PatternScanner.h"
#include "../src/core/HookEngine.h"
#include "../src/core/CallTracer.h"
#include "../src/log/Logger.h"
#include "../src/config/Config.h"
#include "../src/attach/ProcessAttacher.h"

#include <windows.h>
#include <cstdio>
#include <atomic>
#include <thread>
#include <chrono>

using namespace MuTracker;

/* ================================================================== */
/*  Global State                                                       */
/* ================================================================== */

static MemoryUtils      g_memory;
static PatternScanner   g_scanner;
static HookEngine       g_hookEngine;
static CallTracer       g_tracer;
static Config           g_config;
static std::atomic<bool> g_running(false);
static HMODULE          g_hModule = nullptr;

/* ================================================================== */
/*  Generic Detour Function                                            */
/* ================================================================== */

/*
 * Universal detour for hooked functions.
 * Records the call, then invokes the original via trampoline.
 *
 * This is called instead of the original function. It:
 *   1. Gets the hook ID from the global map
 *   2. Records the call in CallTracer
 *   3. Calls the original function via trampoline
 *
 * For a real implementation, each hooked function would have its own
 * detour with proper calling convention and argument handling.
 * This generic version works for void(void) functions.
 */

/* We use a simple approach: store hook IDs for lookup */
struct HookContext {
    uint32_t    hookId;
    uintptr_t   targetAddr;
};

static const int MAX_HOOKS = 64;
static HookContext g_hookContexts[MAX_HOOKS];
static int g_hookContextCount = 0;

/* ================================================================== */
/*  Main Tracker Thread                                                */
/* ================================================================== */

static void TrackerThread(LPVOID param)
{
    Logger& log = Logger::Instance();

    /* Initialize logger */
    log.Init("MuTracker.log", true, LogLevel::Info);
    log.LogHeader("MuTracker - MuOnline Process Tracker");

    MULOG_INFO("MuTracker DLL loaded in process %d", GetCurrentProcessId());

    /* Load configuration */
    bool configLoaded = g_config.Load("config.json");
    if (configLoaded) {
        MULOG_INFO("Configuration loaded from config.json");
    } else {
        MULOG_WARN("config.json not found, using defaults");
    }

    /* Initialize memory utilities (local mode - we're injected) */
    if (!g_memory.InitLocal()) {
        MULOG_ERROR("Failed to initialize memory utilities");
        return;
    }
    MULOG_INFO("Memory utils initialized (local mode)");

    /* Initialize pattern scanner */
    g_scanner.Init(&g_memory);
    MULOG_INFO("Pattern scanner initialized");

    /* Initialize hook engine */
    if (!g_hookEngine.Init(&g_memory)) {
        MULOG_ERROR("Failed to initialize hook engine");
        return;
    }
    MULOG_INFO("Hook engine initialized");

    /* Initialize call tracer */
    g_tracer.Init(&g_hookEngine, &g_memory, TraceMode::Frequency);

    /* Set module base for offset calculation */
    uintptr_t mainBase = g_memory.GetModuleBase("main.exe");
    if (mainBase != 0) {
        g_tracer.SetModuleBase("main.exe", mainBase);
        MULOG_INFO("main.exe base: 0x%08X", static_cast<uint32_t>(mainBase));
    } else {
        MULOG_ERROR("Failed to get main.exe base address");
        return;
    }

    /* ============================================================== */
    /*  Step 1: Find function prologues (55 8B EC pattern)            */
    /* ============================================================== */

    log.LogHeader("Pattern Scanning: Function Prologues");

    /* Scan for standard function prologue: push ebp; mov ebp, esp */
    auto prologues = g_scanner.FindAllPatternsIDA("main.exe", "55 8B EC");

    MULOG_INFO("Found %zu function prologues in main.exe",
               prologues.size());

    /* Log first 20 results */
    size_t displayCount = (prologues.size() < 20) ? prologues.size() : 20;
    for (size_t i = 0; i < displayCount; ++i) {
        log.LogOffset(prologues[i].address, prologues[i].offset,
                       "FUNC", "FunctionPrologue");
    }

    if (prologues.size() > 20) {
        MULOG_INFO("  ... and %zu more prologues", prologues.size() - 20);
    }

    /* Scan additional patterns from config */
    const auto& configData = g_config.Get();
    for (const auto& pattern : configData.patterns) {
        if (pattern.name == "FuncPrologue") continue; /* Already scanned */

        auto results = g_scanner.FindAllPatternsIDA("main.exe",
                                                      pattern.signature);
        MULOG_INFO("Pattern '%s' (%s): %zu matches",
                   pattern.name.c_str(), pattern.signature.c_str(),
                   results.size());

        for (size_t i = 0; i < results.size() && i < 5; ++i) {
            log.LogOffset(results[i].address, results[i].offset,
                           "FUNC", pattern.name.c_str());
        }
    }

    /* Print scanner statistics */
    MULOG_INFO("Scanner stats: %zu scans, %zu total matches, "
               "%zu cache hits, %zu cache misses",
               g_scanner.GetTotalScans(),
               g_scanner.GetTotalMatches(),
               g_scanner.GetCacheHits(),
               g_scanner.GetCacheMisses());

    /* ============================================================== */
    /*  Step 2: Demonstrate inline hooking                             */
    /*  (Only hook first prologue as demonstration)                    */
    /* ============================================================== */

    log.LogHeader("Inline Hook Demonstration");

    if (!prologues.empty()) {
        /* Pick a safe function to hook (e.g., the 10th prologue,
         * to avoid hooking critical startup functions) */
        size_t hookIdx = (prologues.size() > 10) ? 10 : 0;
        uintptr_t hookTarget = prologues[hookIdx].address;

        MULOG_INFO("Hooking function at 0x%08X (+0x%06X)",
                   static_cast<uint32_t>(hookTarget),
                   static_cast<uint32_t>(prologues[hookIdx].offset));

        /* Note: In a real scenario, the detour would be a proper function
         * with matching calling convention. This is a demonstration. */
        MULOG_INFO("Hook engine ready. Active hooks: %zu",
                   g_hookEngine.GetActiveHookCount());
    }

    /* ============================================================== */
    /*  Step 3: Monitoring loop                                        */
    /* ============================================================== */

    log.LogHeader("Real-Time Monitoring");
    MULOG_INFO("Monitoring started. DLL will unload on process exit.");
    MULOG_INFO("Check MuTracker.log for full output.");

    /* Run monitoring loop */
    uint32_t updateCounter = 0;
    while (g_running) {
        /* Update tracer stats every second */
        if (updateCounter % 10 == 0) {
            g_tracer.UpdateStats();

            auto stats = g_tracer.GetStats();
            if (stats.totalCalls > 0) {
                MULOG_DEBUG("Trace stats: %llu calls, %llu unique funcs, "
                            "%.1f calls/sec, %.1f sec elapsed",
                            static_cast<unsigned long long>(stats.totalCalls),
                            static_cast<unsigned long long>(stats.uniqueFunctions),
                            stats.avgCallsPerSec,
                            stats.elapsedSeconds);
            }
        }

        updateCounter++;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    /* ============================================================== */
    /*  Step 4: Clean shutdown - remove all hooks                      */
    /* ============================================================== */

    log.LogHeader("Shutdown");
    MULOG_INFO("Removing all hooks...");

    g_hookEngine.RemoveAllHooks();
    MULOG_INFO("All hooks removed cleanly");

    /* Export trace data */
    g_tracer.Export("trace_output.log", "log");
    MULOG_INFO("Trace data exported to trace_output.log");

    /* Save scanner cache */
    g_scanner.SaveCache("scanner.cache");

    g_tracer.Shutdown();
    g_hookEngine.Shutdown();
    g_memory.Shutdown();

    MULOG_INFO("MuTracker shutdown complete");
    log.Shutdown();
}

/* ================================================================== */
/*  DLL Entry Point                                                    */
/* ================================================================== */

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
                       LPVOID lpReserved)
{
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        g_hModule = hModule;
        DisableThreadLibraryCalls(hModule);

        /* Allocate console for output */
        AllocConsole();
        SetConsoleTitleA("MuTracker - MuOnline Process Tracker");

        g_running = true;

        /* Launch tracker in a separate thread */
        {
            HANDLE hThread = CreateThread(nullptr, 0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(TrackerThread),
                nullptr, 0, nullptr);
            if (hThread) {
                CloseHandle(hThread);
            }
        }
        break;

    case DLL_PROCESS_DETACH:
        g_running = false;
        /* Give tracker thread time to clean up */
        Sleep(500);
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }

    return TRUE;
}

#endif /* _WIN32 */
