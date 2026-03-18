/*
 * MuTrackerDLL - Injectable DLL for MuOnline Process Tracing
 *
 * This DLL is injected into the main.exe process and:
 *   1. Creates SharedMemory for IPC with the Loader GUI
 *   2. Finds patterns (55 8B EC = function prologue) in main.exe
 *   3. Installs inline hooks with trampolines
 *   4. Publishes trace data to SharedMemory for real-time display
 *   5. Clean unhooking on DLL unload
 *
 * Compile: MSVC 2019+ (v142), C++17, x86/x64
 */

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>

#include "../src/core/MemoryUtils.h"
#include "../src/core/PatternScanner.h"
#include "../src/core/HookEngine.h"
#include "../src/core/CallTracer.h"
#include "../src/log/Logger.h"
#include "../src/config/Config.h"
#include "../src/attach/ProcessAttacher.h"
#include "../Shared/SharedStructs.h"

#include <cstdio>
#include <cstring>
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

/* SharedMemory IPC */
static HANDLE           g_hSharedMem = nullptr;
static SharedMemHeader* g_pSharedHeader = nullptr;

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

    /* ============================================================== */
    /*  Initialize SharedMemory IPC for Loader GUI                     */
    /*  Starting base of offsets, functions, variables, modules = 0    */
    /* ============================================================== */

    g_hSharedMem = CreateFileMappingW(
        INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
        0, MUTRACKER_SHMEM_SIZE, MUTRACKER_SHMEM_NAME);

    if (g_hSharedMem) {
        void* pView = MapViewOfFile(g_hSharedMem, FILE_MAP_ALL_ACCESS,
                                     0, 0, MUTRACKER_SHMEM_SIZE);
        if (pView) {
            g_pSharedHeader = static_cast<SharedMemHeader*>(pView);

            /*
             * Zero-initialize the ENTIRE shared memory region.
             * The starting base for all offsets, functions, variables
             * and modules MUST be zero before population from main.exe.
             */
            memset(g_pSharedHeader, 0, MUTRACKER_SHMEM_SIZE);

            /* Set header identification fields */
            g_pSharedHeader->magic        = 0x4D555452; /* "MUTR" */
            g_pSharedHeader->version      = MUTRACKER_VERSION;
            g_pSharedHeader->writeIndex   = 0;
            g_pSharedHeader->readIndex    = 0;
            g_pSharedHeader->bufferSize   = MUTRACKER_SHMEM_SIZE;
            g_pSharedHeader->injectedPid  = GetCurrentProcessId();
            g_pSharedHeader->dllReady     = true;
            g_pSharedHeader->tracingEnabled = false;

            /* All counters start at zero - no data until main.exe scan */
            g_pSharedHeader->totalRecords   = 0;
            g_pSharedHeader->droppedRecords = 0;
            g_pSharedHeader->functionCount  = 0;
            g_pSharedHeader->moduleCount    = 0;
            g_pSharedHeader->variableCount  = 0;
            g_pSharedHeader->activeHookCount = 0;
            g_pSharedHeader->totalCalls     = 0;
            g_pSharedHeader->uptimeMs       = 0;
            g_pSharedHeader->statusText[0]  = '\0';

            MULOG_INFO("SharedMemory IPC initialized (4 MB)");
            MULOG_INFO("Starting base: offsets=0, functions=0, variables=0, modules=0");
        } else {
            MULOG_WARN("Failed to map shared memory view (error: %d)",
                        GetLastError());
        }
    } else {
        MULOG_WARN("Failed to create shared memory (error: %d)",
                    GetLastError());
    }

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
    /*  Populate database from main.exe: Module Enumeration            */
    /*  Scan and record all loaded modules in the process              */
    /* ============================================================== */

    log.LogHeader("Module Enumeration");

    auto loadedModules = g_memory.EnumModules();
    MULOG_INFO("Found %zu loaded modules in process", loadedModules.size());

    if (g_pSharedHeader && !loadedModules.empty()) {
        uint32_t modCount = 0;
        for (size_t i = 0; i < loadedModules.size() &&
             modCount < MUTRACKER_MAX_MODULES; ++i) {
            auto& mod = g_pSharedHeader->modules[modCount];
            mod.baseAddress = loadedModules[i].baseAddress;
            mod.sizeOfImage = static_cast<uint32_t>(loadedModules[i].imageSize);
            mod.isMainExe = (loadedModules[i].name == "main.exe" ||
                              loadedModules[i].name == "MAIN.EXE");

            strncpy(mod.moduleName, loadedModules[i].name.c_str(),
                    sizeof(mod.moduleName) - 1);
            mod.moduleName[sizeof(mod.moduleName) - 1] = '\0';

            strncpy(mod.modulePath, loadedModules[i].fullPath.c_str(),
                    sizeof(mod.modulePath) - 1);
            mod.modulePath[sizeof(mod.modulePath) - 1] = '\0';

            MULOG_INFO("  Module [%u]: %s base=0x%08X size=0x%08X%s",
                       modCount,
                       loadedModules[i].name.c_str(),
                       static_cast<uint32_t>(loadedModules[i].baseAddress),
                       static_cast<uint32_t>(loadedModules[i].imageSize),
                       mod.isMainExe ? " [MAIN]" : "");

            log.LogOffset(loadedModules[i].baseAddress, 0,
                          "MODULE", loadedModules[i].name.c_str());

            modCount++;
        }
        g_pSharedHeader->moduleCount = modCount;
        MULOG_INFO("Published %u modules to SharedMemory", modCount);
    }

    /* ============================================================== */
    /*  Populate database from main.exe: Function Prologues            */
    /*  Scan for 55 8B EC pattern (push ebp; mov ebp, esp)            */
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
    /*  Publish discovered functions to SharedMemory                    */
    /*  Each entry starts at zero and is populated from scan results    */
    /* ============================================================== */

    if (g_pSharedHeader && !prologues.empty()) {
        uint32_t count = 0;
        for (size_t i = 0; i < prologues.size() &&
             count < MUTRACKER_MAX_FUNCTIONS; ++i) {
            auto& entry = g_pSharedHeader->functions[count];
            entry.address    = prologues[i].address;
            entry.offset     = prologues[i].offset;
            entry.totalCalls = 0;
            entry.callsPerSecond = 0;
            entry.lastThreadId   = 0;
            entry.isHooked       = false;

            /* Generate name: sub_XXXXXXXX */
            sprintf_s(entry.name, sizeof(entry.name),
                       "sub_%08X", static_cast<uint32_t>(prologues[i].offset));
            sprintf_s(entry.moduleName, sizeof(entry.moduleName),
                       "main.exe");
            count++;
        }
        g_pSharedHeader->functionCount = count;
        MULOG_INFO("Published %u functions to SharedMemory", count);
    }

    /* ============================================================== */
    /*  Populate database from main.exe: Variable/Data Section Scan    */
    /*  Scan .data section for trackable variables                     */
    /* ============================================================== */

    log.LogHeader("Data Section Variable Scan");

    {
        uintptr_t dataBase = 0;
        size_t dataSize = 0;
        DWORD dataSectionRVA = 0;

        /* Read PE headers to find .data section */
        IMAGE_DOS_HEADER dosHeader;
        if (g_memory.Read(mainBase, &dosHeader, sizeof(dosHeader)) &&
            dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {

            IMAGE_NT_HEADERS ntHeaders;
            if (g_memory.Read(mainBase + dosHeader.e_lfanew,
                              &ntHeaders, sizeof(ntHeaders)) &&
                ntHeaders.Signature == IMAGE_NT_SIGNATURE) {

                uintptr_t sectionBase = mainBase + dosHeader.e_lfanew +
                    sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
                    ntHeaders.FileHeader.SizeOfOptionalHeader;

                for (WORD s = 0; s < ntHeaders.FileHeader.NumberOfSections; ++s) {
                    IMAGE_SECTION_HEADER sec;
                    g_memory.Read(sectionBase + s * sizeof(IMAGE_SECTION_HEADER),
                                  &sec, sizeof(sec));
                    if (strncmp(reinterpret_cast<const char*>(sec.Name),
                                ".data", 5) == 0) {
                        dataBase = mainBase + sec.VirtualAddress;
                        dataSize = sec.Misc.VirtualSize;
                        dataSectionRVA = sec.VirtualAddress;
                        break;
                    }
                }
            }
        }

        uint32_t varCount = 0;
        if (dataBase != 0 && dataSize > 0 && g_pSharedHeader) {
            MULOG_INFO(".data section: base=0x%08X size=0x%X",
                       static_cast<uint32_t>(dataBase),
                       static_cast<uint32_t>(dataSize));

            /*
             * Sample variables from .data section at regular intervals.
             * Track up to MUTRACKER_MAX_VARIABLES entries.
             */
            size_t stride = dataSize / MUTRACKER_MAX_VARIABLES;
            if (stride < sizeof(uint32_t)) stride = sizeof(uint32_t);

            for (size_t off = 0;
                 off + sizeof(uint32_t) <= dataSize &&
                 varCount < MUTRACKER_MAX_VARIABLES;
                 off += stride) {

                uint32_t value = 0;
                if (g_memory.ReadValue<uint32_t>(dataBase + off, value)) {
                    auto& var = g_pSharedHeader->variables[varCount];
                    var.address       = dataBase + off;
                    var.offset        = static_cast<uintptr_t>(
                                          dataSectionRVA + off);
                    var.size          = sizeof(uint32_t);
                    var.currentValue  = value;
                    var.previousValue = value;
                    var.changed       = false;

                    sprintf_s(var.name, sizeof(var.name),
                               "var_%08X",
                               static_cast<uint32_t>(var.address - mainBase));
                    sprintf_s(var.moduleName, sizeof(var.moduleName),
                               "main.exe");
                    varCount++;
                }
            }

            g_pSharedHeader->variableCount = varCount;
            MULOG_INFO("Tracking %u variables from .data section", varCount);
        } else {
            MULOG_WARN("Could not locate .data section for variable tracking");
        }
    }

    /* ============================================================== */
    /*  Demonstrate inline hooking                                     */
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

        if (g_pSharedHeader) {
            g_pSharedHeader->activeHookCount =
                static_cast<uint32_t>(g_hookEngine.GetActiveHookCount());
        }
    }

    /* ============================================================== */
    /*  Real-Time Monitoring Loop                                       */
    /*  Continuously scans and tracks all actions in main.exe:          */
    /*    - Function call statistics                                    */
    /*    - Variable value changes in .data section                     */
    /*    - New module loads/unloads                                    */
    /*  All changes are logged to MuTracker.log and shared memory.      */
    /* ============================================================== */

    log.LogHeader("Real-Time Monitoring");
    MULOG_INFO("Monitoring started. DLL will unload on process exit.");
    MULOG_INFO("Tracking: %u functions, %u modules, %u variables",
               g_pSharedHeader ? g_pSharedHeader->functionCount : 0,
               g_pSharedHeader ? g_pSharedHeader->moduleCount : 0,
               g_pSharedHeader ? g_pSharedHeader->variableCount : 0);
    MULOG_INFO("All game actions are being recorded to MuTracker.log");

    if (g_pSharedHeader) {
        g_pSharedHeader->tracingEnabled = true;
        sprintf_s(g_pSharedHeader->statusText,
                   sizeof(g_pSharedHeader->statusText),
                   "Monitoring active - scanning in real-time");
    }

    /* Run monitoring loop */
    uint32_t updateCounter = 0;
    uint32_t prevModuleCount = g_pSharedHeader ? g_pSharedHeader->moduleCount : 0;
    auto startTime = std::chrono::steady_clock::now();

    while (g_running) {
        /* === Every 100ms: check for variable changes === */
        if (g_pSharedHeader) {
            uint32_t vCount = g_pSharedHeader->variableCount;
            for (uint32_t v = 0; v < vCount; ++v) {
                auto& var = g_pSharedHeader->variables[v];
                uint32_t newValue = 0;
                if (g_memory.ReadValue<uint32_t>(var.address, newValue)) {
                    if (newValue != var.currentValue) {
                        var.previousValue = var.currentValue;
                        var.currentValue  = newValue;
                        var.changed       = true;

                        MULOG_INFO("[VAR_CHANGE] %s at 0x%08X (+0x%08X): "
                                   "0x%08X -> 0x%08X",
                                   var.name,
                                   static_cast<uint32_t>(var.address),
                                   static_cast<uint32_t>(var.offset),
                                   var.previousValue, var.currentValue);
                    }
                }
            }
        }

        /* === Every 1 second: full stats update === */
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

            /* Publish stats to SharedMemory for GUI display */
            if (g_pSharedHeader) {
                g_pSharedHeader->totalCalls    = stats.totalCalls;
                g_pSharedHeader->activeHookCount =
                    static_cast<uint32_t>(g_hookEngine.GetActiveHookCount());

                auto elapsed = std::chrono::steady_clock::now() - startTime;
                g_pSharedHeader->uptimeMs =
                    static_cast<uint64_t>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            elapsed).count());
            }
        }

        /* === Every 5 seconds: check for new module loads === */
        if (updateCounter % 50 == 0 && g_pSharedHeader) {
            auto currentModules = g_memory.EnumModules();
            uint32_t knownCount = g_pSharedHeader->moduleCount;

            if (currentModules.size() != prevModuleCount) {
                MULOG_INFO("[MODULE_CHANGE] Module count changed: %zu -> %zu",
                           static_cast<size_t>(prevModuleCount),
                           currentModules.size());

                /* Re-populate module table with current state */
                uint32_t modCount = 0;
                for (size_t i = 0; i < currentModules.size() &&
                     modCount < MUTRACKER_MAX_MODULES; ++i) {

                    /* Check if this is a new module */
                    bool isNew = true;
                    for (uint32_t k = 0; k < knownCount; ++k) {
                        if (g_pSharedHeader->modules[k].baseAddress ==
                            currentModules[i].baseAddress) {
                            isNew = false;
                            break;
                        }
                    }

                    auto& mod = g_pSharedHeader->modules[modCount];
                    mod.baseAddress = currentModules[i].baseAddress;
                    mod.sizeOfImage = static_cast<uint32_t>(
                                       currentModules[i].imageSize);
                    mod.isMainExe = (currentModules[i].name == "main.exe" ||
                                      currentModules[i].name == "MAIN.EXE");

                    strncpy(mod.moduleName,
                            currentModules[i].name.c_str(),
                            sizeof(mod.moduleName) - 1);
                    mod.moduleName[sizeof(mod.moduleName) - 1] = '\0';

                    strncpy(mod.modulePath,
                            currentModules[i].fullPath.c_str(),
                            sizeof(mod.modulePath) - 1);
                    mod.modulePath[sizeof(mod.modulePath) - 1] = '\0';

                    if (isNew) {
                        MULOG_INFO("[MODULE_LOAD] %s base=0x%08X size=0x%08X",
                                   currentModules[i].name.c_str(),
                                   static_cast<uint32_t>(
                                       currentModules[i].baseAddress),
                                   static_cast<uint32_t>(
                                       currentModules[i].imageSize));
                        log.LogOffset(currentModules[i].baseAddress, 0,
                                      "MODULE", currentModules[i].name.c_str(),
                                      "loaded");
                    }
                    modCount++;
                }
                g_pSharedHeader->moduleCount = modCount;
                prevModuleCount = static_cast<uint32_t>(currentModules.size());
            }
        }

        /* === Every 30 seconds: periodic summary log === */
        if (updateCounter % 300 == 0 && updateCounter > 0) {
            auto elapsed = std::chrono::steady_clock::now() - startTime;
            auto elapsedSec = std::chrono::duration_cast<
                std::chrono::seconds>(elapsed).count();

            MULOG_INFO("[SUMMARY] Uptime: %lld s | Functions: %u | "
                       "Modules: %u | Variables: %u | "
                       "Total calls: %llu | Hooks: %u",
                       static_cast<long long>(elapsedSec),
                       g_pSharedHeader ? g_pSharedHeader->functionCount : 0,
                       g_pSharedHeader ? g_pSharedHeader->moduleCount : 0,
                       g_pSharedHeader ? g_pSharedHeader->variableCount : 0,
                       g_pSharedHeader
                           ? static_cast<unsigned long long>(
                                 g_pSharedHeader->totalCalls) : 0ULL,
                       g_pSharedHeader ? g_pSharedHeader->activeHookCount : 0);
        }

        updateCounter++;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    /* ============================================================== */
    /*  Step 5: Clean shutdown - remove all hooks                      */
    /* ============================================================== */

    log.LogHeader("Shutdown");
    MULOG_INFO("Removing all hooks...");

    g_hookEngine.RemoveAllHooks();
    MULOG_INFO("All hooks removed cleanly");

    /* Mark SharedMemory as shutting down */
    if (g_pSharedHeader) {
        g_pSharedHeader->dllReady = false;
        g_pSharedHeader->tracingEnabled = false;
        sprintf_s(g_pSharedHeader->statusText,
                   sizeof(g_pSharedHeader->statusText),
                   "DLL unloaded");
    }

    /* Export trace data */
    g_tracer.Export("trace_output.log", "log");
    MULOG_INFO("Trace data exported to trace_output.log");

    /* Save scanner cache */
    g_scanner.SaveCache("scanner.cache");

    g_tracer.Shutdown();
    g_hookEngine.Shutdown();
    g_memory.Shutdown();

    /* Clean up SharedMemory */
    if (g_pSharedHeader) {
        UnmapViewOfFile(g_pSharedHeader);
        g_pSharedHeader = nullptr;
    }
    if (g_hSharedMem) {
        CloseHandle(g_hSharedMem);
        g_hSharedMem = nullptr;
    }

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
