/*
 * SharedStructs.h - Shared data structures for MuTracker IPC
 *
 * This header is included by both MuTrackerDLL and MuTrackerLoader
 * to ensure consistent data layout for inter-process communication
 * via shared memory.
 *
 * Compile: MSVC 2019+ (v142), C++17, Win32/x64
 */

#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <cstdint>

/* ================================================================== */
/*  Version & IPC Constants                                            */
/* ================================================================== */

#define MUTRACKER_VERSION       0x0102
#define MUTRACKER_PIPE_NAME     L"\\\\.\\pipe\\MuTrackerIPC"
#define MUTRACKER_SHMEM_NAME    L"MuTrackerSharedMem"
#define MUTRACKER_SHMEM_SIZE    (1024 * 1024 * 4)   /* 4 MB ring buffer */
#define MUTRACKER_MAX_FUNCTIONS 4096
#define MUTRACKER_MAX_MODULES   64
#define MUTRACKER_MAX_VARIABLES 256
#define MUTRACKER_MAX_RECORDS   65536

/* ================================================================== */
/*  Record Types                                                       */
/* ================================================================== */

#pragma pack(push, 1)

enum class RecordType : uint8_t {
    FunctionCall  = 0x01,
    MemoryAccess  = 0x02,
    ExceptionInfo = 0x03,
    ModuleLoad    = 0x04,
    Heartbeat     = 0x05
};

/* ================================================================== */
/*  Function Call Record (sent from DLL to Loader via shared memory)   */
/* ================================================================== */

struct FunctionCallRecord {
    RecordType  type;               /* RecordType::FunctionCall         */
    uint32_t    recordSize;         /* sizeof this structure            */
    uint64_t    timestamp;          /* QueryPerformanceCounter value    */
    uintptr_t   absoluteAddress;    /* Absolute VA of the function      */
    uintptr_t   moduleBase;         /* Base address of the module       */
    uintptr_t   offset;             /* = absoluteAddress - moduleBase   */
    uintptr_t   callerAddress;      /* Address of the CALL instruction  */
    uint32_t    threadId;           /* Thread that made the call        */
    uint64_t    callCount;          /* Cumulative call count            */
    uint32_t    argCount;           /* Number of captured arguments     */
    uintptr_t   args[8];           /* First 8 stack arguments          */
    char        moduleName[64];     /* Module name (e.g. "main.exe")    */
    char        symbolName[128];    /* Symbol or "sub_XXXXXXXX"         */
};

/* ================================================================== */
/*  Module Information                                                  */
/* ================================================================== */

struct SharedModuleInfo {
    uintptr_t   baseAddress;
    uint32_t    sizeOfImage;
    char        moduleName[MAX_PATH];
    char        modulePath[MAX_PATH];
    bool        isMainExe;
};

/* ================================================================== */
/*  Tracked Function Summary (for Loader ListView display)             */
/* ================================================================== */

struct TrackedFunctionEntry {
    uintptr_t   address;            /* Absolute address                 */
    uintptr_t   offset;             /* Relative to module base          */
    char        name[128];          /* Function name / symbol           */
    char        moduleName[64];     /* Module name                      */
    uint64_t    totalCalls;         /* Total call count                 */
    uint32_t    callsPerSecond;     /* Calls/sec (updated by DLL)       */
    uint32_t    lastThreadId;       /* Last thread that called it       */
    bool        isHooked;           /* Currently hooked?                */
};

/* ================================================================== */
/*  Tracked Variable Entry (for data section monitoring)               */
/* ================================================================== */

struct TrackedVariableEntry {
    uintptr_t   address;            /* Absolute address                 */
    uintptr_t   offset;             /* Relative to module base          */
    char        name[128];          /* Variable name / label            */
    char        moduleName[64];     /* Module name                      */
    uint32_t    size;               /* Size of variable in bytes        */
    uint32_t    currentValue;       /* Current value (first 4 bytes)    */
    uint32_t    previousValue;      /* Previous value for change detect */
    volatile bool changed;          /* Value changed since last check?  */
};

/* ================================================================== */
/*  Shared Memory Header (beginning of the mapped region)              */
/* ================================================================== */

struct SharedMemHeader {
    volatile uint32_t   magic;              /* 0x4D555452 = "MUTR"     */
    volatile uint32_t   version;            /* MUTRACKER_VERSION        */
    volatile uint32_t   writeIndex;         /* Ring buffer write pos    */
    volatile uint32_t   readIndex;          /* Ring buffer read pos     */
    uint32_t            bufferSize;         /* Total ring buffer size   */
    DWORD               injectedPid;        /* PID of injected process  */
    volatile bool       dllReady;           /* DLL initialized?         */
    volatile bool       tracingEnabled;     /* Tracing active?          */
    volatile uint32_t   totalRecords;       /* Total records written    */
    volatile uint32_t   droppedRecords;     /* Records dropped (full)   */

    /* Function table for Loader display */
    volatile uint32_t   functionCount;
    TrackedFunctionEntry functions[MUTRACKER_MAX_FUNCTIONS];

    /* Module table */
    volatile uint32_t   moduleCount;
    SharedModuleInfo     modules[MUTRACKER_MAX_MODULES];

    /* Variable table for data section monitoring */
    volatile uint32_t   variableCount;
    TrackedVariableEntry variables[MUTRACKER_MAX_VARIABLES];

    /* Status info */
    volatile uint32_t   activeHookCount;
    volatile uint64_t   totalCalls;
    volatile uint64_t   uptimeMs;           /* DLL uptime in ms         */
    char                statusText[256];    /* Status message           */
};

#pragma pack(pop)

/* ================================================================== */
/*  Inline Helpers                                                     */
/* ================================================================== */

inline bool IsSharedMemValid(const SharedMemHeader* p)
{
    return p != nullptr
        && p->magic == 0x4D555452   /* "MUTR" */
        && p->version == MUTRACKER_VERSION;
}
