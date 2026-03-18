/*
 * IPC_Protocol.h - Named Pipe protocol for MuTracker
 *
 * Optional IPC mechanism for extended command/response communication
 * between the Loader and the injected DLL.
 *
 * Compile: MSVC 2019+ (v142), C++17, Win32/x64
 */

#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <cstdint>

#include "SharedStructs.h"

/* ================================================================== */
/*  IPC Constants                                                      */
/* ================================================================== */

#define IPC_MAGIC           0x4D555452  /* "MUTR" */
#define PIPE_BUFFER_SIZE    65536

/* ================================================================== */
/*  IPC Commands                                                       */
/* ================================================================== */

enum class IpcCommand : uint32_t {
    Ping            = 0x01,
    StartTrace      = 0x02,
    StopTrace       = 0x03,
    AddHookByOffset = 0x04,
    RemoveHook      = 0x05,
    GetStats        = 0x06,
    SetFilter       = 0x07,
    ExportData      = 0x08,
    Shutdown        = 0x09
};

/* ================================================================== */
/*  IPC Message Structures                                             */
/* ================================================================== */

#pragma pack(push, 1)

struct IpcMessage {
    uint32_t    magic;          /* IPC_MAGIC                        */
    IpcCommand  command;        /* Command to execute               */
    uint32_t    payloadSize;    /* Size of payload in bytes         */
    uint8_t     payload[1];     /* Variable-length payload          */
};

struct IpcResponse {
    uint32_t    magic;          /* IPC_MAGIC                        */
    uint32_t    status;         /* 0 = OK, nonzero = error          */
    uint32_t    payloadSize;    /* Size of response payload         */
    uint8_t     payload[1];     /* Variable-length payload          */
};

#pragma pack(pop)
