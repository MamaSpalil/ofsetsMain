/*
 * HookEngine.cpp - Inline Hook Engine Implementation
 *
 * Creates trampoline-based inline hooks for x86 (32-bit) functions.
 *
 * Hook layout:
 *
 *   Target function (before):     Target function (after):
 *   +-------------------+         +-------------------+
 *   | PUSH EBP          |         | JMP detour        |  <- 5-byte overwrite
 *   | MOV EBP, ESP      |         | NOP (padding)     |
 *   | SUB ESP, XX        |         | <rest of func>    |
 *   | ...               |         | ...               |
 *   +-------------------+         +-------------------+
 *
 *   Trampoline:                   Detour function:
 *   +-------------------+         +-------------------+
 *   | PUSH EBP          |  <- stolen bytes (original) | user code         |
 *   | MOV EBP, ESP      |         | ...               |
 *   | JMP target+N      |  <- jump back               | CALL trampoline   | <- call original
 *   +-------------------+         | ...               |
 *                                 | RET               |
 *                                 +-------------------+
 */

#include "HookEngine.h"
#include "MemoryUtils.h"
#include "../disasm/DisasmEngine.h"
#include "../disasm/hde32.h"

#include <cstring>
#include <cstdio>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#endif

namespace MuTracker {

/* x86 JMP rel32 instruction: E9 XX XX XX XX (5 bytes) */
static const uint8_t JMP_REL32_OPCODE = 0xE9;
static const size_t  JMP_REL32_SIZE   = 5;

/* x86 NOP instruction */
static const uint8_t NOP_OPCODE = 0x90;

HookEngine::HookEngine()
    : m_memory(nullptr)
    , m_initialized(false)
    , m_nextHookId(1)
{
}

HookEngine::~HookEngine()
{
    Shutdown();
}

bool HookEngine::Init(MemoryUtils* memory)
{
    if (!memory || !memory->IsInitialized()) return false;

    std::lock_guard<std::mutex> lock(m_mutex);
    m_memory = memory;
    m_initialized = true;
    return true;
}

void HookEngine::Shutdown()
{
    RemoveAllHooks();
    std::lock_guard<std::mutex> lock(m_mutex);
    m_memory = nullptr;
    m_initialized = false;
}

/* ------------------------------------------------------------------ */
/*  Stolen Byte Calculation                                            */
/* ------------------------------------------------------------------ */

uint8_t HookEngine::CalculateStolenBytes(uintptr_t address)
{
    DisasmEngine disasm;
    uint8_t totalBytes = 0;
    uint8_t buffer[64];

    /* Read enough bytes to analyze */
    if (!m_memory->Read(address, buffer, sizeof(buffer))) {
        return 0;
    }

    /* Decode instructions until we have at least JMP_REL32_SIZE bytes */
    const uint8_t* p = buffer;
    while (totalBytes < JMP_REL32_SIZE) {
        hde32s hs;
        unsigned int len = hde32_disasm(p + totalBytes, &hs);

        if (len == 0 || (hs.flags & F_ERROR)) {
            /* Failed to decode - use minimum 5 bytes and hope for the best */
            return JMP_REL32_SIZE;
        }

        totalBytes += static_cast<uint8_t>(len);

        /* Safety limit */
        if (totalBytes > 32) {
            return 0;
        }
    }

    return totalBytes;
}

/* ------------------------------------------------------------------ */
/*  Trampoline Creation                                                */
/* ------------------------------------------------------------------ */

uintptr_t HookEngine::CreateTrampoline(uintptr_t target, uint8_t stolenBytes)
{
    /* Trampoline layout:
     *   [stolen bytes] (stolenBytes bytes, with fixups)
     *   [JMP target + stolenBytes] (5 bytes)
     *
     * Total size: stolenBytes + 5
     */
    size_t trampolineSize = stolenBytes + JMP_REL32_SIZE;

#ifdef _WIN32
    /* Allocate executable memory for the trampoline */
    uintptr_t trampoline = m_memory->Alloc(trampolineSize,
                                            PAGE_EXECUTE_READWRITE);
    if (trampoline == 0) return 0;

    /* Read and copy original stolen bytes */
    uint8_t originalBytes[32];
    if (!m_memory->Read(target, originalBytes, stolenBytes)) {
        m_memory->Free(trampoline);
        return 0;
    }

    /* Write stolen bytes to trampoline */
    if (!m_memory->Write(trampoline, originalBytes, stolenBytes)) {
        m_memory->Free(trampoline);
        return 0;
    }

    /* Fixup relative instructions in stolen bytes */
    FixupTrampoline(trampoline, target, originalBytes, stolenBytes);

    /* Write JMP back to original function (after stolen bytes) */
    uintptr_t jmpBackTarget = target + stolenBytes;
    uintptr_t jmpBackFrom = trampoline + stolenBytes;

    uint8_t jmpBack[JMP_REL32_SIZE];
    jmpBack[0] = JMP_REL32_OPCODE;
    int32_t relOffset = static_cast<int32_t>(jmpBackTarget - (jmpBackFrom + JMP_REL32_SIZE));
    memcpy(&jmpBack[1], &relOffset, sizeof(int32_t));

    if (!m_memory->Write(jmpBackFrom, jmpBack, JMP_REL32_SIZE)) {
        m_memory->Free(trampoline);
        return 0;
    }

    return trampoline;
#else
    return 0;
#endif
}

/* ------------------------------------------------------------------ */
/*  Relative Instruction Fixup                                         */
/* ------------------------------------------------------------------ */

bool HookEngine::FixupTrampoline(uintptr_t trampolineAddr,
                                   uintptr_t originalAddr,
                                   const uint8_t* originalBytes,
                                   uint8_t byteCount)
{
    DisasmEngine disasm;
    size_t offset = 0;

    while (offset < byteCount) {
        Instruction instr = disasm.Decode(originalAddr + offset,
                                           originalBytes + offset);
        if (instr.length == 0) break;

        /* If the instruction has a relative offset, fix it up */
        if (instr.isRelative) {
            /* Calculate the delta between original and trampoline positions */
            intptr_t delta = static_cast<intptr_t>(originalAddr) -
                             static_cast<intptr_t>(trampolineAddr);

            uint8_t opcode = originalBytes[offset];

            if (opcode == 0xE8 || opcode == 0xE9) {
                /* CALL rel32 / JMP rel32: offset is at position 1, 4 bytes */
                int32_t origRel;
                memcpy(&origRel, originalBytes + offset + 1, sizeof(int32_t));
                int32_t newRel = origRel + static_cast<int32_t>(delta);
                m_memory->Write(trampolineAddr + offset + 1,
                                &newRel, sizeof(int32_t));
            }
            else if (opcode >= 0x70 && opcode <= 0x7F) {
                /* Jcc short (rel8) - need to convert to Jcc near (rel32)
                 * This is complex; for now, skip short conditional jumps
                 * in the first 5 bytes (uncommon in function prologues)
                 */
            }
            else if (opcode == 0xEB) {
                /* JMP short (rel8) - same issue as Jcc short */
            }
            else if (opcode == 0x0F) {
                /* Two-byte opcode: 0F 80-8F = Jcc near (rel32) */
                uint8_t op2 = originalBytes[offset + 1];
                if (op2 >= 0x80 && op2 <= 0x8F) {
                    int32_t origRel;
                    memcpy(&origRel, originalBytes + offset + 2, sizeof(int32_t));
                    int32_t newRel = origRel + static_cast<int32_t>(delta);
                    m_memory->Write(trampolineAddr + offset + 2,
                                    &newRel, sizeof(int32_t));
                }
            }
        }

        offset += instr.length;
    }

    return true;
}

/* ------------------------------------------------------------------ */
/*  JMP Writing                                                        */
/* ------------------------------------------------------------------ */

bool HookEngine::WriteJmp(uintptr_t from, uintptr_t to)
{
    uint8_t jmp[JMP_REL32_SIZE];
    jmp[0] = JMP_REL32_OPCODE;
    int32_t relOffset = static_cast<int32_t>(to - (from + JMP_REL32_SIZE));
    memcpy(&jmp[1], &relOffset, sizeof(int32_t));

    return m_memory->Write(from, jmp, JMP_REL32_SIZE);
}

/* ------------------------------------------------------------------ */
/*  Inline Hook Installation                                           */
/* ------------------------------------------------------------------ */

uint32_t HookEngine::InstallInlineHook(uintptr_t target, uintptr_t detour,
                                         const char* name)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_initialized || !m_memory) return 0;

    /* Check if address is already hooked */
    for (const auto& pair : m_hooks) {
        if (pair.second.targetAddress == target &&
            pair.second.status == HookStatus::Active) {
            return 0; /* Already hooked */
        }
    }

    /* Calculate how many bytes we need to steal */
    uint8_t stolenBytes = CalculateStolenBytes(target);
    if (stolenBytes == 0 || stolenBytes > 32) return 0;

    /* Create trampoline */
    uintptr_t trampoline = CreateTrampoline(target, stolenBytes);
    if (trampoline == 0) return 0;

    /* Save original bytes */
    HookInfo hook = {};
    hook.id = m_nextHookId++;
    hook.type = HookType::Inline;
    hook.status = HookStatus::Active;
    hook.targetAddress = target;
    hook.detourAddress = detour;
    hook.trampolineAddr = trampoline;
    hook.stolenByteCount = stolenBytes;
    hook.hitCount = 0;

    if (name) hook.name = name;

    if (!m_memory->Read(target, hook.originalBytes, stolenBytes)) {
        m_memory->Free(trampoline);
        return 0;
    }

    /* Write JMP to detour at target address */
    if (!WriteJmp(target, detour)) {
        m_memory->Free(trampoline);
        return 0;
    }

    /* NOP-pad remaining stolen bytes (after the 5-byte JMP) */
    if (stolenBytes > JMP_REL32_SIZE) {
        uint8_t nops[32];
        memset(nops, NOP_OPCODE, sizeof(nops));
        m_memory->Write(target + JMP_REL32_SIZE,
                        nops, stolenBytes - JMP_REL32_SIZE);
    }

    m_hooks[hook.id] = hook;
    return hook.id;
}

/* ------------------------------------------------------------------ */
/*  IAT Hook Installation                                              */
/* ------------------------------------------------------------------ */

uint32_t HookEngine::InstallIATHook(const char* moduleName,
                                      const char* dllName,
                                      const char* funcName,
                                      uintptr_t detour,
                                      const char* name)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_initialized || !m_memory) return 0;

#ifdef _WIN32
    uintptr_t moduleBase = m_memory->GetModuleBase(moduleName);
    if (moduleBase == 0) return 0;

    /* Read PE headers to find IAT */
    IMAGE_DOS_HEADER dosHeader;
    if (!m_memory->Read(moduleBase, &dosHeader, sizeof(dosHeader))) return 0;
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS32 ntHeaders;
    if (!m_memory->Read(moduleBase + dosHeader.e_lfanew,
                        &ntHeaders, sizeof(ntHeaders))) return 0;

    IMAGE_DATA_DIRECTORY& importDir =
        ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress == 0) return 0;

    /* Walk import descriptors */
    uintptr_t descAddr = moduleBase + importDir.VirtualAddress;
    IMAGE_IMPORT_DESCRIPTOR importDesc;

    while (true) {
        if (!m_memory->Read(descAddr, &importDesc, sizeof(importDesc))) break;
        if (importDesc.Name == 0) break;

        /* Read DLL name */
        std::string importDllName = m_memory->ReadString(
            moduleBase + importDesc.Name, 256);

        /* Case-insensitive DLL name comparison */
        std::string dllLower = importDllName;
        std::string targetDll = dllName;
        std::transform(dllLower.begin(), dllLower.end(),
                       dllLower.begin(), ::tolower);
        std::transform(targetDll.begin(), targetDll.end(),
                       targetDll.begin(), ::tolower);

        if (dllLower == targetDll) {
            /* Walk INT (Import Name Table) and IAT simultaneously */
            uintptr_t intAddr = moduleBase +
                (importDesc.OriginalFirstThunk ? importDesc.OriginalFirstThunk
                                                : importDesc.FirstThunk);
            uintptr_t iatAddr = moduleBase + importDesc.FirstThunk;

            uint32_t thunk;
            while (true) {
                if (!m_memory->ReadValue<uint32_t>(intAddr, thunk)) break;
                if (thunk == 0) break;

                /* Check if import by name (not by ordinal) */
                if (!(thunk & 0x80000000)) {
                    /* Read IMAGE_IMPORT_BY_NAME (skip 2-byte Hint) */
                    std::string importName = m_memory->ReadString(
                        moduleBase + thunk + 2, 256);

                    if (importName == funcName) {
                        /* Found it! Patch the IAT entry */
                        HookInfo hook = {};
                        hook.id = m_nextHookId++;
                        hook.type = HookType::IAT;
                        hook.status = HookStatus::Active;
                        hook.targetAddress = iatAddr;
                        hook.detourAddress = detour;
                        hook.trampolineAddr = 0;
                        hook.stolenByteCount = sizeof(uint32_t);
                        hook.hitCount = 0;

                        if (name) hook.name = name;

                        /* Save original IAT value */
                        uint32_t originalIATValue;
                        if (!m_memory->ReadValue<uint32_t>(iatAddr, originalIATValue)) {
                            return 0;
                        }
                        memcpy(hook.originalBytes, &originalIATValue, sizeof(uint32_t));

                        /* Write detour address to IAT */
                        uint32_t detourAddr32 = static_cast<uint32_t>(detour);
                        if (!m_memory->WriteValue<uint32_t>(iatAddr, detourAddr32)) {
                            return 0;
                        }

                        /* Store original function address as trampoline
                         * (for IAT hooks, "trampoline" = original function) */
                        hook.trampolineAddr = static_cast<uintptr_t>(originalIATValue);

                        m_hooks[hook.id] = hook;
                        return hook.id;
                    }
                }

                intAddr += sizeof(uint32_t);
                iatAddr += sizeof(uint32_t);
            }
        }

        descAddr += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
#endif

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Hook Removal                                                       */
/* ------------------------------------------------------------------ */

bool HookEngine::RemoveHook(uint32_t hookId)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_hooks.find(hookId);
    if (it == m_hooks.end()) return false;

    HookInfo& hook = it->second;

    if (hook.status == HookStatus::Removed) return true;

    if (hook.type == HookType::Inline) {
        /* Restore original bytes */
        m_memory->Write(hook.targetAddress, hook.originalBytes,
                        hook.stolenByteCount);

        /* Free trampoline memory */
        if (hook.trampolineAddr) {
            m_memory->Free(hook.trampolineAddr);
            hook.trampolineAddr = 0;
        }
    } else if (hook.type == HookType::IAT) {
        /* Restore original IAT entry */
        m_memory->Write(hook.targetAddress, hook.originalBytes,
                        sizeof(uint32_t));
    }

    hook.status = HookStatus::Removed;
    return true;
}

bool HookEngine::DisableHook(uint32_t hookId)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_hooks.find(hookId);
    if (it == m_hooks.end()) return false;

    HookInfo& hook = it->second;
    if (hook.status != HookStatus::Active) return false;

    /* Restore original bytes (but keep trampoline alive) */
    if (hook.type == HookType::Inline) {
        m_memory->Write(hook.targetAddress, hook.originalBytes,
                        hook.stolenByteCount);
    } else if (hook.type == HookType::IAT) {
        m_memory->Write(hook.targetAddress, hook.originalBytes,
                        sizeof(uint32_t));
    }

    hook.status = HookStatus::Disabled;
    return true;
}

bool HookEngine::EnableHook(uint32_t hookId)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_hooks.find(hookId);
    if (it == m_hooks.end()) return false;

    HookInfo& hook = it->second;
    if (hook.status != HookStatus::Disabled) return false;

    if (hook.type == HookType::Inline) {
        /* Re-write JMP to detour */
        WriteJmp(hook.targetAddress, hook.detourAddress);

        /* NOP-pad remaining bytes */
        if (hook.stolenByteCount > JMP_REL32_SIZE) {
            uint8_t nops[32];
            memset(nops, NOP_OPCODE, sizeof(nops));
            m_memory->Write(hook.targetAddress + JMP_REL32_SIZE,
                            nops, hook.stolenByteCount - JMP_REL32_SIZE);
        }
    } else if (hook.type == HookType::IAT) {
        uint32_t detourAddr32 = static_cast<uint32_t>(hook.detourAddress);
        m_memory->WriteValue<uint32_t>(hook.targetAddress, detourAddr32);
    }

    hook.status = HookStatus::Active;
    return true;
}

void HookEngine::RemoveAllHooks()
{
    /* Get all hook IDs first to avoid modifying map during iteration */
    std::vector<uint32_t> hookIds;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& pair : m_hooks) {
            hookIds.push_back(pair.first);
        }
    }

    /* Remove hooks in reverse order */
    std::reverse(hookIds.begin(), hookIds.end());
    for (uint32_t id : hookIds) {
        RemoveHook(id);
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    m_hooks.clear();
}

/* ------------------------------------------------------------------ */
/*  Hook Queries                                                       */
/* ------------------------------------------------------------------ */

uintptr_t HookEngine::GetOriginal(uint32_t hookId)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_hooks.find(hookId);
    if (it == m_hooks.end()) return 0;

    return it->second.trampolineAddr;
}

const HookInfo* HookEngine::GetHookInfo(uint32_t hookId) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_hooks.find(hookId);
    if (it == m_hooks.end()) return nullptr;

    return &it->second;
}

std::vector<const HookInfo*> HookEngine::GetAllHooks() const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    std::vector<const HookInfo*> result;
    for (const auto& pair : m_hooks) {
        result.push_back(&pair.second);
    }
    return result;
}

void HookEngine::IncrementHitCount(uint32_t hookId)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_hooks.find(hookId);
    if (it != m_hooks.end()) {
        it->second.hitCount++;
    }
}

uint32_t HookEngine::IsAddressHooked(uintptr_t address) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    for (const auto& pair : m_hooks) {
        if (pair.second.targetAddress == address &&
            pair.second.status == HookStatus::Active) {
            return pair.first;
        }
    }
    return 0;
}

size_t HookEngine::GetActiveHookCount() const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    size_t count = 0;
    for (const auto& pair : m_hooks) {
        if (pair.second.status == HookStatus::Active) {
            count++;
        }
    }
    return count;
}

} /* namespace MuTracker */
