/*
 * MemoryUtils.cpp - Memory manipulation utilities implementation
 */

#include "MemoryUtils.h"

#ifdef _WIN32
#include <tlhelp32.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#endif

#include <cstring>
#include <algorithm>

namespace MuTracker {

MemoryUtils::MemoryUtils()
    : m_initialized(false)
    , m_isLocal(false)
    , m_processId(0)
#ifdef _WIN32
    , m_processHandle(nullptr)
#endif
{
}

MemoryUtils::~MemoryUtils()
{
    Shutdown();
}

bool MemoryUtils::InitLocal()
{
    Shutdown();
#ifdef _WIN32
    m_processId = GetCurrentProcessId();
    m_processHandle = GetCurrentProcess();
    m_isLocal = true;
    m_initialized = true;
    return true;
#else
    return false;
#endif
}

bool MemoryUtils::InitRemote(uint32_t processId)
{
    Shutdown();
#ifdef _WIN32
    m_processHandle = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
        PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD,
        FALSE, processId);

    if (!m_processHandle) {
        return false;
    }

    m_processId = processId;
    m_isLocal = false;
    m_initialized = true;
    return true;
#else
    return false;
#endif
}

void MemoryUtils::Shutdown()
{
#ifdef _WIN32
    if (m_initialized && !m_isLocal && m_processHandle) {
        CloseHandle(m_processHandle);
    }
    m_processHandle = nullptr;
#endif
    m_initialized = false;
    m_isLocal = false;
    m_processId = 0;
}

bool MemoryUtils::Read(uintptr_t address, void* buffer, size_t size)
{
    if (!m_initialized || !buffer || size == 0) return false;

#ifdef _WIN32
    if (m_isLocal) {
        __try {
            memcpy(buffer, reinterpret_cast<const void*>(address), size);
            return true;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    } else {
        SIZE_T bytesRead = 0;
        return ReadProcessMemory(m_processHandle,
                                 reinterpret_cast<LPCVOID>(address),
                                 buffer, size, &bytesRead)
               && bytesRead == size;
    }
#else
    return false;
#endif
}

bool MemoryUtils::Write(uintptr_t address, const void* buffer, size_t size)
{
    if (!m_initialized || !buffer || size == 0) return false;

#ifdef _WIN32
    /* Change protection to allow writing */
    DWORD oldProtect = 0;
    if (!VirtualProtectEx(m_processHandle,
                          reinterpret_cast<LPVOID>(address),
                          size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }

    bool success = false;
    if (m_isLocal) {
        __try {
            memcpy(reinterpret_cast<void*>(address), buffer, size);
            success = true;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            success = false;
        }
    } else {
        SIZE_T bytesWritten = 0;
        success = WriteProcessMemory(m_processHandle,
                                     reinterpret_cast<LPVOID>(address),
                                     buffer, size, &bytesWritten)
                  && bytesWritten == size;
    }

    /* Restore original protection */
    VirtualProtectEx(m_processHandle,
                     reinterpret_cast<LPVOID>(address),
                     size, oldProtect, &oldProtect);

    /* Flush instruction cache if we wrote to executable memory */
    if (success) {
        FlushInstructionCache(m_processHandle,
                              reinterpret_cast<LPCVOID>(address), size);
    }

    return success;
#else
    return false;
#endif
}

bool MemoryUtils::Protect(uintptr_t address, size_t size,
                           uint32_t newProtect, uint32_t* oldProtect)
{
    if (!m_initialized) return false;

#ifdef _WIN32
    DWORD old = 0;
    BOOL result = VirtualProtectEx(m_processHandle,
                                   reinterpret_cast<LPVOID>(address),
                                   size, newProtect, &old);
    if (oldProtect) *oldProtect = old;
    return result != FALSE;
#else
    return false;
#endif
}

uintptr_t MemoryUtils::Alloc(size_t size, uint32_t protection,
                              uintptr_t preferredAddr)
{
    if (!m_initialized) return 0;

#ifdef _WIN32
    LPVOID addr = VirtualAllocEx(m_processHandle,
                                 reinterpret_cast<LPVOID>(preferredAddr),
                                 size, MEM_COMMIT | MEM_RESERVE, protection);
    return reinterpret_cast<uintptr_t>(addr);
#else
    return 0;
#endif
}

bool MemoryUtils::Free(uintptr_t address)
{
    if (!m_initialized || address == 0) return false;

#ifdef _WIN32
    return VirtualFreeEx(m_processHandle,
                         reinterpret_cast<LPVOID>(address),
                         0, MEM_RELEASE) != FALSE;
#else
    return false;
#endif
}

std::vector<MemoryRegion> MemoryUtils::EnumRegions()
{
    std::vector<MemoryRegion> regions;
    if (!m_initialized) return regions;

#ifdef _WIN32
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t address = 0;

    while (VirtualQueryEx(m_processHandle,
                          reinterpret_cast<LPCVOID>(address),
                          &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT) {
            MemoryRegion region;
            region.baseAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            region.regionSize = mbi.RegionSize;
            region.protection = mbi.Protect;
            region.state = mbi.State;
            region.type = mbi.Type;
            regions.push_back(region);
        }

        address = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (address == 0) break; /* Overflow protection */
    }
#endif

    return regions;
}

std::vector<ModuleInfo> MemoryUtils::EnumModules()
{
    std::vector<ModuleInfo> modules;
    if (!m_initialized) return modules;

#ifdef _WIN32
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                            m_processId);
    if (snap == INVALID_HANDLE_VALUE) return modules;

    MODULEENTRY32 me;
    me.dwSize = sizeof(me);

    if (Module32First(snap, &me)) {
        do {
            ModuleInfo info;
            info.name = me.szModule;
            info.baseAddress = reinterpret_cast<uintptr_t>(me.modBaseAddr);
            info.imageSize = me.modBaseSize;
            info.fullPath = me.szExePath;
            modules.push_back(info);
        } while (Module32Next(snap, &me));
    }

    CloseHandle(snap);
#endif

    return modules;
}

uintptr_t MemoryUtils::GetModuleBase(const char* moduleName)
{
    auto modules = EnumModules();
    for (const auto& mod : modules) {
        /* Case-insensitive comparison */
        std::string modLower = mod.name;
        std::string nameLower = moduleName;
        std::transform(modLower.begin(), modLower.end(), modLower.begin(), ::tolower);
        std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);
        if (modLower == nameLower) {
            return mod.baseAddress;
        }
    }
    return 0;
}

size_t MemoryUtils::GetModuleSize(const char* moduleName)
{
    auto modules = EnumModules();
    for (const auto& mod : modules) {
        std::string modLower = mod.name;
        std::string nameLower = moduleName;
        std::transform(modLower.begin(), modLower.end(), modLower.begin(), ::tolower);
        std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);
        if (modLower == nameLower) {
            return mod.imageSize;
        }
    }
    return 0;
}

std::string MemoryUtils::ReadString(uintptr_t address, size_t maxLen)
{
    std::string result;
    if (!m_initialized) return result;

    char ch;
    for (size_t i = 0; i < maxLen; ++i) {
        if (!Read(address + i, &ch, 1) || ch == '\0') break;
        result += ch;
    }
    return result;
}

} /* namespace MuTracker */
