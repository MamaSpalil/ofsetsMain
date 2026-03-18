/*
 * MemoryUtils.h - Memory manipulation utilities for Windows process memory
 *
 * Provides safe wrappers around Windows memory API functions for both
 * local (injected DLL) and remote (ReadProcessMemory) modes.
 */

#ifndef MUTRACKER_MEMORY_UTILS_H
#define MUTRACKER_MEMORY_UTILS_H

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

namespace MuTracker {

/* Memory region information */
struct MemoryRegion {
    uintptr_t   baseAddress;
    size_t      regionSize;
    uint32_t    protection;     /* PAGE_xxx flags */
    uint32_t    state;          /* MEM_COMMIT, MEM_FREE, MEM_RESERVE */
    uint32_t    type;           /* MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE */
};

/* Module information */
struct ModuleInfo {
    std::string     name;
    uintptr_t       baseAddress;
    size_t          imageSize;
    std::string     fullPath;
};

class MemoryUtils {
public:
    MemoryUtils();
    ~MemoryUtils();

    /*
     * Initialize for local process (injected DLL mode).
     * Uses direct memory access (fastest, no API calls needed).
     */
    bool InitLocal();

    /*
     * Initialize for remote process (external mode).
     * Uses ReadProcessMemory/WriteProcessMemory.
     *
     * @param processId  Target process ID
     * @return           true if process handle was obtained
     */
    bool InitRemote(uint32_t processId);

    /* Close handles and clean up */
    void Shutdown();

    /* Check if initialized */
    bool IsInitialized() const { return m_initialized; }
    bool IsLocal() const { return m_isLocal; }

    /*
     * Read memory from target process.
     *
     * @param address   Address to read from
     * @param buffer    Output buffer
     * @param size      Number of bytes to read
     * @return          true if read succeeded
     */
    bool Read(uintptr_t address, void* buffer, size_t size);

    /*
     * Write memory to target process.
     * Automatically handles page protection changes.
     *
     * @param address   Address to write to
     * @param buffer    Source buffer
     * @param size      Number of bytes to write
     * @return          true if write succeeded
     */
    bool Write(uintptr_t address, const void* buffer, size_t size);

    /*
     * Change memory page protection.
     *
     * @param address       Starting address
     * @param size          Size of region
     * @param newProtect    New PAGE_xxx protection
     * @param oldProtect    Output: previous protection
     * @return              true if protection was changed
     */
    bool Protect(uintptr_t address, size_t size,
                 uint32_t newProtect, uint32_t* oldProtect);

    /*
     * Allocate memory in the target process.
     *
     * @param size          Allocation size
     * @param protection    PAGE_xxx protection flags
     * @param preferredAddr Preferred base address (nullptr for any)
     * @return              Allocated address, or 0 on failure
     */
    uintptr_t Alloc(size_t size, uint32_t protection,
                    uintptr_t preferredAddr = 0);

    /*
     * Free memory in the target process.
     *
     * @param address   Address to free
     * @return          true if freed
     */
    bool Free(uintptr_t address);

    /*
     * Enumerate all committed memory regions in the target process.
     *
     * @return  Vector of memory regions
     */
    std::vector<MemoryRegion> EnumRegions();

    /*
     * Enumerate all loaded modules in the target process.
     *
     * @return  Vector of module information
     */
    std::vector<ModuleInfo> EnumModules();

    /*
     * Get the base address of a specific module.
     *
     * @param moduleName    Module name (e.g., "main.exe")
     * @return              Base address, or 0 if not found
     */
    uintptr_t GetModuleBase(const char* moduleName);

    /*
     * Get the size of a specific module.
     *
     * @param moduleName    Module name
     * @return              Module image size, or 0 if not found
     */
    size_t GetModuleSize(const char* moduleName);

    /*
     * Read a null-terminated string from memory.
     *
     * @param address   Address of string
     * @param maxLen    Maximum length to read
     * @return          The string (truncated at maxLen or null terminator)
     */
    std::string ReadString(uintptr_t address, size_t maxLen = 256);

    /*
     * Read a typed value from memory.
     *
     * @tparam T        Type to read
     * @param address   Address to read from
     * @param value     Output value
     * @return          true if read succeeded
     */
    template<typename T>
    bool ReadValue(uintptr_t address, T& value) {
        return Read(address, &value, sizeof(T));
    }

    /*
     * Write a typed value to memory.
     *
     * @tparam T        Type to write
     * @param address   Address to write to
     * @param value     Value to write
     * @return          true if write succeeded
     */
    template<typename T>
    bool WriteValue(uintptr_t address, const T& value) {
        return Write(address, &value, sizeof(T));
    }

    /* Get the process handle (for remote mode) */
    #ifdef _WIN32
    HANDLE GetProcessHandle() const { return m_processHandle; }
    #endif

    uint32_t GetProcessId() const { return m_processId; }

private:
    bool        m_initialized;
    bool        m_isLocal;
    uint32_t    m_processId;

    #ifdef _WIN32
    HANDLE      m_processHandle;
    #endif
};

} /* namespace MuTracker */

#endif /* MUTRACKER_MEMORY_UTILS_H */
