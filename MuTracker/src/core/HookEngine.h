/*
 * HookEngine.h - Inline Hook Engine for x86 (32-bit)
 *
 * Provides trampoline-based inline function hooking for 32-bit x86 code.
 * Supports:
 *   - Inline hook (5-byte JMP splice with trampoline)
 *   - IAT hook (Import Address Table patching)
 *   - Callback-based hooking with original function access
 *   - Thread-safe hook installation/removal
 *   - Automatic instruction boundary detection via hde32
 *
 * Usage:
 *   HookEngine engine;
 *   engine.Init(&memoryUtils);
 *
 *   // Install inline hook
 *   auto id = engine.InstallInlineHook(targetAddr, myDetourFunc);
 *
 *   // Call original from detour:
 *   auto origFunc = (OrigType)engine.GetOriginal(id);
 *   origFunc(args...);
 *
 *   // Remove hook when done
 *   engine.RemoveHook(id);
 */

#ifndef MUTRACKER_HOOK_ENGINE_H
#define MUTRACKER_HOOK_ENGINE_H

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <functional>

namespace MuTracker {

/* Forward declarations */
class MemoryUtils;

/* Hook type enumeration */
enum class HookType {
    Inline,     /* Trampoline-based inline hook (JMP splice) */
    IAT,        /* Import Address Table patch */
    VTable,     /* Virtual function table patch */
    Hardware    /* Hardware breakpoint (DR0-DR3) */
};

/* Hook status */
enum class HookStatus {
    Active,         /* Hook is installed and active */
    Disabled,       /* Hook is installed but temporarily disabled */
    Removed,        /* Hook has been removed */
    Error           /* Hook failed to install */
};

/* Individual hook descriptor */
struct HookInfo {
    uint32_t        id;             /* Unique hook ID */
    HookType        type;           /* Type of hook */
    HookStatus      status;         /* Current status */
    uintptr_t       targetAddress;  /* Address being hooked */
    uintptr_t       detourAddress;  /* Detour function address */
    uintptr_t       trampolineAddr; /* Trampoline (call original) */
    uint8_t         originalBytes[32]; /* Saved original bytes */
    uint8_t         stolenByteCount;   /* Number of bytes stolen for JMP */
    std::string     name;           /* Human-readable name */
    uint64_t        hitCount;       /* Number of times hook was triggered */
};

/* Hook callback type:
 * Parameters: (hookId, targetAddress, returnAddress, stackPointer) */
using HookCallback = std::function<void(uint32_t, uintptr_t, uintptr_t, uintptr_t)>;

class HookEngine {
public:
    HookEngine();
    ~HookEngine();

    /*
     * Initialize the hook engine.
     *
     * @param memory    Pointer to initialized MemoryUtils (must be local mode)
     * @return          true if initialized
     */
    bool Init(MemoryUtils* memory);

    /* Shutdown: remove all hooks and clean up */
    void Shutdown();

    /*
     * Install an inline hook (trampoline-based).
     *
     * Overwrites the first N bytes of the target function with a JMP
     * to the detour. Creates a trampoline that executes the original
     * stolen bytes then JMPs to target+N for calling the original.
     *
     * @param target    Address of function to hook
     * @param detour    Address of detour function
     * @param name      Optional name for the hook
     * @return          Hook ID (0 on failure)
     */
    uint32_t InstallInlineHook(uintptr_t target, uintptr_t detour,
                                const char* name = "");

    /*
     * Install an IAT hook.
     *
     * Patches the Import Address Table entry for a function to redirect
     * calls to the detour. Only works for imported functions.
     *
     * @param moduleName    Module containing the IAT (e.g., "main.exe")
     * @param dllName       DLL of the target function (e.g., "USER32.dll")
     * @param funcName      Name of the function to hook
     * @param detour        Address of detour function
     * @param name          Optional name for the hook
     * @return              Hook ID (0 on failure)
     */
    uint32_t InstallIATHook(const char* moduleName, const char* dllName,
                             const char* funcName, uintptr_t detour,
                             const char* name = "");

    /*
     * Remove a hook by ID.
     * Restores original bytes and frees trampoline memory.
     *
     * @param hookId    Hook to remove
     * @return          true if hook was removed
     */
    bool RemoveHook(uint32_t hookId);

    /*
     * Temporarily disable a hook (restore original bytes).
     *
     * @param hookId    Hook to disable
     * @return          true if disabled
     */
    bool DisableHook(uint32_t hookId);

    /*
     * Re-enable a previously disabled hook.
     *
     * @param hookId    Hook to enable
     * @return          true if enabled
     */
    bool EnableHook(uint32_t hookId);

    /*
     * Remove all installed hooks.
     */
    void RemoveAllHooks();

    /*
     * Get the trampoline address for calling the original function.
     *
     * @param hookId    Hook ID
     * @return          Trampoline address (castable to function pointer)
     */
    uintptr_t GetOriginal(uint32_t hookId);

    /*
     * Get hook information.
     *
     * @param hookId    Hook ID
     * @return          Pointer to HookInfo, or nullptr if not found
     */
    const HookInfo* GetHookInfo(uint32_t hookId) const;

    /*
     * Get all installed hooks.
     */
    std::vector<const HookInfo*> GetAllHooks() const;

    /*
     * Increment hit counter for a hook (called from detour functions).
     *
     * @param hookId    Hook ID
     */
    void IncrementHitCount(uint32_t hookId);

    /*
     * Check if a specific address is hooked.
     *
     * @param address   Address to check
     * @return          Hook ID if hooked, 0 if not
     */
    uint32_t IsAddressHooked(uintptr_t address) const;

    /* Get total number of active hooks */
    size_t GetActiveHookCount() const;

private:
    MemoryUtils*    m_memory;
    bool            m_initialized;
    uint32_t        m_nextHookId;
    mutable std::mutex m_mutex;

    std::unordered_map<uint32_t, HookInfo> m_hooks;

    /* Internal: Create trampoline for inline hook */
    uintptr_t CreateTrampoline(uintptr_t target, uint8_t stolenBytes);

    /* Internal: Write JMP instruction at address */
    bool WriteJmp(uintptr_t from, uintptr_t to);

    /* Internal: Calculate stolen byte count (instruction boundary aligned) */
    uint8_t CalculateStolenBytes(uintptr_t address);

    /* Internal: Fixup relative instructions in trampoline */
    bool FixupTrampoline(uintptr_t trampolineAddr, uintptr_t originalAddr,
                          const uint8_t* originalBytes, uint8_t byteCount);
};

} /* namespace MuTracker */

#endif /* MUTRACKER_HOOK_ENGINE_H */
