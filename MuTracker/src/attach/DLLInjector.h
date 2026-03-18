/*
 * DLLInjector.h - DLL Injection into Remote Process
 *
 * Injects a DLL into a target process using CreateRemoteThread + LoadLibrary.
 */

#ifndef MUTRACKER_DLL_INJECTOR_H
#define MUTRACKER_DLL_INJECTOR_H

#include <cstdint>
#include <string>

namespace MuTracker {

/* Injection method */
enum class InjectionMethod {
    LoadLib,            /* CreateRemoteThread + LoadLibraryA */
    ManualMap           /* Manual PE mapping (advanced, for anti-cheat bypass) */
};

/* Injection result */
struct InjectionResult {
    bool        success;
    uint32_t    errorCode;      /* GetLastError() on failure */
    uintptr_t   dllBaseAddress; /* Base address of injected DLL */
    std::string errorMessage;
};

class DLLInjector {
public:
    DLLInjector();
    ~DLLInjector();

    /*
     * Inject a DLL into a remote process.
     *
     * @param pid       Target process ID
     * @param dllPath   Full path to the DLL to inject
     * @param method    Injection method (default: LoadLibrary)
     * @return          Injection result
     */
    InjectionResult Inject(uint32_t pid, const std::string& dllPath,
                            InjectionMethod method = InjectionMethod::LoadLib);

    /*
     * Eject (unload) a previously injected DLL.
     *
     * @param pid           Target process ID
     * @param dllName       Name of the DLL module to unload
     * @return              true if ejected
     */
    bool Eject(uint32_t pid, const char* dllName);

    /*
     * Check if a DLL is loaded in a process.
     *
     * @param pid       Process ID
     * @param dllName   DLL name
     * @return          Base address if loaded, 0 if not
     */
    uintptr_t IsDLLLoaded(uint32_t pid, const char* dllName);

private:
    /* Internal: LoadLibrary injection */
    InjectionResult InjectLoadLibrary(uint32_t pid, const std::string& dllPath);

    /* Internal: Get module handle in remote process */
    uintptr_t GetRemoteModuleHandle(uint32_t pid, const char* moduleName);
};

} /* namespace MuTracker */

#endif /* MUTRACKER_DLL_INJECTOR_H */
