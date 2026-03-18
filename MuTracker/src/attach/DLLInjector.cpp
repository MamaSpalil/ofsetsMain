/*
 * DLLInjector.cpp - DLL Injection Implementation
 */

#include "DLLInjector.h"

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#endif

#include <cstring>

namespace MuTracker {

DLLInjector::DLLInjector()
{
}

DLLInjector::~DLLInjector()
{
}

InjectionResult DLLInjector::Inject(uint32_t pid, const std::string& dllPath,
                                      InjectionMethod method)
{
    switch (method) {
    case InjectionMethod::LoadLib:
        return InjectLoadLibrary(pid, dllPath);
    case InjectionMethod::ManualMap:
        /* Not implemented in first step */
        return { false, 0, 0, "ManualMap injection not yet implemented" };
    default:
        return { false, 0, 0, "Unknown injection method" };
    }
}

InjectionResult DLLInjector::InjectLoadLibrary(uint32_t pid,
                                                 const std::string& dllPath)
{
    InjectionResult result = { false, 0, 0, "" };

#ifdef _WIN32
    /* Open target process with required permissions */
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD |
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, pid);

    if (!hProcess) {
        result.errorCode = GetLastError();
        result.errorMessage = "Failed to open target process (error: " +
                               std::to_string(result.errorCode) + ")";
        return result;
    }

    /* Allocate memory in target process for DLL path string */
    size_t pathSize = dllPath.length() + 1;
    LPVOID remotePath = VirtualAllocEx(hProcess, nullptr, pathSize,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_READWRITE);
    if (!remotePath) {
        result.errorCode = GetLastError();
        result.errorMessage = "Failed to allocate memory in target process";
        CloseHandle(hProcess);
        return result;
    }

    /* Write DLL path to target process */
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, remotePath, dllPath.c_str(),
                             pathSize, &bytesWritten)) {
        result.errorCode = GetLastError();
        result.errorMessage = "Failed to write DLL path to target process";
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return result;
    }

    /* Get LoadLibraryA address (same across processes on same system) */
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        result.errorMessage = "Failed to get kernel32.dll handle";
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return result;
    }

    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
    if (!pLoadLibrary) {
        result.errorMessage = "Failed to get LoadLibraryA address";
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return result;
    }

    /* Create remote thread to call LoadLibraryA(dllPath) */
    HANDLE hThread = CreateRemoteThread(
        hProcess, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLibrary),
        remotePath, 0, nullptr);

    if (!hThread) {
        result.errorCode = GetLastError();
        result.errorMessage = "Failed to create remote thread (error: " +
                               std::to_string(result.errorCode) + ")";
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return result;
    }

    /* Wait for remote thread to complete */
    WaitForSingleObject(hThread, 10000); /* 10 second timeout */

    /* Get return value (module handle from LoadLibrary) */
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    result.dllBaseAddress = static_cast<uintptr_t>(exitCode);

    /* Clean up */
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    if (result.dllBaseAddress != 0) {
        result.success = true;
    } else {
        result.errorMessage = "LoadLibraryA returned NULL in target process";
    }
#else
    result.errorMessage = "DLL injection only supported on Windows";
#endif

    return result;
}

bool DLLInjector::Eject(uint32_t pid, const char* dllName)
{
#ifdef _WIN32
    uintptr_t moduleBase = GetRemoteModuleHandle(pid, dllName);
    if (moduleBase == 0) return false;

    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    if (!hProcess) return false;

    /* Get FreeLibrary address */
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC pFreeLibrary = GetProcAddress(hKernel32, "FreeLibrary");

    /* Create remote thread to call FreeLibrary(moduleHandle) */
    HANDLE hThread = CreateRemoteThread(
        hProcess, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(pFreeLibrary),
        reinterpret_cast<LPVOID>(moduleBase), 0, nullptr);

    if (!hThread) {
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, 5000);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);

    CloseHandle(hThread);
    CloseHandle(hProcess);

    return exitCode != 0;
#else
    return false;
#endif
}

uintptr_t DLLInjector::IsDLLLoaded(uint32_t pid, const char* dllName)
{
    return GetRemoteModuleHandle(pid, dllName);
}

uintptr_t DLLInjector::GetRemoteModuleHandle(uint32_t pid, const char* moduleName)
{
#ifdef _WIN32
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);

    /* Convert narrow module name to wide for comparison */
    wchar_t wModuleName[MAX_MODULE_NAME32 + 1] = {};
    MultiByteToWideChar(CP_UTF8, 0, moduleName, -1, wModuleName, MAX_MODULE_NAME32 + 1);

    uintptr_t base = 0;

    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, wModuleName) == 0) {
                base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                break;
            }
        } while (Module32NextW(snap, &me));
    }

    CloseHandle(snap);
    return base;
#else
    return 0;
#endif
}

} /* namespace MuTracker */
