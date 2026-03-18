/*
 * DLLInjector.cpp - DLL Injection Implementation
 *
 * All injection steps are logged to a text file for diagnostics.
 */

#include "DLLInjector.h"

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#endif

#include <cstring>
#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <chrono>
#include <filesystem>

namespace MuTracker {

DLLInjector::DLLInjector()
{
}

DLLInjector::~DLLInjector()
{
    std::lock_guard<std::mutex> lock(m_logMutex);
    if (m_logFile.is_open()) {
        m_logFile.close();
    }
}

/* ================================================================== */
/*  Logging Helpers                                                    */
/* ================================================================== */

std::string DLLInjector::GetTimestamp() const
{
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    struct tm timeinfo;
#ifdef _WIN32
    localtime_s(&timeinfo, &time_t_now);
#else
    localtime_r(&time_t_now, &timeinfo);
#endif

    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
             timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
             timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec,
             static_cast<int>(ms.count()));
    return std::string(buf);
}

void DLLInjector::SetLogFile(const std::string& logFilePath)
{
    std::lock_guard<std::mutex> lock(m_logMutex);
    if (m_logFile.is_open()) {
        m_logFile.close();
    }
    m_logFile.open(logFilePath, std::ios::out | std::ios::app);
}

void DLLInjector::LogInject(const char* fmt, ...)
{
    std::lock_guard<std::mutex> lock(m_logMutex);
    if (!m_logFile.is_open()) return;

    char buf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    std::string ts = GetTimestamp();
    m_logFile << "[" << ts << "] " << buf << std::endl;
    m_logFile.flush();
}

/* ================================================================== */
/*  SeDebugPrivilege                                                   */
/* ================================================================== */

bool DLLInjector::EnableDebugPrivilege()
{
#ifdef _WIN32
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        LogInject("  [WARN] OpenProcessToken failed (error: %lu)", GetLastError());
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &luid)) {
        LogInject("  [WARN] LookupPrivilegeValue for SeDebugPrivilege failed (error: %lu)",
                  GetLastError());
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
        LogInject("  [WARN] AdjustTokenPrivileges failed (error: %lu)", GetLastError());
        CloseHandle(hToken);
        return false;
    }

    DWORD err = GetLastError();
    CloseHandle(hToken);

    if (err == ERROR_NOT_ALL_ASSIGNED) {
        LogInject("  [WARN] SeDebugPrivilege not assigned - process may lack admin rights");
        return false;
    }

    LogInject("  [OK] SeDebugPrivilege enabled successfully");
    return true;
#else
    return false;
#endif
}

/* ================================================================== */
/*  Inject                                                             */
/* ================================================================== */

InjectionResult DLLInjector::Inject(uint32_t pid, const std::string& dllPath,
                                      InjectionMethod method)
{
    LogInject("========================================");
    LogInject("INJECTION ATTEMPT START");
    LogInject("  Target PID  : %u", pid);
    LogInject("  DLL Path    : %s", dllPath.c_str());
    LogInject("  Method      : %s",
              method == InjectionMethod::LoadLib ? "LoadLibrary" : "ManualMap");

    InjectionResult result;

    switch (method) {
    case InjectionMethod::LoadLib:
        result = InjectLoadLibrary(pid, dllPath);
        break;
    case InjectionMethod::ManualMap:
        result = { false, 0, 0, "ManualMap injection not yet implemented" };
        break;
    default:
        result = { false, 0, 0, "Unknown injection method" };
        break;
    }

    if (result.success) {
        LogInject("INJECTION RESULT: SUCCESS (base address: 0x%08X)",
                  static_cast<unsigned int>(result.dllBaseAddress));
    } else {
        LogInject("INJECTION RESULT: FAILED");
        LogInject("  Error Code  : %u", result.errorCode);
        LogInject("  Error       : %s", result.errorMessage.c_str());
    }
    LogInject("========================================\n");

    return result;
}

/* ================================================================== */
/*  InjectLoadLibrary                                                  */
/* ================================================================== */

InjectionResult DLLInjector::InjectLoadLibrary(uint32_t pid,
                                                 const std::string& dllPath)
{
    InjectionResult result = { false, 0, 0, "" };

#ifdef _WIN32
    /* ---- Step 1: Validate DLL file exists ---- */
    LogInject("  [Step 1] Validating DLL file exists...");
    {
        std::error_code ec;
        if (!std::filesystem::exists(dllPath, ec)) {
            result.errorCode = ERROR_FILE_NOT_FOUND;
            result.errorMessage = "DLL file not found at path: " + dllPath;
            LogInject("  [FAIL] DLL file does not exist: %s", dllPath.c_str());
            return result;
        }
        if (!std::filesystem::is_regular_file(dllPath, ec)) {
            result.errorCode = ERROR_FILE_NOT_FOUND;
            result.errorMessage = "DLL path is not a regular file: " + dllPath;
            LogInject("  [FAIL] Path is not a regular file: %s", dllPath.c_str());
            return result;
        }
        auto fileSize = std::filesystem::file_size(dllPath, ec);
        LogInject("  [OK] DLL file exists (size: %llu bytes)",
                  static_cast<unsigned long long>(fileSize));
    }

    /* ---- Step 2: Enable SeDebugPrivilege ---- */
    LogInject("  [Step 2] Enabling SeDebugPrivilege...");
    EnableDebugPrivilege();

    /* ---- Step 3: Open target process ---- */
    LogInject("  [Step 3] Opening target process (PID: %u)...", pid);
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD |
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, pid);

    if (!hProcess) {
        result.errorCode = GetLastError();
        result.errorMessage = "Failed to open target process (PID: " +
                               std::to_string(pid) + ", error: " +
                               std::to_string(result.errorCode) + ")";

        /* Provide human-readable reason */
        if (result.errorCode == ERROR_ACCESS_DENIED) {
            result.errorMessage += " - Access denied. Run as Administrator.";
        } else if (result.errorCode == ERROR_INVALID_PARAMETER) {
            result.errorMessage += " - Invalid parameter. Process may have exited.";
        } else if (result.errorCode == ERROR_INVALID_HANDLE) {
            result.errorMessage += " - Invalid handle. Process does not exist.";
        }

        LogInject("  [FAIL] OpenProcess failed (error: %u)", result.errorCode);
        return result;
    }
    LogInject("  [OK] Process opened successfully (handle: 0x%p)", hProcess);

    /* ---- Step 4: Verify process is still alive ---- */
    LogInject("  [Step 4] Verifying target process is alive...");
    {
        DWORD exitCodeCheck = 0;
        if (GetExitCodeProcess(hProcess, &exitCodeCheck) && exitCodeCheck != STILL_ACTIVE) {
            result.errorCode = 0;
            result.errorMessage = "Target process (PID: " + std::to_string(pid) +
                                   ") has already exited (exit code: " +
                                   std::to_string(exitCodeCheck) + ")";
            LogInject("  [FAIL] Process already exited (exit code: %u)", exitCodeCheck);
            CloseHandle(hProcess);
            return result;
        }
        LogInject("  [OK] Process is running");
    }

    /* ---- Step 5: Allocate memory in target process ---- */
    LogInject("  [Step 5] Allocating memory in target process for DLL path (%zu bytes)...",
              dllPath.length() + 1);
    size_t pathSize = dllPath.length() + 1;
    LPVOID remotePath = VirtualAllocEx(hProcess, nullptr, pathSize,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_READWRITE);
    if (!remotePath) {
        result.errorCode = GetLastError();
        result.errorMessage = "Failed to allocate memory in target process (error: " +
                               std::to_string(result.errorCode) + ")";
        LogInject("  [FAIL] VirtualAllocEx failed (error: %u)", result.errorCode);
        CloseHandle(hProcess);
        return result;
    }
    LogInject("  [OK] Remote memory allocated at 0x%p", remotePath);

    /* ---- Step 6: Write DLL path to target process ---- */
    LogInject("  [Step 6] Writing DLL path to target process memory...");
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, remotePath, dllPath.c_str(),
                             pathSize, &bytesWritten)) {
        result.errorCode = GetLastError();
        result.errorMessage = "Failed to write DLL path to target process (error: " +
                               std::to_string(result.errorCode) + ")";
        LogInject("  [FAIL] WriteProcessMemory failed (error: %u)", result.errorCode);
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return result;
    }
    LogInject("  [OK] Wrote %zu bytes to remote process", static_cast<size_t>(bytesWritten));

    /* ---- Step 7: Resolve LoadLibraryA address ---- */
    LogInject("  [Step 7] Resolving LoadLibraryA address from kernel32.dll...");
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        result.errorCode = GetLastError();
        result.errorMessage = "Failed to get kernel32.dll handle (error: " +
                               std::to_string(result.errorCode) + ")";
        LogInject("  [FAIL] GetModuleHandleA(\"kernel32.dll\") failed");
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return result;
    }

    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
    if (!pLoadLibrary) {
        result.errorCode = GetLastError();
        result.errorMessage = "Failed to get LoadLibraryA address (error: " +
                               std::to_string(result.errorCode) + ")";
        LogInject("  [FAIL] GetProcAddress(\"LoadLibraryA\") failed");
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return result;
    }
    LogInject("  [OK] LoadLibraryA address: 0x%p", reinterpret_cast<void*>(pLoadLibrary));

    /* ---- Step 8: Create remote thread ---- */
    LogInject("  [Step 8] Creating remote thread (LoadLibraryA with DLL path)...");
    HANDLE hThread = CreateRemoteThread(
        hProcess, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLibrary),
        remotePath, 0, nullptr);

    if (!hThread) {
        result.errorCode = GetLastError();
        result.errorMessage = "Failed to create remote thread (error: " +
                               std::to_string(result.errorCode) + ")";

        if (result.errorCode == ERROR_ACCESS_DENIED) {
            result.errorMessage += " - Access denied. Target may be protected or require elevation.";
        }

        LogInject("  [FAIL] CreateRemoteThread failed (error: %u)", result.errorCode);
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return result;
    }
    LogInject("  [OK] Remote thread created (handle: 0x%p)", hThread);

    /* ---- Step 9: Wait for remote thread to complete ---- */
    LogInject("  [Step 9] Waiting for remote thread to complete (timeout: 10s)...");
    DWORD waitResult = WaitForSingleObject(hThread, 10000);

    if (waitResult == WAIT_TIMEOUT) {
        result.errorCode = 0;
        result.errorMessage = "Remote thread timed out after 10 seconds. "
                               "LoadLibraryA may be blocked or hung in the target process. "
                               "Possible causes: DLL has a long DllMain, "
                               "loader lock contention, or anti-cheat blocking.";
        LogInject("  [FAIL] WaitForSingleObject returned WAIT_TIMEOUT");
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return result;
    }

    if (waitResult == WAIT_FAILED) {
        result.errorCode = GetLastError();
        result.errorMessage = "WaitForSingleObject failed (error: " +
                               std::to_string(result.errorCode) + ")";
        LogInject("  [FAIL] WaitForSingleObject returned WAIT_FAILED (error: %u)",
                  result.errorCode);
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return result;
    }
    LogInject("  [OK] Remote thread completed (wait result: %u)", waitResult);

    /* ---- Step 10: Get LoadLibraryA return value ---- */
    LogInject("  [Step 10] Retrieving LoadLibraryA return value...");
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    result.dllBaseAddress = static_cast<uintptr_t>(exitCode);
    LogInject("  LoadLibraryA returned: 0x%08X", exitCode);

    /* Clean up */
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    if (result.dllBaseAddress != 0) {
        result.success = true;
        LogInject("  [OK] DLL loaded at base address: 0x%08X",
                  static_cast<unsigned int>(result.dllBaseAddress));
    } else {
        result.errorMessage = "LoadLibraryA returned NULL in target process. "
                               "Possible causes: DLL file not found by target process "
                               "(check path and working directory), DLL architecture mismatch "
                               "(32-bit vs 64-bit), missing DLL dependencies, "
                               "or DllMain returned FALSE.";
        LogInject("  [FAIL] LoadLibraryA returned NULL (0x00000000)");
        LogInject("  Possible causes:");
        LogInject("    - DLL file not accessible from target process context");
        LogInject("    - Architecture mismatch (injecting x64 DLL into x86 process or vice versa)");
        LogInject("    - DLL has missing dependencies (check with Dependency Walker)");
        LogInject("    - DllMain() returned FALSE");
        LogInject("    - Path contains non-ASCII characters (use ASCII-only path)");
    }
#else
    result.errorMessage = "DLL injection only supported on Windows";
#endif

    return result;
}

bool DLLInjector::Eject(uint32_t pid, const char* dllName)
{
#ifdef _WIN32
    LogInject("Eject request: PID=%u, module=%s", pid, dllName);

    uintptr_t moduleBase = GetRemoteModuleHandle(pid, dllName);
    if (moduleBase == 0) {
        LogInject("  [FAIL] Module '%s' not found in process %u", dllName, pid);
        return false;
    }

    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    if (!hProcess) {
        LogInject("  [FAIL] OpenProcess failed for eject (error: %lu)", GetLastError());
        return false;
    }

    /* Get FreeLibrary address */
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC pFreeLibrary = GetProcAddress(hKernel32, "FreeLibrary");

    /* Create remote thread to call FreeLibrary(moduleHandle) */
    HANDLE hThread = CreateRemoteThread(
        hProcess, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(pFreeLibrary),
        reinterpret_cast<LPVOID>(moduleBase), 0, nullptr);

    if (!hThread) {
        LogInject("  [FAIL] CreateRemoteThread for eject failed (error: %lu)", GetLastError());
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, 5000);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);

    CloseHandle(hThread);
    CloseHandle(hProcess);

    bool ok = exitCode != 0;
    LogInject("  Eject result: %s", ok ? "SUCCESS" : "FAILED");
    return ok;
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
