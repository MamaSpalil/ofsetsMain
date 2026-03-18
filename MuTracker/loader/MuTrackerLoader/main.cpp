/*
 * MuTrackerLoader - External Launcher & Process Manager (GUI Version)
 *
 * This is the external GUI launcher that:
 *   1. Finds or waits for main.exe (MuOnline) process
 *   2. Injects MuTrackerDLL.dll into the game process
 *   3. Provides a beautiful Win32 GUI for managing the tracker
 *   4. Displays real-time trace data via SharedMemory IPC
 *
 * Entry: WinMain (Windows subsystem, no console)
 * Compile: MSVC 2019+ (v142), C++17, x86/x64
 */

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>

#include "../src/core/MemoryUtils.h"
#include "../src/core/PatternScanner.h"
#include "../src/core/CallTracer.h"
#include "../src/log/Logger.h"
#include "../src/config/Config.h"
#include "../src/attach/ProcessAttacher.h"
#include "../src/attach/DLLInjector.h"

#include "MainWindow.h"

#include <string>

using namespace MuTracker;

/* ================================================================== */
/*  Global Instances                                                   */
/* ================================================================== */

static ProcessAttacher g_attacher;
static DLLInjector     g_injector;
static Config          g_config;

/* ================================================================== */
/*  Callback: Find Process                                             */
/* ================================================================== */

static DWORD FindProcessCallback(const char* procName)
{
    return g_attacher.FindProcessByName(procName);
}

/* ================================================================== */
/*  Callback: Inject DLL                                               */
/* ================================================================== */

static bool InjectCallback(DWORD pid, const std::wstring& dllPath)
{
    /* Convert wide path to narrow for the injector */
    char narrowPath[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, dllPath.c_str(), -1,
                         narrowPath, MAX_PATH, nullptr, nullptr);

    auto result = g_injector.Inject(pid, narrowPath);
    return result.success;
}

/* ================================================================== */
/*  Callback: Eject DLL                                                */
/* ================================================================== */

static bool EjectCallback(DWORD pid)
{
    return g_injector.Eject(pid, "MuTrackerDLL.dll");
}

/* ================================================================== */
/*  WinMain - GUI Entry Point                                          */
/* ================================================================== */

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE /*hPrevInstance*/,
                       LPWSTR /*lpCmdLine*/, int nCmdShow)
{
    /* Initialize logger (file only, no console) */
    Logger& log = Logger::Instance();
    log.Init("MuTrackerLoader.log", false, LogLevel::Info);
    MULOG_INFO("MuTracker Loader GUI starting...");

    /* Load configuration */
    if (g_config.Load("config.json")) {
        MULOG_INFO("Configuration loaded");
    } else {
        MULOG_WARN("config.json not found, creating default...");
        Config::CreateDefault("config.json");
        g_config.Load("config.json");
    }

    /* Create and show the main window */
    MainWindow mainWindow;

    /* Wire up callbacks */
    mainWindow.SetFindCallback(FindProcessCallback);
    mainWindow.SetInjectCallback(InjectCallback);
    mainWindow.SetEjectCallback(EjectCallback);

    if (!mainWindow.Create(hInstance, nCmdShow)) {
        MessageBoxW(nullptr, L"Failed to create main window.",
                     L"MuTracker Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    mainWindow.AppendLog("[MuTracker] Configuration loaded: %s\r\n",
                          g_config.Get().processName.c_str());

    /* Auto-attach if configured */
    if (g_config.Get().autoAttach) {
        DWORD pid = g_attacher.FindProcessByName(
            g_config.Get().processName.c_str());
        if (pid != 0) {
            mainWindow.AppendLog("[+] Auto-attached to %s (PID: %d)\r\n",
                                  g_config.Get().processName.c_str(), pid);
        }
    }

    /* Run the message loop */
    int exitCode = mainWindow.Run();

    /* Cleanup */
    MULOG_INFO("MuTracker Loader shutting down (exit code: %d)", exitCode);
    log.Shutdown();

    return exitCode;
}

#else
/* Non-Windows stub */
#include <cstdio>
int main() {
    printf("MuTracker requires Windows.\n");
    return 1;
}
#endif
