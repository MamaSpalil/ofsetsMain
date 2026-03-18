/*
 * ProcessMonitor.cpp
 * MuOffsetLogger - Мониторинг процесса main.exe MU Online
 *
 * Реализация модуля мониторинга процесса и окна игры.
 * Отслеживание: состояние процесса, окно, заголовок, фокус,
 * позиция, свёрнутость, видимость.
 * Совместимость: Visual Studio 2010 (v100), Windows 10 x86/x64
 */

#include "ProcessMonitor.h"
#include "Logger.h"
#include <tlhelp32.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

/* ============================================================
 * Статические данные модуля
 * ============================================================ */
static HANDLE      g_hMonProcess     = NULL;
static DWORD       g_MonProcessId    = 0;
static HWND        g_hGameWindow     = NULL;
static GAME_STATE  g_MonState        = GS_UNKNOWN;
static GAME_STATE  g_MonPrevState    = GS_UNKNOWN;
static char        g_MonWinTitle[256]     = {0};
static char        g_MonPrevWinTitle[256] = {0};
static RECT        g_MonWinRect      = {0, 0, 0, 0};
static RECT        g_MonPrevWinRect  = {0, 0, 0, 0};
static BOOL        g_MonWasMinimized   = FALSE;
static BOOL        g_MonWasForeground  = FALSE;
static BOOL        g_MonWasVisible     = TRUE;
static DWORD       g_MonStartTime      = 0;
static DWORD       g_MonEventCount     = 0;
static DWORD       g_MonLastUpdate     = 0;
static BOOL        g_MonInitialized    = FALSE;

/* Контекст для EnumWindows callback */
typedef struct _ENUM_WND_CTX
{
    DWORD ProcessId;
    HWND  ResultWindow;
} ENUM_WND_CTX;

/* ============================================================
 * Внутренние функции
 * ============================================================ */

/*
 * Callback для EnumWindows — поиск видимого окна верхнего уровня по PID
 */
static BOOL CALLBACK FindGameWindowProc(HWND hwnd, LPARAM lParam)
{
    ENUM_WND_CTX* ctx = (ENUM_WND_CTX*)lParam;
    DWORD windowPid   = 0;

    GetWindowThreadProcessId(hwnd, &windowPid);

    if (windowPid == ctx->ProcessId)
    {
        if (IsWindowVisible(hwnd) && GetParent(hwnd) == NULL)
        {
            char title[256];
            int  len;

            len = GetWindowTextA(hwnd, title, sizeof(title));
            if (len > 0)
            {
                ctx->ResultWindow = hwnd;
                return FALSE; /* Нашли — останавливаем перечисление */
            }
        }
    }

    return TRUE; /* Продолжаем поиск */
}

/*
 * Получение строкового представления состояния
 */
static const char* GetMonStateName(GAME_STATE state)
{
    switch (state)
    {
        case GS_UNKNOWN:        return "UNKNOWN";
        case GS_STARTING:       return "STARTING";
        case GS_WINDOW_CREATED: return "WINDOW_CREATED";
        case GS_ACTIVE:         return "ACTIVE";
        case GS_INACTIVE:       return "INACTIVE";
        case GS_MINIMIZED:      return "MINIMIZED";
        case GS_CLOSED:         return "CLOSED";
        default:                return "INVALID";
    }
}

/*
 * Логирование события мониторинга с меткой времени
 */
static void LogMonEvent(const char* eventType, const char* format, ...)
{
    char    details[512];
    va_list args;
    DWORD   elapsed;

    va_start(args, format);
    _vsnprintf(details, sizeof(details) - 1, format, args);
    va_end(args);
    details[sizeof(details) - 1] = '\0';

    elapsed = (GetTickCount() - g_MonStartTime) / 1000;

    Logger_Write(COLOR_OFFSET,
        "  [%02u:%02u:%02u]",
        elapsed / 3600, (elapsed % 3600) / 60, elapsed % 60);
    Logger_Write(COLOR_SECTION,
        " [%s]", eventType);
    Logger_Write(COLOR_DEFAULT,
        " %s\n", details);

    g_MonEventCount++;
}

/* ============================================================
 * Реализация API
 * ============================================================ */

DWORD ProcessMonitor_FindProcess(const char* processName)
{
    HANDLE         hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD          pid = 0;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return 0;

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32))
    {
        do
        {
            if (_stricmp(pe32.szExeFile, processName) == 0)
            {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return pid;
}

BOOL ProcessMonitor_Init(DWORD processId, HANDLE hProcess)
{
    if (g_MonInitialized)
        return TRUE;

    if (processId == 0)
        return FALSE;

    g_MonProcessId = processId;

    if (hProcess != NULL)
    {
        g_hMonProcess = hProcess;
    }
    else
    {
        g_hMonProcess = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE,
            FALSE, processId);

        if (g_hMonProcess == NULL)
        {
            Logger_Write(COLOR_WARN,
                "  [WARNING] Cannot open process %u for monitoring (error: %u)\n",
                processId, GetLastError());
            Logger_Write(COLOR_INFO,
                "  Window monitoring will still work.\n");
        }
    }

    g_MonState         = GS_STARTING;
    g_MonPrevState     = GS_UNKNOWN;
    g_MonStartTime     = GetTickCount();
    g_MonLastUpdate    = g_MonStartTime;
    g_MonEventCount    = 0;
    g_hGameWindow      = NULL;
    g_MonWasMinimized  = FALSE;
    g_MonWasForeground = FALSE;
    g_MonWasVisible    = TRUE;
    g_MonInitialized   = TRUE;

    memset(g_MonWinTitle, 0, sizeof(g_MonWinTitle));
    memset(g_MonPrevWinTitle, 0, sizeof(g_MonPrevWinTitle));
    memset(&g_MonWinRect, 0, sizeof(g_MonWinRect));
    memset(&g_MonPrevWinRect, 0, sizeof(g_MonPrevWinRect));

    Logger_WriteHeader("PROCESS MONITOR (MONITORING PROTSESSA main.exe)");

    Logger_Write(COLOR_INFO,
        "  Monitoring started for PID=%u\n", processId);
    Logger_Write(COLOR_INFO,
        "  Press Q or ESC to stop monitoring\n\n");

    LogMonEvent("INIT", "Process monitoring started (PID=%u)", processId);

    return TRUE;
}

BOOL ProcessMonitor_Update(void)
{
    DWORD now;

    if (!g_MonInitialized)
        return FALSE;

    now = GetTickCount();

    /* Ограничение частоты обновления: ~10 раз в секунду */
    if (now - g_MonLastUpdate < 100)
        return (g_MonState != GS_CLOSED);

    g_MonLastUpdate = now;

    /* ================================================================
     * 1. Проверка состояния процесса
     * ================================================================ */
    if (g_hMonProcess != NULL)
    {
        if (WaitForSingleObject(g_hMonProcess, 0) == WAIT_OBJECT_0)
        {
            DWORD exitCode = 0;
            GetExitCodeProcess(g_hMonProcess, &exitCode);

            g_MonPrevState = g_MonState;
            g_MonState     = GS_CLOSED;

            LogMonEvent("PROCESS", "main.exe terminated (exit code: %u)", exitCode);
            return FALSE;
        }
    }
    else
    {
        /* Нет хэндла процесса — проверяем по PID */
        HANDLE hCheck = OpenProcess(SYNCHRONIZE, FALSE, g_MonProcessId);
        if (hCheck == NULL)
        {
            g_MonPrevState = g_MonState;
            g_MonState     = GS_CLOSED;

            LogMonEvent("PROCESS", "main.exe process no longer exists (PID=%u)",
                g_MonProcessId);
            return FALSE;
        }
        CloseHandle(hCheck);
    }

    /* ================================================================
     * 2. Поиск / проверка окна игры
     * ================================================================ */
    {
        ENUM_WND_CTX ctx;
        ctx.ProcessId    = g_MonProcessId;
        ctx.ResultWindow = NULL;

        EnumWindows(FindGameWindowProc, (LPARAM)&ctx);

        if (ctx.ResultWindow != NULL && g_hGameWindow == NULL)
        {
            /* Обнаружено новое окно */
            g_hGameWindow = ctx.ResultWindow;
            g_MonPrevState = g_MonState;
            g_MonState     = GS_WINDOW_CREATED;

            GetWindowTextA(g_hGameWindow, g_MonWinTitle, sizeof(g_MonWinTitle));
            g_MonWinTitle[sizeof(g_MonWinTitle) - 1] = '\0';
            _snprintf(g_MonPrevWinTitle, sizeof(g_MonPrevWinTitle) - 1,
                "%s", g_MonWinTitle);
            g_MonPrevWinTitle[sizeof(g_MonPrevWinTitle) - 1] = '\0';

            GetWindowRect(g_hGameWindow, &g_MonWinRect);
            memcpy(&g_MonPrevWinRect, &g_MonWinRect, sizeof(RECT));

            LogMonEvent("WINDOW",
                "Game window created: \"%s\" (HWND=0x%p)",
                g_MonWinTitle, (void*)g_hGameWindow);
            LogMonEvent("WINDOW",
                "Window position: %d,%d  Size: %dx%d",
                g_MonWinRect.left, g_MonWinRect.top,
                g_MonWinRect.right - g_MonWinRect.left,
                g_MonWinRect.bottom - g_MonWinRect.top);
        }
        else if (ctx.ResultWindow == NULL && g_hGameWindow != NULL)
        {
            /* Окно исчезло (возможно, ещё не закрыт процесс) */
            LogMonEvent("WINDOW", "Game window destroyed");
            g_hGameWindow  = NULL;
            g_MonPrevState = g_MonState;
            g_MonState     = GS_STARTING;
        }
        else if (ctx.ResultWindow != NULL &&
                 ctx.ResultWindow != g_hGameWindow)
        {
            /* Окно изменилось (пересоздано) */
            g_hGameWindow = ctx.ResultWindow;
            GetWindowTextA(g_hGameWindow, g_MonWinTitle, sizeof(g_MonWinTitle));

            LogMonEvent("WINDOW",
                "Game window recreated: HWND=0x%p \"%s\"",
                (void*)g_hGameWindow, g_MonWinTitle);
        }
    }

    /* ================================================================
     * 3. Мониторинг окна игры (если найдено)
     * ================================================================ */
    if (g_hGameWindow != NULL && IsWindow(g_hGameWindow))
    {
        /* --- Проверка заголовка окна --- */
        {
            char currentTitle[256];
            GetWindowTextA(g_hGameWindow, currentTitle, sizeof(currentTitle));

            if (strcmp(currentTitle, g_MonPrevWinTitle) != 0)
            {
                LogMonEvent("TITLE",
                    "Window title changed: \"%s\" -> \"%s\"",
                    g_MonPrevWinTitle, currentTitle);

                _snprintf(g_MonPrevWinTitle, sizeof(g_MonPrevWinTitle) - 1,
                    "%s", currentTitle);
                g_MonPrevWinTitle[sizeof(g_MonPrevWinTitle) - 1] = '\0';
                _snprintf(g_MonWinTitle, sizeof(g_MonWinTitle) - 1,
                    "%s", currentTitle);
                g_MonWinTitle[sizeof(g_MonWinTitle) - 1] = '\0';
            }
        }

        /* --- Проверка позиции и размера окна --- */
        {
            RECT currentRect;
            GetWindowRect(g_hGameWindow, &currentRect);

            if (currentRect.left   != g_MonPrevWinRect.left  ||
                currentRect.top    != g_MonPrevWinRect.top   ||
                currentRect.right  != g_MonPrevWinRect.right ||
                currentRect.bottom != g_MonPrevWinRect.bottom)
            {
                LogMonEvent("RESIZE",
                    "Window moved/resized: %d,%d %dx%d -> %d,%d %dx%d",
                    g_MonPrevWinRect.left, g_MonPrevWinRect.top,
                    g_MonPrevWinRect.right  - g_MonPrevWinRect.left,
                    g_MonPrevWinRect.bottom - g_MonPrevWinRect.top,
                    currentRect.left, currentRect.top,
                    currentRect.right  - currentRect.left,
                    currentRect.bottom - currentRect.top);

                memcpy(&g_MonPrevWinRect, &currentRect, sizeof(RECT));
            }
        }

        /* --- Проверка фокуса (передний план / фон) --- */
        {
            HWND foreground    = GetForegroundWindow();
            BOOL isForeground  = (foreground == g_hGameWindow);

            if (isForeground && !g_MonWasForeground)
            {
                g_MonPrevState = g_MonState;
                g_MonState     = GS_ACTIVE;

                LogMonEvent("FOCUS",
                    "Game window gained focus (foreground)");
                g_MonWasForeground = TRUE;
            }
            else if (!isForeground && g_MonWasForeground)
            {
                g_MonPrevState = g_MonState;
                g_MonState     = GS_INACTIVE;

                LogMonEvent("FOCUS",
                    "Game window lost focus (background)");
                g_MonWasForeground = FALSE;
            }
        }

        /* --- Проверка свёрнутости окна --- */
        {
            BOOL isMinimized = IsIconic(g_hGameWindow);

            if (isMinimized && !g_MonWasMinimized)
            {
                g_MonPrevState = g_MonState;
                g_MonState     = GS_MINIMIZED;

                LogMonEvent("STATE", "Game window minimized");
                g_MonWasMinimized = TRUE;
            }
            else if (!isMinimized && g_MonWasMinimized)
            {
                g_MonPrevState = g_MonState;
                g_MonState     = GS_ACTIVE;

                LogMonEvent("STATE", "Game window restored from minimized");
                g_MonWasMinimized = FALSE;
            }
        }

        /* --- Проверка видимости --- */
        {
            BOOL isVisible = IsWindowVisible(g_hGameWindow);

            if (isVisible != g_MonWasVisible)
            {
                LogMonEvent("STATE", "Game window %s",
                    isVisible ? "became visible" : "became hidden");
                g_MonWasVisible = isVisible;
            }
        }
    }

    return TRUE;
}

BOOL ProcessMonitor_IsRunning(void)
{
    if (!g_MonInitialized)
        return FALSE;

    return (g_MonState != GS_CLOSED);
}

GAME_STATE ProcessMonitor_GetState(void)
{
    return g_MonState;
}

BOOL ProcessMonitor_ReadMemory(DWORD va, void* buffer, SIZE_T size)
{
    SIZE_T bytesRead = 0;

    if (g_hMonProcess == NULL || buffer == NULL)
        return FALSE;

    return ReadProcessMemory(g_hMonProcess, (LPCVOID)(DWORD_PTR)va,
                             buffer, size, &bytesRead);
}

DWORD ProcessMonitor_GetEventCount(void)
{
    return g_MonEventCount;
}

void ProcessMonitor_Shutdown(void)
{
    DWORD elapsed;

    if (!g_MonInitialized)
        return;

    elapsed = (GetTickCount() - g_MonStartTime) / 1000;

    Logger_Write(COLOR_DEFAULT, "\n");
    Logger_WriteHeader("MONITORING COMPLETE (MONITORING ZAVERSHEN)");

    Logger_Write(COLOR_INFO,
        "  Monitoring duration:  %02u:%02u:%02u\n",
        elapsed / 3600, (elapsed % 3600) / 60, elapsed % 60);
    Logger_Write(COLOR_INFO,
        "  Events recorded:      %u\n", g_MonEventCount);
    Logger_Write(COLOR_INFO,
        "  Final state:          %s\n", GetMonStateName(g_MonState));

    if (g_hMonProcess != NULL)
    {
        CloseHandle(g_hMonProcess);
        g_hMonProcess = NULL;
    }

    g_hGameWindow      = NULL;
    g_MonState         = GS_CLOSED;
    g_MonProcessId     = 0;
    g_MonInitialized   = FALSE;
}
