/*
 * dllmain.cpp
 * MuOffsetLogger - Система логирования офсетов main.exe MU Online
 *
 * Точка входа DLL. При внедрении в main.exe:
 * 1. Открывает консольное окно
 * 2. Анализирует PE-структуру main.exe в памяти
 * 3. Перехватывает и логирует все офсеты, переменные и функции
 * 4. Записывает результаты в txt-файл и выводит в консоль
 *
 * Совместимость: Visual Studio 2010 (v100), Windows 10 x86/x64
 *
 * Использование:
 *   Внедрить MuOffsetLogger.dll в процесс main.exe любым инжектором.
 *   При загрузке DLL откроется консольное окно с полным логом офсетов.
 *   Лог-файл сохраняется рядом с main.exe как MuOffsetLog.txt.
 */

#include <windows.h>
#include <stdio.h>
#include "Logger.h"
#include "PEAnalyzer.h"
#include "OffsetDatabase.h"
#include "FunctionScanner.h"

/* Имя лог-файла */
#define LOG_FILENAME "MuOffsetLog.txt"

/* Флаг работы */
static volatile BOOL g_Running = FALSE;
static HANDLE g_hThread = NULL;

/*
 * Получение пути к лог-файлу (рядом с main.exe)
 */
static void GetLogFilePath(char* buffer, DWORD bufSize)
{
    char modulePath[MAX_PATH];
    char* lastSlash;

    GetModuleFileNameA(NULL, modulePath, MAX_PATH);

    lastSlash = strrchr(modulePath, '\\');
    if (lastSlash != NULL)
    {
        *(lastSlash + 1) = '\0';
        _snprintf(buffer, bufSize - 1, "%s%s", modulePath, LOG_FILENAME);
    }
    else
    {
        _snprintf(buffer, bufSize - 1, "%s", LOG_FILENAME);
    }

    buffer[bufSize - 1] = '\0';
}

/*
 * Основной поток анализа и логирования
 */
static DWORD WINAPI AnalysisThread(LPVOID lpParam)
{
    HMODULE hMainModule;
    PE_FILE_INFO peInfo;
    char logPath[MAX_PATH];
    DWORD totalOffsets;

    (void)lpParam;
    g_Running = TRUE;

    /* Получение пути к лог-файлу */
    GetLogFilePath(logPath, MAX_PATH);

    /* Инициализация логгера */
    if (!Logger_Init(logPath))
    {
        MessageBoxA(NULL,
            "MuOffsetLogger: Failed to initialize logger!",
            "Error", MB_ICONERROR | MB_OK);
        g_Running = FALSE;
        return 1;
    }

    Logger_Write(COLOR_HEADER,
        "\n  MuOffsetLogger v1.0 - MU Online main.exe Offset Analyzer\n");
    Logger_Write(COLOR_INFO,
        "  Injected into process, starting analysis...\n\n");

    /* ================================================================
     * ЭТАП 1: Анализ PE-структуры
     * ================================================================ */
    Logger_WriteHeader("STAGE 1: PE STRUCTURE ANALYSIS");

    hMainModule = GetModuleHandleA(NULL);

    if (hMainModule == NULL)
    {
        Logger_Write(COLOR_WARN,
            "[ERROR] Cannot get main module handle!\n");
        Logger_Shutdown();
        g_Running = FALSE;
        return 1;
    }

    Logger_Write(COLOR_INFO,
        "  Main module base address: 0x%08X\n",
        (DWORD)(DWORD_PTR)hMainModule);  /* main.exe is PE32 (32-bit) */

    /* Разбор PE */
    if (!PEAnalyzer_Parse(hMainModule, &peInfo))
    {
        Logger_Write(COLOR_WARN,
            "[ERROR] Failed to parse PE headers!\n");
        Logger_Shutdown();
        g_Running = FALSE;
        return 1;
    }

    /* Вывод заголовков PE */
    PEAnalyzer_LogHeaders(&peInfo);

    /* Вывод секций */
    PEAnalyzer_LogSections(&peInfo);

    /* Вывод таблицы импорта */
    PEAnalyzer_LogImports(&peInfo);

    /* ================================================================
     * ЭТАП 2: База известных офсетов
     * ================================================================ */
    Logger_WriteHeader("STAGE 2: KNOWN OFFSETS DATABASE");

    OffsetDB_LogAllOffsets((DWORD_PTR)hMainModule);

    /* ================================================================
     * ЭТАП 3: Сканирование функций в .text секции
     * ================================================================ */
    Logger_WriteHeader("STAGE 3: FUNCTION SCANNING (.text section)");

    FuncScanner_ScanTextSection(&peInfo, (BYTE*)hMainModule);
    FuncScanner_LogResults();

    /* ================================================================
     * ЭТАП 4: Сканирование строковых ссылок
     * ================================================================ */
    Logger_WriteHeader("STAGE 4: STRING REFERENCE SCANNING");

    FuncScanner_ScanStringRefs(&peInfo, (BYTE*)hMainModule);
    FuncScanner_LogStringRefs();

    /* ================================================================
     * ИТОГИ
     * ================================================================ */
    totalOffsets = Logger_GetOffsetCount();

    Logger_Write(COLOR_DEFAULT, "\n");
    Logger_WriteHeader("ANALYSIS COMPLETE (ANALIZ ZAVERSHEN)");

    Logger_Write(COLOR_HEADER,
        "  Total offsets logged:         %u\n", totalOffsets);
    Logger_Write(COLOR_DEFAULT,
        "  Functions discovered:         %u\n",
        FuncScanner_GetCount());
    Logger_Write(COLOR_DEFAULT,
        "  Import DLLs:                  %u\n", peInfo.ImportDllCount);
    Logger_Write(COLOR_DEFAULT,
        "  PE Sections:                  %u\n", peInfo.SectionCount);
    Logger_Write(COLOR_HEADER,
        "  Log file saved to:            %s\n", logPath);

    Logger_Write(COLOR_DEFAULT, "\n");
    Logger_Write(COLOR_INFO,
        "  Press any key in console to close logger...\n");

    /* Ожидание нажатия клавиши (бесконечно, пока консоль открыта) */
    while (g_Running)
    {
        Sleep(100);
    }

    Logger_Shutdown();
    return 0;
}

/*
 * Экспортируемые функции для ручного управления
 */
extern "C" __declspec(dllexport) void StartLogging(void)
{
    if (g_hThread == NULL)
    {
        g_Running = TRUE;
        g_hThread = CreateThread(NULL, 0, AnalysisThread, NULL, 0, NULL);
    }
}

extern "C" __declspec(dllexport) void StopLogging(void)
{
    g_Running = FALSE;

    if (g_hThread != NULL)
    {
        WaitForSingleObject(g_hThread, 5000);
        CloseHandle(g_hThread);
        g_hThread = NULL;
    }
}

/*
 * Точка входа DLL
 */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
                      LPVOID lpReserved)
{
    (void)lpReserved;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        /* Запускаем анализ в отдельном потоке, чтобы не блокировать загрузку */
        g_Running = TRUE;
        g_hThread = CreateThread(NULL, 0, AnalysisThread, NULL, 0, NULL);
        break;

    case DLL_PROCESS_DETACH:
        StopLogging();
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }

    return TRUE;
}
