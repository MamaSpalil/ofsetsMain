/*
 * Logger.cpp
 * MuOffsetLogger - Система логирования офсетов main.exe MU Online
 *
 * Реализация модуля логирования
 * Совместимость: Visual Studio 2010 (v100), Windows 10 x86/x64
 */

#include "Logger.h"
#include <stdarg.h>
#include <time.h>

static FILE*   g_LogFile       = NULL;
static HANDLE  g_hConsole      = NULL;
static DWORD   g_OffsetCount   = 0;
static BOOL    g_Initialized   = FALSE;

static const char* SEPARATOR_LINE =
    "====================================================================================================";

BOOL Logger_Init(const char* logFilePath)
{
    if (g_Initialized)
        return TRUE;

    /* Создание консольного окна */
    AllocConsole();
    SetConsoleTitleA("MuOffsetLogger - MU Online main.exe Offset Analyzer");

    g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (g_hConsole == INVALID_HANDLE_VALUE)
        return FALSE;

    /* Установка размера буфера консоли */
    {
        COORD bufferSize;
        bufferSize.X = 180;
        bufferSize.Y = 9999;
        SetConsoleScreenBufferSize(g_hConsole, bufferSize);
    }

    /* Установка размера окна консоли */
    {
        SMALL_RECT windowSize;
        windowSize.Left   = 0;
        windowSize.Top    = 0;
        windowSize.Right  = 179;
        windowSize.Bottom = 50;
        SetConsoleWindowInfo(g_hConsole, TRUE, &windowSize);
    }

    /* Перенаправление stdout в консоль */
    freopen("CONOUT$", "w", stdout);

    /* Открытие файла для записи */
    g_LogFile = fopen(logFilePath, "w");
    if (g_LogFile == NULL)
    {
        Logger_Write(COLOR_WARN,
            "[WARNING] Cannot open log file: %s\n", logFilePath);
        /* Продолжаем работу без файла */
    }

    g_OffsetCount  = 0;
    g_Initialized  = TRUE;

    /* Записываем заголовок */
    {
        time_t     rawtime;
        struct tm* timeinfo;
        char       timeStr[64];

        time(&rawtime);
        timeinfo = localtime(&rawtime);
        strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", timeinfo);

        Logger_WriteSeparator();
        Logger_Write(COLOR_HEADER,
            "  MuOffsetLogger - MU Online main.exe Offset Analyzer\n");
        Logger_Write(COLOR_HEADER,
            "  Date: %s\n", timeStr);
        Logger_Write(COLOR_HEADER,
            "  Log file: %s\n", logFilePath);
        Logger_WriteSeparator();
        Logger_Write(COLOR_DEFAULT, "\n");
    }

    return TRUE;
}

void Logger_Shutdown(void)
{
    if (!g_Initialized)
        return;

    Logger_Write(COLOR_DEFAULT, "\n");
    Logger_WriteSeparator();
    Logger_Write(COLOR_HEADER,
        "  Total offsets logged: %u\n", g_OffsetCount);
    Logger_WriteSeparator();

    if (g_LogFile != NULL)
    {
        fflush(g_LogFile);
        fclose(g_LogFile);
        g_LogFile = NULL;
    }

    FreeConsole();
    g_Initialized = FALSE;
}

void Logger_WriteHeader(const char* text)
{
    Logger_Write(COLOR_DEFAULT, "\n");
    Logger_WriteSeparator();
    Logger_Write(COLOR_SECTION, "  %s\n", text);
    Logger_WriteSeparator();
    Logger_Write(COLOR_DEFAULT, "\n");
}

void Logger_WriteSeparator(void)
{
    Logger_Write(COLOR_INFO, "%s\n", SEPARATOR_LINE);
}

void Logger_Write(WORD color, const char* format, ...)
{
    char    buffer[2048];
    va_list args;
    int     len;

    va_start(args, format);
    len = _vsnprintf(buffer, sizeof(buffer) - 1, format, args);
    va_end(args);

    if (len < 0)
        len = sizeof(buffer) - 1;
    buffer[len] = '\0';

    /* Вывод в консоль с цветом */
    if (g_hConsole != NULL)
    {
        DWORD written;
        SetConsoleTextAttribute(g_hConsole, color);
        WriteConsoleA(g_hConsole, buffer, (DWORD)len, &written, NULL);
        SetConsoleTextAttribute(g_hConsole, COLOR_DEFAULT);
    }

    /* Запись в файл */
    if (g_LogFile != NULL)
    {
        fprintf(g_LogFile, "%s", buffer);
        fflush(g_LogFile);
    }
}

void Logger_WriteOffset(DWORD va, DWORD fileOffset, const char* category,
                        const char* name, const char* description)
{
    Logger_Write(COLOR_OFFSET,
        "  0x%08X", va);
    Logger_Write(COLOR_INFO,
        "  (File: 0x%08X)", fileOffset);
    Logger_Write(COLOR_SECTION,
        "  [%s]", category);
    Logger_Write(COLOR_DEFAULT,
        "  %s", name);
    if (description != NULL && description[0] != '\0')
    {
        Logger_Write(COLOR_INFO,
            " -- %s", description);
    }
    Logger_Write(COLOR_DEFAULT, "\n");

    g_OffsetCount++;
}

void Logger_WriteImport(DWORD iatVA, const char* dllName,
                        const char* funcName, DWORD callCount)
{
    Logger_Write(COLOR_IMPORT,
        "  0x%08X", iatVA);
    Logger_Write(COLOR_INFO,
        "  [IAT]");
    Logger_Write(COLOR_DEFAULT,
        "  %s", funcName);
    Logger_Write(COLOR_INFO,
        "  (%s, calls: %u)", dllName, callCount);
    Logger_Write(COLOR_DEFAULT, "\n");

    g_OffsetCount++;
}

void Logger_WriteFunction(DWORD va, DWORD fileOffset,
                          const char* name, const char* description)
{
    Logger_Write(COLOR_FUNCTION,
        "  0x%08X", va);
    Logger_Write(COLOR_INFO,
        "  (File: 0x%08X)", fileOffset);
    Logger_Write(COLOR_SECTION,
        "  [FUNC]");
    Logger_Write(COLOR_DEFAULT,
        "  %s", name);
    if (description != NULL && description[0] != '\0')
    {
        Logger_Write(COLOR_INFO,
            " -- %s", description);
    }
    Logger_Write(COLOR_DEFAULT, "\n");

    g_OffsetCount++;
}

void Logger_WriteVariable(DWORD va, DWORD fileOffset,
                          const char* name, const char* description)
{
    Logger_Write(COLOR_VARIABLE,
        "  0x%08X", va);
    Logger_Write(COLOR_INFO,
        "  (File: 0x%08X)", fileOffset);
    Logger_Write(COLOR_SECTION,
        "  [VAR]");
    Logger_Write(COLOR_DEFAULT,
        "  %s", name);
    if (description != NULL && description[0] != '\0')
    {
        Logger_Write(COLOR_INFO,
            " -- %s", description);
    }
    Logger_Write(COLOR_DEFAULT, "\n");

    g_OffsetCount++;
}

DWORD Logger_GetOffsetCount(void)
{
    return g_OffsetCount;
}
