/*
 * main.cpp
 * MuOffsetLogger - Система логирования офсетов main.exe MU Online
 *
 * Консольное приложение (EXE). Логика работы:
 * 1. Помещаем MuOffsetLogger.exe в папку с игровым клиентом
 * 2. Запускаем MuOffsetLogger.exe — открывается консольное окно
 * 3. Автоматический поиск main.exe (или уже запущенного процесса)
 * 4. Анализ PE-структуры и автоматическая классификация офсетов
 * 5. Запуск мониторинга: отслеживание окна, фокуса, состояния main.exe
 * 6. Консоль остаётся открытой всё время работы main.exe
 * 7. Логи отображаются в консоли и сохраняются в MuOffsetLog.txt
 *
 * Совместимость: Visual Studio 2010 (v100), Windows 10 x86/x64
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <conio.h>
#include "Logger.h"
#include "PEAnalyzer.h"
#include "OffsetDatabase.h"
#include "FunctionScanner.h"
#include "ProcessMonitor.h"

/* Имя лог-файла */
#define LOG_FILENAME    "MuOffsetLog.txt"
/* Имя анализируемого исполняемого файла */
#define TARGET_EXE      "main.exe"

/*
 * Получение пути к файлу в директории EXE
 */
static void GetPathInExeDir(const char* fileName, char* buffer, DWORD bufSize)
{
    char modulePath[MAX_PATH];
    char* lastSlash;

    GetModuleFileNameA(NULL, modulePath, MAX_PATH);

    lastSlash = strrchr(modulePath, '\\');
    if (lastSlash != NULL)
    {
        *(lastSlash + 1) = '\0';
        _snprintf(buffer, bufSize - 1, "%s%s", modulePath, fileName);
    }
    else
    {
        _snprintf(buffer, bufSize - 1, "%s", fileName);
    }

    buffer[bufSize - 1] = '\0';
}

/*
 * Чтение файла main.exe с диска
 * Возвращает указатель на буфер с данными файла (нужно освободить VirtualFree)
 * fileSize — размер прочитанного файла
 */
static BYTE* ReadFileToBuffer(const char* filePath, DWORD* fileSize)
{
    HANDLE hFile;
    DWORD  size;
    DWORD  bytesRead;
    BYTE*  buffer;

    hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return NULL;

    size = GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE || size == 0)
    {
        CloseHandle(hFile);
        return NULL;
    }

    buffer = (BYTE*)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE,
                                  PAGE_READWRITE);
    if (buffer == NULL)
    {
        CloseHandle(hFile);
        return NULL;
    }

    if (!ReadFile(hFile, buffer, size, &bytesRead, NULL) || bytesRead != size)
    {
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return NULL;
    }

    CloseHandle(hFile);
    *fileSize = size;
    return buffer;
}

/*
 * Маппинг PE-файла в память: копируем заголовки и секции
 * на позиции их виртуальных адресов (эмуляция загрузки Windows)
 *
 * fileBuffer — данные файла с диска
 * fileSize   — размер файла
 *
 * Возвращает указатель на образ в памяти (нужно освободить VirtualFree)
 */
static BYTE* MapPEImage(BYTE* fileBuffer, DWORD fileSize)
{
    IMAGE_DOS_HEADER*    dosHeader;
    IMAGE_NT_HEADERS*    ntHeaders;
    IMAGE_SECTION_HEADER* sections;
    BYTE*                image;
    DWORD                sizeOfImage;
    DWORD                sizeOfHeaders;
    WORD                 numSections;
    WORD                 i;

    /* Проверка DOS заголовка */
    if (fileSize < sizeof(IMAGE_DOS_HEADER))
        return NULL;

    dosHeader = (IMAGE_DOS_HEADER*)fileBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    /* Проверка NT заголовков */
    if ((DWORD)dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > fileSize)
        return NULL;

    ntHeaders = (IMAGE_NT_HEADERS*)(fileBuffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    sizeOfImage   = ntHeaders->OptionalHeader.SizeOfImage;
    sizeOfHeaders = ntHeaders->OptionalHeader.SizeOfHeaders;
    numSections   = ntHeaders->FileHeader.NumberOfSections;

    /* Выделяем память под полный образ */
    image = (BYTE*)VirtualAlloc(NULL, sizeOfImage,
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (image == NULL)
        return NULL;

    memset(image, 0, sizeOfImage);

    /* Копируем заголовки PE */
    if (sizeOfHeaders > fileSize)
        sizeOfHeaders = fileSize;
    memcpy(image, fileBuffer, sizeOfHeaders);

    /* Копируем секции на их виртуальные позиции */
    sections = (IMAGE_SECTION_HEADER*)(
        fileBuffer + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

    for (i = 0; i < numSections; i++)
    {
        DWORD virtualAddr = sections[i].VirtualAddress;
        DWORD rawOffset   = sections[i].PointerToRawData;
        DWORD rawSize     = sections[i].SizeOfRawData;

        /* Проверка границ */
        if (rawOffset == 0 || rawSize == 0)
            continue;
        if (rawOffset + rawSize > fileSize)
            rawSize = fileSize - rawOffset;
        if (virtualAddr + rawSize > sizeOfImage)
            continue;

        memcpy(image + virtualAddr, fileBuffer + rawOffset, rawSize);
    }

    return image;
}

/*
 * Запуск main.exe из той же директории
 * Возвращает TRUE при успешном запуске
 * pProcessId     — PID запущенного процесса
 * pProcessHandle — хэндл процесса для мониторинга
 */
static BOOL LaunchMainExe(const char* exePath,
                          DWORD* pProcessId,
                          HANDLE* pProcessHandle)
{
    STARTUPINFOA        si;
    PROCESS_INFORMATION pi;

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    if (!CreateProcessA(exePath, NULL, NULL, NULL, FALSE,
                        0, NULL, NULL, &si, &pi))
    {
        return FALSE;
    }

    /* Возвращаем информацию для мониторинга */
    *pProcessId     = pi.dwProcessId;
    *pProcessHandle = pi.hProcess;

    /* Закрываем хэндл потока — не нужен для мониторинга */
    CloseHandle(pi.hThread);
    return TRUE;
}

/*
 * Точка входа консольного приложения
 */
int main(int argc, char* argv[])
{
    char exePath[MAX_PATH];
    char logPath[MAX_PATH];
    BYTE* fileBuffer   = NULL;
    BYTE* imageBuffer  = NULL;
    DWORD fileSize     = 0;
    PE_FILE_INFO peInfo;
    DWORD totalOffsets;
    int   userChoice;
    DWORD processId    = 0;
    HANDLE hProcess    = NULL;
    BOOL  launchGame   = FALSE;
    BOOL  monitorMode  = FALSE;

    (void)argc;
    (void)argv;

    /* Настройка консольного окна */
    SetConsoleTitleA("MuOffsetLogger - MU Online main.exe Offset Analyzer");

    printf("\n");
    printf("  ============================================================\n");
    printf("  MuOffsetLogger v2.0 - MU Online main.exe Offset Analyzer\n");
    printf("  Standalone EXE version\n");
    printf("  ============================================================\n");
    printf("\n");

    /* Путь к main.exe */
    GetPathInExeDir(TARGET_EXE, exePath, MAX_PATH);

    /* Проверяем наличие main.exe на диске */
    {
        DWORD attr = GetFileAttributesA(exePath);
        if (attr == INVALID_FILE_ATTRIBUTES)
        {
            printf("  [ERROR] File not found: %s\n", exePath);
            printf("  Place MuOffsetLogger.exe in the same folder as main.exe\n");
            printf("\n  Press any key to exit...");
            _getch();
            return 1;
        }
    }

    printf("  Found: %s\n", exePath);
    printf("\n");

    /* Проверяем, не запущен ли уже main.exe */
    processId = ProcessMonitor_FindProcess(TARGET_EXE);
    if (processId != 0)
    {
        printf("  [INFO] main.exe is already running (PID=%u)\n", processId);
        printf("  Attaching to existing process for monitoring.\n\n");

        /* Открываем хэндл для мониторинга */
        hProcess = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE,
            FALSE, processId);
        monitorMode = TRUE;
    }
    else
    {
        printf("  Launch main.exe and start offset analysis? (Zapustit' main.exe?)\n");
        printf("  1 - Yes, launch and monitor (Da, zapustit' i otslezhivat')\n");
        printf("  0 - No, only analyze file (Net, tol'ko analiz fajla)\n");
        printf("\n  Your choice (Vash vybor): ");

        userChoice = getchar();
        /* Очистка буфера ввода до конца строки */
        if (userChoice != '\n' && userChoice != EOF)
        {
            int c;
            while ((c = getchar()) != '\n' && c != EOF);
        }

        if (userChoice == '1')
        {
            launchGame = TRUE;
        }
    }

    /* ================================================================
     * Чтение и маппинг main.exe
     * ================================================================ */
    printf("\n  Reading %s from disk...\n", TARGET_EXE);

    fileBuffer = ReadFileToBuffer(exePath, &fileSize);
    if (fileBuffer == NULL)
    {
        printf("  [ERROR] Cannot read file: %s\n", exePath);
        printf("\n  Press any key to exit...");
        _getch();
        return 1;
    }

    printf("  File size: %u bytes (0x%08X)\n", fileSize, fileSize);
    printf("  Mapping PE sections into memory...\n");

    imageBuffer = MapPEImage(fileBuffer, fileSize);

    /* Файловый буфер больше не нужен */
    VirtualFree(fileBuffer, 0, MEM_RELEASE);
    fileBuffer = NULL;

    if (imageBuffer == NULL)
    {
        printf("  [ERROR] Failed to map PE image!\n");
        printf("\n  Press any key to exit...");
        _getch();
        return 1;
    }

    printf("  PE image mapped successfully.\n\n");

    /* ================================================================
     * Запуск main.exe (если пользователь выбрал и процесс ещё не запущен)
     * ================================================================ */
    if (launchGame && processId == 0)
    {
        printf("  Launching %s...\n", TARGET_EXE);

        if (LaunchMainExe(exePath, &processId, &hProcess))
        {
            printf("  main.exe launched successfully! (PID=%u)\n\n", processId);
            monitorMode = TRUE;
        }
        else
        {
            DWORD err = GetLastError();
            printf("  [WARNING] Failed to launch main.exe (error: %u)\n", err);
            printf("  Continuing with file analysis...\n\n");
        }
    }
    else if (!launchGame && !monitorMode)
    {
        printf("  Skipping main.exe launch. Analyzing file only...\n\n");
    }

    /* ================================================================
     * Инициализация логгера
     * ================================================================ */
    GetPathInExeDir(LOG_FILENAME, logPath, MAX_PATH);

    if (!Logger_Init(logPath))
    {
        printf("  [ERROR] Failed to initialize logger!\n");
        VirtualFree(imageBuffer, 0, MEM_RELEASE);
        printf("\n  Press any key to exit...");
        _getch();
        return 1;
    }

    Logger_Write(COLOR_HEADER,
        "\n  MuOffsetLogger v2.0 - MU Online main.exe Offset Analyzer\n");
    Logger_Write(COLOR_INFO,
        "  Standalone EXE: analyzing %s from disk\n", TARGET_EXE);
    Logger_Write(COLOR_INFO,
        "  File: %s\n", exePath);
    Logger_Write(COLOR_INFO,
        "  File size: %u bytes (0x%08X)\n\n", fileSize, fileSize);

    /* ================================================================
     * ЭТАП 1: Анализ PE-структуры
     * ================================================================ */
    Logger_WriteHeader("STAGE 1: PE STRUCTURE ANALYSIS (ANALIZ PE-STRUKTURY)");

    if (!PEAnalyzer_Parse((HMODULE)imageBuffer, &peInfo))
    {
        Logger_Write(COLOR_WARN,
            "[ERROR] Failed to parse PE headers!\n");
        Logger_Shutdown();
        VirtualFree(imageBuffer, 0, MEM_RELEASE);
        printf("\n  Press any key to exit...");
        _getch();
        return 1;
    }

    Logger_Write(COLOR_INFO,
        "  Mapped image base address: 0x%08X\n",
        (DWORD)(DWORD_PTR)imageBuffer);
    Logger_Write(COLOR_INFO,
        "  PE ImageBase: 0x%08X\n\n", peInfo.ImageBase);

    /* Вывод заголовков PE */
    PEAnalyzer_LogHeaders(&peInfo);

    /* Вывод секций */
    PEAnalyzer_LogSections(&peInfo);

    /* Вывод таблицы импорта */
    PEAnalyzer_LogImports(&peInfo);

    /* ================================================================
     * ЭТАП 2: База известных офсетов
     * ================================================================ */
    Logger_WriteHeader("STAGE 2: KNOWN OFFSETS DATABASE (BAZA IZVESTNYH OFSETOV)");

    OffsetDB_LogAllOffsets((DWORD_PTR)peInfo.ImageBase);

    /* ================================================================
     * ЭТАП 3: Сканирование функций в .text секции
     * ================================================================ */
    Logger_WriteHeader("STAGE 3: FUNCTION SCANNING (.text section)");

    FuncScanner_ScanTextSection(&peInfo, imageBuffer);
    FuncScanner_LogResults();

    /* ================================================================
     * ЭТАП 4: Сканирование строковых ссылок
     * ================================================================ */
    Logger_WriteHeader("STAGE 4: STRING REFERENCE SCANNING (POISK STROK)");

    FuncScanner_ScanStringRefs(&peInfo, imageBuffer);
    FuncScanner_LogStringRefs();

    /* ================================================================
     * ЭТАП 5: Автоматическая классификация функций (версионно-независимо)
     * ================================================================ */
    Logger_WriteHeader(
        "STAGE 5: AUTO-CLASSIFICATION (AVTOKLASSIFIKATSIYA FUNKTSIJ)");

    Logger_Write(COLOR_INFO,
        "  Analyzing function bodies for import calls and string refs...\n");
    Logger_Write(COLOR_INFO,
        "  This auto-detects function purpose regardless of main.exe version.\n\n");

    FuncScanner_AutoClassify(&peInfo, imageBuffer);
    FuncScanner_LogAutoClassified();

    /* ================================================================
     * ИТОГИ АНАЛИЗА
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

    /* Освобождаем образ PE — анализ файла завершён */
    VirtualFree(imageBuffer, 0, MEM_RELEASE);
    imageBuffer = NULL;

    /* ================================================================
     * РЕЖИМ МОНИТОРИНГА — отслеживание всех действий main.exe
     * Консольное окно остаётся открытым!
     * ================================================================ */
    if (monitorMode && processId != 0)
    {
        Logger_Write(COLOR_HEADER, "\n");
        Logger_Write(COLOR_HEADER,
            "  ============================================================\n");
        Logger_Write(COLOR_HEADER,
            "  MONITORING MODE - Tracking all main.exe actions\n");
        Logger_Write(COLOR_HEADER,
            "  (REZHIM MONITORINGA - Otslezhivanie vsekh dejstvij main.exe)\n");
        Logger_Write(COLOR_HEADER,
            "  Press Q or ESC to stop monitoring and exit\n");
        Logger_Write(COLOR_HEADER,
            "  ============================================================\n\n");

        if (ProcessMonitor_Init(processId, hProcess))
        {
            /* Главный цикл мониторинга — окно остаётся открытым */
            while (ProcessMonitor_IsRunning())
            {
                /* Проверяем нажатие клавиши (неблокирующее) */
                if (_kbhit())
                {
                    int key = _getch();
                    if (key == 'q' || key == 'Q' || key == 27) /* q, Q, ESC */
                    {
                        Logger_Write(COLOR_INFO,
                            "\n  User requested exit. Stopping monitor...\n");
                        break;
                    }
                }

                /* Обновляем мониторинг */
                if (!ProcessMonitor_Update())
                {
                    Logger_Write(COLOR_INFO,
                        "\n  main.exe has closed. Monitoring stopped.\n");
                    break;
                }

                Sleep(100); /* 100 мс — aligned with monitor's update throttle */
            }

            ProcessMonitor_Shutdown();

            /* hProcess закрыт внутри ProcessMonitor_Shutdown, обнуляем */
            hProcess = NULL;
        }
        else
        {
            Logger_Write(COLOR_WARN,
                "  [WARNING] Failed to initialize process monitor.\n");
        }
    }
    else
    {
        Logger_Write(COLOR_INFO,
            "  File analysis mode. No process monitoring.\n");
    }

    /* ================================================================
     * Финальное завершение
     * ================================================================ */
    Logger_Write(COLOR_DEFAULT, "\n");
    Logger_Write(COLOR_HEADER,
        "  Analysis and monitoring complete.\n");
    Logger_Write(COLOR_INFO,
        "  Log saved to: %s\n", logPath);
    Logger_Write(COLOR_INFO,
        "  Press any key to close... (Nazhmi lyubuyu klavishu)\n");

    Logger_Shutdown();

    /* Если хэндл процесса не был передан монитору, закроем его */
    if (hProcess != NULL)
    {
        CloseHandle(hProcess);
        hProcess = NULL;
    }

    /* Ожидание нажатия любой клавиши (гарантия: окно не закроется само) */
    _getch();

    return 0;
}
