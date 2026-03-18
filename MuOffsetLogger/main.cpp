/*
 * main.cpp
 * MuOffsetLogger - Система логирования офсетов main.exe MU Online
 *
 * Консольное приложение (EXE). Логика работы:
 * 1. Помещаем MuOffsetLogger.exe в папку с игровым клиентом
 * 2. Запускаем MuOffsetLogger.exe — открывается консольное окно с меню
 * 3. Консоль остаётся открытой (главный цикл меню)
 * 4. Пользователь выбирает действие из меню:
 *    - Поиск main.exe
 *    - Запуск main.exe
 *    - Запуск поиска офсетов (PE-анализ + мониторинг)
 *    - Пауза программы
 *    - Остановить отладку (дебаг)
 *    - Закрыть программу
 * 5. Логи отображаются в консоли и сохраняются в MuOffsetLog.txt
 *
 * Совместимость: Visual Studio 2010 (v100), Windows 10 x86/x64
 */

#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <string.h>
#include <conio.h>
#include "Logger.h"
#include "PEAnalyzer.h"
#include "OffsetDatabase.h"
#include "FunctionScanner.h"
#include "ProcessMonitor.h"
#include "GameMonitor.h"
#include "OffsetStore.h"

/* Имя лог-файла */
#define LOG_FILENAME    "MuOffsetLog.txt"
/* Имя анализируемого исполняемого файла */
#define TARGET_EXE      "main.exe"
/* Код клавиши ESC */
#define KEY_ESC         27

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

    /* Копируем заголовки PE.
     * Некоторые упакованные PE (ASProtect и др.) могут иметь SizeOfHeaders
     * меньше реального объёма заголовков. Вычисляем минимальный размер,
     * включающий DOS-заголовок, NT-заголовки и все заголовки секций. */
    {
        DWORD headerEndOffset = (DWORD)dosHeader->e_lfanew
                                + sizeof(DWORD)
                                + sizeof(IMAGE_FILE_HEADER)
                                + ntHeaders->FileHeader.SizeOfOptionalHeader
                                + numSections * sizeof(IMAGE_SECTION_HEADER);
        DWORD copySize = (sizeOfHeaders > headerEndOffset)
                         ? sizeOfHeaders : headerEndOffset;
        if (copySize > fileSize)
            copySize = fileSize;
        if (copySize > sizeOfImage)
            copySize = sizeOfImage;
        memcpy(image, fileBuffer, copySize);
    }

    /* Копируем секции на их виртуальные позиции */
    sections = (IMAGE_SECTION_HEADER*)(
        fileBuffer + dosHeader->e_lfanew + sizeof(DWORD)
        + sizeof(IMAGE_FILE_HEADER)
        + ntHeaders->FileHeader.SizeOfOptionalHeader);

    for (i = 0; i < numSections; i++)
    {
        DWORD virtualAddr = sections[i].VirtualAddress;
        DWORD rawOffset   = sections[i].PointerToRawData;
        DWORD rawSize     = sections[i].SizeOfRawData;

        /* Проверка границ */
        if (rawOffset == 0 || rawSize == 0)
            continue;
        if (rawOffset >= fileSize)
            continue;
        if (rawOffset + rawSize > fileSize)
            rawSize = fileSize - rawOffset;
        if (virtualAddr >= sizeOfImage)
            continue;
        if (virtualAddr + rawSize > sizeOfImage)
            rawSize = sizeOfImage - virtualAddr;

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

    if (CreateProcessA(exePath, NULL, NULL, NULL, FALSE,
                        0, NULL, NULL, &si, &pi))
    {
        /* Возвращаем информацию для мониторинга */
        *pProcessId     = pi.dwProcessId;
        *pProcessHandle = pi.hProcess;

        /* Закрываем хэндл потока — не нужен для мониторинга */
        CloseHandle(pi.hThread);
        return TRUE;
    }

    /* Если CreateProcess вернул ERROR_ELEVATION_REQUIRED (740),
     * повторяем запуск через ShellExecuteEx с verb "runas"
     * для запроса повышения прав (UAC) */
    if (GetLastError() == ERROR_ELEVATION_REQUIRED)
    {
        SHELLEXECUTEINFOA sei;
        memset(&sei, 0, sizeof(sei));
        sei.cbSize = sizeof(sei);
        sei.fMask  = SEE_MASK_NOCLOSEPROCESS;
        sei.lpVerb = "runas";
        sei.lpFile = exePath;
        sei.nShow  = SW_SHOWNORMAL;

        if (ShellExecuteExA(&sei))
        {
            DWORD pid = GetProcessId(sei.hProcess);
            if (pid == 0)
            {
                CloseHandle(sei.hProcess);
                return FALSE;
            }
            *pProcessHandle = sei.hProcess;
            *pProcessId     = pid;
            return TRUE;
        }
    }

    return FALSE;
}

/*
 * Вывод главного меню с текущим статусом
 */
static void ShowMenu(BOOL exeFound, const char* exePath,
                     DWORD processId, BOOL analysisComplete)
{
    printf("\n");
    printf("  ============================================================\n");
    printf("  Menu:\n");
    printf("  ------------------------------------------------------------\n");
    printf("  1 - Poisk main.exe                (Find main.exe)\n");
    printf("  2 - Zapusk main.exe + avto-poisk   (Launch + auto offset search)\n");
    printf("  3 - Zapusk poiska ofsetov          (Start offset search)\n");
    printf("  4 - Pauza programmy               (Pause program)\n");
    printf("  5 - Ostanovit' otladku (debug)    (Stop debugging)\n");
    printf("  6 - Zakryt' programmu             (Close program)\n");
    printf("  ------------------------------------------------------------\n");

    /* Строка статуса */
    if (exeFound)
        printf("  [main.exe: found]");
    else
        printf("  [main.exe: not found]");

    if (processId != 0)
        printf("  [Process: PID=%u]", processId);
    else
        printf("  [Process: -]");

    if (analysisComplete)
        printf("  [Analysis: done]");
    else
        printf("  [Analysis: -]");

    printf("\n");
    printf("  ============================================================\n");
    printf("\n  Vash vybor (Your choice) [1-6]: ");
}

/*
 * Точка входа консольного приложения
 *
 * Программа остаётся открытой благодаря главному циклу меню.
 * Закрытие только по выбору пользователя (пункт 6).
 */
int main(int argc, char* argv[])
{
    char  exePath[MAX_PATH];
    char  logPath[MAX_PATH];
    BOOL  exeFound          = FALSE;
    BOOL  analysisComplete  = FALSE;
    BOOL  loggerInitialized = FALSE;
    DWORD processId         = 0;
    HANDLE hProcess         = NULL;
    int   running           = 1;

    (void)argc;
    (void)argv;

    /* Настройка консольного окна */
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
    SetConsoleTitleA("MuOffsetLogger - MU Online main.exe Offset Analyzer");

    printf("\n");
    printf("  ============================================================\n");
    printf("  MuOffsetLogger v2.0 - MU Online main.exe Offset Analyzer\n");
    printf("  Standalone EXE version\n");
    printf("  ============================================================\n");
    printf("\n");

    /* Автоматический поиск main.exe при старте */
    memset(exePath, 0, sizeof(exePath));
    memset(logPath, 0, sizeof(logPath));

    GetPathInExeDir(TARGET_EXE, exePath, MAX_PATH);
    {
        DWORD attr = GetFileAttributesA(exePath);
        if (attr != INVALID_FILE_ATTRIBUTES)
        {
            exeFound = TRUE;
            printf("  [OK] Found: %s\n", exePath);
        }
        else
        {
            printf("  [INFO] main.exe not found in current directory.\n");
            printf("  Use menu option 1 to search.\n");
        }
    }

    /* Проверяем, не запущен ли уже main.exe */
    if (exeFound)
    {
        DWORD pid = ProcessMonitor_FindProcess(TARGET_EXE);
        if (pid != 0)
        {
            printf("  [INFO] main.exe is already running (PID=%u)\n", pid);
            processId = pid;
            hProcess = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE,
                FALSE, pid);
        }
    }

    /* ================================================================
     * Главный цикл меню — окно остаётся открытым!
     * Программа не закрывается, пока пользователь не выберет пункт 6.
     * ================================================================ */
    while (running)
    {
        int choice;

        /* Проверяем, жив ли отслеживаемый процесс */
        if (processId != 0 && hProcess != NULL)
        {
            DWORD exitCode = 0;
            if (GetExitCodeProcess(hProcess, &exitCode)
                && exitCode != STILL_ACTIVE)
            {
                printf("\n  [INFO] main.exe (PID=%u) has terminated.\n",
                       processId);
                CloseHandle(hProcess);
                hProcess   = NULL;
                processId  = 0;
            }
        }

        ShowMenu(exeFound, exePath, processId, analysisComplete);

        choice = _getch();
        printf("%c\n\n", choice);

        switch (choice)
        {
        /* ==============================================================
         * 1 — Поиск main.exe
         * ============================================================== */
        case '1':
        {
            printf("  Searching for main.exe...\n");
            GetPathInExeDir(TARGET_EXE, exePath, MAX_PATH);
            {
                DWORD attr = GetFileAttributesA(exePath);
                if (attr != INVALID_FILE_ATTRIBUTES)
                {
                    exeFound = TRUE;
                    printf("  [OK] Found: %s\n", exePath);
                }
                else
                {
                    exeFound = FALSE;
                    printf("  [ERROR] Not found: %s\n", exePath);
                    printf("  Place MuOffsetLogger.exe in the same"
                           " folder as main.exe\n");
                }
            }
            /* Проверяем, не запущен ли уже */
            {
                DWORD pid = ProcessMonitor_FindProcess(TARGET_EXE);
                if (pid != 0)
                {
                    HANDLE h;
                    printf("  [INFO] main.exe is already running"
                           " (PID=%u)\n", pid);
                    if (hProcess != NULL)
                        CloseHandle(hProcess);
                    h = OpenProcess(
                        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
                        | SYNCHRONIZE, FALSE, pid);
                    if (h != NULL)
                    {
                        processId = pid;
                        hProcess  = h;
                    }
                    else
                    {
                        printf("  [WARNING] Cannot open process"
                               " handle.\n");
                        hProcess  = NULL;
                        processId = 0;
                    }
                }
                else
                {
                    printf("  [INFO] main.exe is not running.\n");
                }
            }
            break;
        }

        /* ==============================================================
         * 2 — Запуск main.exe + автоматический поиск офсетов
         * ============================================================== */
        case '2':
        {
            BYTE* fileBuffer  = NULL;
            BYTE* imageBuffer = NULL;
            DWORD fileSize    = 0;
            static PE_FILE_INFO peInfo2;
            DWORD totalOffsets;
            char  dbPath[MAX_PATH];

            if (!exeFound)
            {
                printf("  [ERROR] main.exe not found!"
                       " Use option 1 first.\n");
                break;
            }
            if (processId != 0)
            {
                printf("  [INFO] main.exe is already running"
                       " (PID=%u)\n", processId);
                break;
            }

            printf("  Launching %s...\n", TARGET_EXE);
            if (!LaunchMainExe(exePath, &processId, &hProcess))
            {
                printf("  [ERROR] Failed to launch (error: %u)\n",
                       GetLastError());
                break;
            }
            printf("  [OK] main.exe launched! (PID=%u)\n", processId);

            /* === Автоматический запуск поиска офсетов === */
            printf("\n  [AUTO] Starting automatic offset search...\n");

            /* Чтение и маппинг main.exe */
            printf("  Reading %s from disk...\n", TARGET_EXE);
            fileBuffer = ReadFileToBuffer(exePath, &fileSize);
            if (fileBuffer == NULL)
            {
                printf("  [ERROR] Cannot read file: %s\n", exePath);
                break;
            }

            printf("  File size: %u bytes (0x%08X)\n", fileSize, fileSize);
            printf("  Mapping PE sections into memory...\n");

            imageBuffer = MapPEImage(fileBuffer, fileSize);
            VirtualFree(fileBuffer, 0, MEM_RELEASE);
            fileBuffer = NULL;

            if (imageBuffer == NULL)
            {
                printf("  [ERROR] Failed to map PE image!\n");
                break;
            }

            printf("  PE image mapped successfully.\n\n");

            /* Инициализация логгера (один раз) */
            if (!loggerInitialized)
            {
                GetPathInExeDir(LOG_FILENAME, logPath, MAX_PATH);
                if (!Logger_Init(logPath))
                {
                    printf("  [ERROR] Failed to initialize logger!\n");
                    VirtualFree(imageBuffer, 0, MEM_RELEASE);
                    break;
                }
                loggerInitialized = TRUE;
            }

            /* Инициализация базы данных офсетов */
            GetPathInExeDir(OSTORE_DB_FILENAME, dbPath, MAX_PATH);
            OffsetStore_Init(dbPath);

            Logger_Write(COLOR_HEADER,
                "\n  MuOffsetLogger v2.0 - MU Online main.exe"
                " Offset Analyzer\n");
            Logger_Write(COLOR_INFO,
                "  AUTO-LAUNCH MODE: analyzing %s + continuous"
                " monitoring\n", TARGET_EXE);
            Logger_Write(COLOR_INFO,
                "  File: %s\n", exePath);
            Logger_Write(COLOR_INFO,
                "  File size: %u bytes (0x%08X)\n\n",
                fileSize, fileSize);

            /* ЭТАП 1: Анализ PE-структуры */
            Logger_WriteHeader(
                "STAGE 1: PE STRUCTURE ANALYSIS"
                " (ANALIZ PE-STRUKTURY)");

            if (!PEAnalyzer_Parse((HMODULE)imageBuffer, &peInfo2))
            {
                Logger_Write(COLOR_WARN,
                    "[ERROR] Failed to parse PE headers!\n");
                VirtualFree(imageBuffer, 0, MEM_RELEASE);
                break;
            }

            Logger_Write(COLOR_INFO,
                "  Mapped image base address: 0x%08X\n",
                (DWORD)(DWORD_PTR)imageBuffer);
            Logger_Write(COLOR_INFO,
                "  PE ImageBase: 0x%08X\n\n", peInfo2.ImageBase);

            PEAnalyzer_LogHeaders(&peInfo2);
            PEAnalyzer_LogSections(&peInfo2);
            PEAnalyzer_LogImports(&peInfo2);

            /* Записать секции и импорты в базу данных офсетов */
            {
                DWORD s;
                for (s = 0; s < peInfo2.SectionCount; s++)
                {
                    OffsetStore_Add(
                        peInfo2.ImageBase
                            + peInfo2.Sections[s].VirtualAddress,
                        "",
                        peInfo2.Sections[s].Name,
                        "SectionBase");
                }
                for (s = 0; s < peInfo2.ImportDllCount; s++)
                {
                    DWORD f;
                    for (f = 0; f < peInfo2.Imports[s].FunctionCount; f++)
                    {
                        OffsetStore_Add(
                            peInfo2.Imports[s].Functions[f].IatVA,
                            peInfo2.Imports[s].Functions[f].FunctionName,
                            peInfo2.Imports[s].DllName,
                            "ImportFunction");
                    }
                }
            }

            /* ЭТАП 2: База известных офсетов */
            Logger_WriteHeader(
                "STAGE 2: KNOWN OFFSETS DATABASE"
                " (BAZA IZVESTNYH OFSETOV)");
            OffsetDB_LogAllOffsets((DWORD_PTR)peInfo2.ImageBase);

            /* Записать все известные офсеты в базу данных */
            {
                DWORD count = 0;
                const OFFSET_ENTRY* allOffsets
                    = OffsetDB_GetAllOffsets(&count);
                DWORD k;
                for (k = 0; k < count; k++)
                {
                    OffsetStore_Add(allOffsets[k].VA,
                        (allOffsets[k].Type == OT_FUNCTION)
                            ? allOffsets[k].Name : "",
                        allOffsets[k].Category,
                        (allOffsets[k].Type != OT_FUNCTION)
                            ? allOffsets[k].Name : "");
                }
            }

            /* ЭТАП 3: Сканирование функций в .text секции */
            Logger_WriteHeader(
                "STAGE 3: FUNCTION SCANNING (.text section)");
            FuncScanner_ScanTextSection(&peInfo2, imageBuffer);
            FuncScanner_LogResults();

            /* ЭТАП 4: Сканирование строковых ссылок */
            Logger_WriteHeader(
                "STAGE 4: STRING REFERENCE SCANNING"
                " (POISK STROK)");
            FuncScanner_ScanStringRefs(&peInfo2, imageBuffer);
            FuncScanner_LogStringRefs();

            /* ЭТАП 5: Автоклассификация функций */
            Logger_WriteHeader(
                "STAGE 5: AUTO-CLASSIFICATION"
                " (AVTOKLASSIFIKATSIYA FUNKTSIJ)");
            Logger_Write(COLOR_INFO,
                "  Analyzing function bodies for import calls"
                " and string refs...\n");
            Logger_Write(COLOR_INFO,
                "  This auto-detects function purpose regardless"
                " of main.exe version.\n\n");
            FuncScanner_AutoClassify(&peInfo2, imageBuffer);
            FuncScanner_LogAutoClassified();

            /* Итоги анализа */
            totalOffsets = Logger_GetOffsetCount();

            Logger_Write(COLOR_DEFAULT, "\n");
            Logger_WriteHeader("ANALYSIS COMPLETE (ANALIZ ZAVERSHEN)");

            Logger_Write(COLOR_HEADER,
                "  Total offsets logged:         %u\n", totalOffsets);
            Logger_Write(COLOR_DEFAULT,
                "  Functions discovered:         %u\n",
                FuncScanner_GetCount());
            Logger_Write(COLOR_DEFAULT,
                "  Import DLLs:                  %u\n",
                peInfo2.ImportDllCount);
            Logger_Write(COLOR_DEFAULT,
                "  PE Sections:                  %u\n",
                peInfo2.SectionCount);
            Logger_Write(COLOR_HEADER,
                "  Database records:             %u\n",
                OffsetStore_GetCount());
            Logger_Write(COLOR_HEADER,
                "  Log file saved to:            %s\n", logPath);

            Logger_Write(COLOR_DEFAULT, "\n");

            VirtualFree(imageBuffer, 0, MEM_RELEASE);
            imageBuffer = NULL;
            analysisComplete = TRUE;

            /* Непрерывный мониторинг до закрытия main.exe */
            Logger_Write(COLOR_HEADER, "\n");
            Logger_Write(COLOR_HEADER,
                "  ======================================"
                "====================\n");
            Logger_Write(COLOR_HEADER,
                "  CONTINUOUS MONITORING - Tracking main.exe"
                " (PID=%u)\n", processId);
            Logger_Write(COLOR_HEADER,
                "  Tracking ALL game actions: server,"
                " login, character, inventory,\n");
            Logger_Write(COLOR_HEADER,
                "  chat, teleport, combat, monsters,"
                " players, keyboard, mouse\n");
            Logger_Write(COLOR_HEADER,
                "  All offsets saved to database:"
                " %s\n", OSTORE_DB_FILENAME);
            Logger_Write(COLOR_HEADER,
                "  Format: Offset | FunctionName |"
                " ModuleName | VariableName\n");
            Logger_Write(COLOR_HEADER,
                "  Press Q / ESC / 5 to stop monitoring,"
                " 6 to quit\n");
            Logger_Write(COLOR_HEADER,
                "  ======================================"
                "====================\n\n");

            if (ProcessMonitor_Init(processId, hProcess))
            {
                /* Инициализация GameMonitor для отслеживания
                 * всех игровых действий через чтение памяти */
                if (!GameMonitor_Init(hProcess, processId))
                {
                    Logger_Write(COLOR_WARN,
                        "  [WARNING] GameMonitor init"
                        " failed. Window monitoring"
                        " only.\n");
                }

                /* Непрерывный цикл мониторинга до закрытия main.exe */
                while (ProcessMonitor_IsRunning())
                {
                    if (_kbhit())
                    {
                        int key = _getch();
                        if (key == '5' || key == 'q'
                            || key == 'Q' || key == KEY_ESC)
                        {
                            Logger_Write(COLOR_INFO,
                                "\n  Monitoring stopped"
                                " by user.\n");
                            break;
                        }
                        if (key == '6')
                        {
                            Logger_Write(COLOR_INFO,
                                "\n  Exiting program...\n");
                            running = 0;
                            break;
                        }
                    }

                    if (!ProcessMonitor_Update())
                    {
                        Logger_Write(COLOR_INFO,
                            "\n  main.exe has closed."
                            " Monitoring stopped.\n");
                        break;
                    }

                    /* Обновление GameMonitor:
                     * чтение памяти, обнаружение
                     * изменений игровых данных,
                     * запись офсетов в базу данных */
                    GameMonitor_Update();

                    Sleep(100);
                }

                /* Flush database before shutdown summary */
                OffsetStore_Flush();

                GameMonitor_Shutdown();
                ProcessMonitor_Shutdown();

                Logger_Write(COLOR_HEADER,
                    "\n  [OffsetStore] Total offsets in database:"
                    " %u\n", OffsetStore_GetCount());

                OffsetStore_Shutdown();

                /* hProcess закрыт в Shutdown — обнуляем */
                hProcess  = NULL;
                processId = 0;
            }
            else
            {
                Logger_Write(COLOR_WARN,
                    "  [WARNING] Failed to initialize"
                    " process monitor.\n");
                OffsetStore_Shutdown();
            }

            break;
        }

        /* ==============================================================
         * 3 — Запуск поиска офсетов (PE-анализ + мониторинг)
         * ============================================================== */
        case '3':
        {
            BYTE* fileBuffer  = NULL;
            BYTE* imageBuffer = NULL;
            DWORD fileSize    = 0;
            static PE_FILE_INFO peInfo;
            DWORD totalOffsets;
            char  dbPath3[MAX_PATH];

            if (!exeFound)
            {
                printf("  [ERROR] main.exe not found!"
                       " Use option 1 first.\n");
                break;
            }

            /* Чтение и маппинг main.exe */
            printf("  Reading %s from disk...\n", TARGET_EXE);
            fileBuffer = ReadFileToBuffer(exePath, &fileSize);
            if (fileBuffer == NULL)
            {
                printf("  [ERROR] Cannot read file: %s\n", exePath);
                break;
            }

            printf("  File size: %u bytes (0x%08X)\n", fileSize, fileSize);
            printf("  Mapping PE sections into memory...\n");

            imageBuffer = MapPEImage(fileBuffer, fileSize);
            VirtualFree(fileBuffer, 0, MEM_RELEASE);
            fileBuffer = NULL;

            if (imageBuffer == NULL)
            {
                printf("  [ERROR] Failed to map PE image!\n");
                break;
            }

            printf("  PE image mapped successfully.\n\n");

            /* Инициализация логгера (один раз) */
            if (!loggerInitialized)
            {
                GetPathInExeDir(LOG_FILENAME, logPath, MAX_PATH);
                if (!Logger_Init(logPath))
                {
                    printf("  [ERROR] Failed to initialize logger!\n");
                    VirtualFree(imageBuffer, 0, MEM_RELEASE);
                    break;
                }
                loggerInitialized = TRUE;
            }

            /* Инициализация базы данных офсетов */
            GetPathInExeDir(OSTORE_DB_FILENAME, dbPath3, MAX_PATH);
            OffsetStore_Init(dbPath3);

            Logger_Write(COLOR_HEADER,
                "\n  MuOffsetLogger v2.0 - MU Online main.exe"
                " Offset Analyzer\n");
            Logger_Write(COLOR_INFO,
                "  Standalone EXE: analyzing %s from disk\n", TARGET_EXE);
            Logger_Write(COLOR_INFO,
                "  File: %s\n", exePath);
            Logger_Write(COLOR_INFO,
                "  File size: %u bytes (0x%08X)\n\n", fileSize, fileSize);

            /* ЭТАП 1: Анализ PE-структуры */
            Logger_WriteHeader(
                "STAGE 1: PE STRUCTURE ANALYSIS"
                " (ANALIZ PE-STRUKTURY)");

            if (!PEAnalyzer_Parse((HMODULE)imageBuffer, &peInfo))
            {
                Logger_Write(COLOR_WARN,
                    "[ERROR] Failed to parse PE headers!\n");
                VirtualFree(imageBuffer, 0, MEM_RELEASE);
                break;
            }

            Logger_Write(COLOR_INFO,
                "  Mapped image base address: 0x%08X\n",
                (DWORD)(DWORD_PTR)imageBuffer);
            Logger_Write(COLOR_INFO,
                "  PE ImageBase: 0x%08X\n\n", peInfo.ImageBase);

            PEAnalyzer_LogHeaders(&peInfo);
            PEAnalyzer_LogSections(&peInfo);
            PEAnalyzer_LogImports(&peInfo);

            /* ЭТАП 2: База известных офсетов */
            Logger_WriteHeader(
                "STAGE 2: KNOWN OFFSETS DATABASE"
                " (BAZA IZVESTNYH OFSETOV)");
            OffsetDB_LogAllOffsets((DWORD_PTR)peInfo.ImageBase);

            /* Записать все известные офсеты в базу данных */
            {
                DWORD count3 = 0;
                const OFFSET_ENTRY* allOffsets3
                    = OffsetDB_GetAllOffsets(&count3);
                DWORD k3;
                for (k3 = 0; k3 < count3; k3++)
                {
                    OffsetStore_Add(allOffsets3[k3].VA,
                        (allOffsets3[k3].Type == OT_FUNCTION)
                            ? allOffsets3[k3].Name : "",
                        allOffsets3[k3].Category,
                        (allOffsets3[k3].Type != OT_FUNCTION)
                            ? allOffsets3[k3].Name : "");
                }
            }

            /* ЭТАП 3: Сканирование функций в .text секции */
            Logger_WriteHeader(
                "STAGE 3: FUNCTION SCANNING (.text section)");
            FuncScanner_ScanTextSection(&peInfo, imageBuffer);
            FuncScanner_LogResults();

            /* ЭТАП 4: Сканирование строковых ссылок */
            Logger_WriteHeader(
                "STAGE 4: STRING REFERENCE SCANNING (POISK STROK)");
            FuncScanner_ScanStringRefs(&peInfo, imageBuffer);
            FuncScanner_LogStringRefs();

            /* ЭТАП 5: Автоклассификация функций */
            Logger_WriteHeader(
                "STAGE 5: AUTO-CLASSIFICATION"
                " (AVTOKLASSIFIKATSIYA FUNKTSIJ)");
            Logger_Write(COLOR_INFO,
                "  Analyzing function bodies for import calls"
                " and string refs...\n");
            Logger_Write(COLOR_INFO,
                "  This auto-detects function purpose regardless"
                " of main.exe version.\n\n");
            FuncScanner_AutoClassify(&peInfo, imageBuffer);
            FuncScanner_LogAutoClassified();

            /* Итоги анализа */
            totalOffsets = Logger_GetOffsetCount();

            Logger_Write(COLOR_DEFAULT, "\n");
            Logger_WriteHeader("ANALYSIS COMPLETE (ANALIZ ZAVERSHEN)");

            Logger_Write(COLOR_HEADER,
                "  Total offsets logged:         %u\n", totalOffsets);
            Logger_Write(COLOR_DEFAULT,
                "  Functions discovered:         %u\n",
                FuncScanner_GetCount());
            Logger_Write(COLOR_DEFAULT,
                "  Import DLLs:                  %u\n",
                peInfo.ImportDllCount);
            Logger_Write(COLOR_DEFAULT,
                "  PE Sections:                  %u\n",
                peInfo.SectionCount);
            Logger_Write(COLOR_HEADER,
                "  Database records:             %u\n",
                OffsetStore_GetCount());
            Logger_Write(COLOR_HEADER,
                "  Log file saved to:            %s\n", logPath);

            Logger_Write(COLOR_DEFAULT, "\n");

            VirtualFree(imageBuffer, 0, MEM_RELEASE);
            imageBuffer = NULL;
            analysisComplete = TRUE;

            /* Если main.exe запущен — войти в режим мониторинга */
            if (processId != 0 && hProcess != NULL)
            {
                Logger_Write(COLOR_HEADER, "\n");
                Logger_Write(COLOR_HEADER,
                    "  ======================================"
                    "====================\n");
                Logger_Write(COLOR_HEADER,
                    "  MONITORING MODE - Tracking main.exe"
                    " (PID=%u)\n", processId);
                Logger_Write(COLOR_HEADER,
                    "  Tracking ALL game actions: server,"
                    " login, character, inventory,\n");
                Logger_Write(COLOR_HEADER,
                    "  chat, teleport, combat, monsters,"
                    " players, keyboard, mouse\n");
                Logger_Write(COLOR_HEADER,
                    "  All offsets saved to database:"
                    " %s\n", OSTORE_DB_FILENAME);
                Logger_Write(COLOR_HEADER,
                    "  Press Q / ESC / 5 to stop monitoring,"
                    " 6 to quit\n");
                Logger_Write(COLOR_HEADER,
                    "  ======================================"
                    "====================\n\n");

                if (ProcessMonitor_Init(processId, hProcess))
                {
                    /* Инициализация GameMonitor для отслеживания
                     * всех игровых действий через чтение памяти */
                    if (!GameMonitor_Init(hProcess, processId))
                    {
                        Logger_Write(COLOR_WARN,
                            "  [WARNING] GameMonitor init"
                            " failed. Window monitoring"
                            " only.\n");
                    }

                    while (ProcessMonitor_IsRunning())
                    {
                        if (_kbhit())
                        {
                            int key = _getch();
                            if (key == '5' || key == 'q'
                                || key == 'Q' || key == KEY_ESC)
                            {
                                Logger_Write(COLOR_INFO,
                                    "\n  Monitoring stopped"
                                    " by user.\n");
                                break;
                            }
                            if (key == '6')
                            {
                                Logger_Write(COLOR_INFO,
                                    "\n  Exiting program...\n");
                                running = 0;
                                break;
                            }
                        }

                        if (!ProcessMonitor_Update())
                        {
                            Logger_Write(COLOR_INFO,
                                "\n  main.exe has closed."
                                " Monitoring stopped.\n");
                            break;
                        }

                        /* Обновление GameMonitor:
                         * чтение памяти, обнаружение
                         * изменений игровых данных */
                        GameMonitor_Update();

                        Sleep(100);
                    }

                    OffsetStore_Flush();
                    GameMonitor_Shutdown();
                    ProcessMonitor_Shutdown();

                    Logger_Write(COLOR_HEADER,
                        "\n  [OffsetStore] Total offsets in database:"
                        " %u\n", OffsetStore_GetCount());

                    OffsetStore_Shutdown();

                    /* hProcess закрыт в Shutdown — обнуляем */
                    hProcess  = NULL;
                    processId = 0;
                }
                else
                {
                    Logger_Write(COLOR_WARN,
                        "  [WARNING] Failed to initialize"
                        " process monitor.\n");
                    OffsetStore_Shutdown();
                }
            }
            else
            {
                Logger_Write(COLOR_INFO,
                    "  File analysis mode."
                    " No process monitoring.\n");
                OffsetStore_Shutdown();
            }

            break;
        }

        /* ==============================================================
         * 4 — Пауза программы
         * ============================================================== */
        case '4':
        {
            printf("  Program paused. Press any key to continue...\n");
            printf("  (Programma priostanovlena."
                   " Nazhmi lyubuyu klavishu...)\n");
            _getch();
            printf("  Resumed.\n");
            break;
        }

        /* ==============================================================
         * 5 — Остановить отладку (дебаг)
         * ============================================================== */
        case '5':
        {
            if (processId != 0 || hProcess != NULL)
            {
                printf("  Stopping debug session...\n");
                if (hProcess != NULL)
                {
                    CloseHandle(hProcess);
                    hProcess = NULL;
                }
                processId = 0;
                printf("  [OK] Debug session stopped.\n");
            }
            else
            {
                printf("  [INFO] No active debug session.\n");
            }
            break;
        }

        /* ==============================================================
         * 6 — Закрыть программу
         * ============================================================== */
        case '6':
        {
            running = 0;
            break;
        }

        default:
            printf("  Invalid choice. Please select 1-6.\n");
            break;
        }
    }

    /* ================================================================
     * Финальное завершение и очистка ресурсов
     * ================================================================ */
    if (loggerInitialized)
    {
        Logger_Write(COLOR_INFO, "  Program closing...\n");
        Logger_Shutdown();
    }

    if (hProcess != NULL)
    {
        CloseHandle(hProcess);
        hProcess = NULL;
    }

    printf("\n  MuOffsetLogger closed. (Programma zavershena.)\n");
    return 0;
}
