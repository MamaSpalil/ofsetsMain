/*
 * main.cpp
 * MuOffsetLogger - Система логирования офсетов main.exe MU Online
 *
 * Консольное приложение (EXE). Логика работы:
 * 1. Помещаем MuOffsetLogger.exe в папку с игровым клиентом
 * 2. Запускаем MuOffsetLogger.exe — открывается консольное окно
 * 3. Предлагается запустить main.exe — соглашаемся
 * 4. Запускается main.exe из той же папки
 * 5. Консоль анализирует все внутриигровые офсеты
 * 6. Логи отображаются в консоли и сохраняются в MuOffsetLog.txt
 *
 * Совместимость: Visual Studio 2010 (v100), Windows 10 x86/x64
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "Logger.h"
#include "PEAnalyzer.h"
#include "OffsetDatabase.h"
#include "FunctionScanner.h"

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
 */
static BOOL LaunchMainExe(const char* exePath)
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

    /* Закрываем хэндлы процесса — не ждём завершения */
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
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

    /* Проверяем наличие main.exe */
    {
        DWORD attr = GetFileAttributesA(exePath);
        if (attr == INVALID_FILE_ATTRIBUTES)
        {
            printf("  [ERROR] File not found: %s\n", exePath);
            printf("  Place MuOffsetLogger.exe in the same folder as main.exe\n");
            printf("\n  Press Enter to exit...");
            getchar();
            return 1;
        }
    }

    printf("  Found: %s\n", exePath);
    printf("\n");
    printf("  Launch main.exe and start offset analysis? (Zapustit' main.exe?)\n");
    printf("  1 - Yes (Da)\n");
    printf("  0 - No, only analyze file (Net, tol'ko analiz fajla)\n");
    printf("\n  Your choice (Vash vybor): ");

    userChoice = getchar();
    /* Очистка буфера ввода */
    while (getchar() != '\n');

    /* ================================================================
     * Чтение и маппинг main.exe
     * ================================================================ */
    printf("\n  Reading %s from disk...\n", TARGET_EXE);

    fileBuffer = ReadFileToBuffer(exePath, &fileSize);
    if (fileBuffer == NULL)
    {
        printf("  [ERROR] Cannot read file: %s\n", exePath);
        printf("\n  Press Enter to exit...");
        getchar();
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
        printf("\n  Press Enter to exit...");
        getchar();
        return 1;
    }

    printf("  PE image mapped successfully.\n\n");

    /* ================================================================
     * Запуск main.exe (если пользователь выбрал)
     * ================================================================ */
    if (userChoice == '1')
    {
        printf("  Launching %s...\n", TARGET_EXE);

        if (LaunchMainExe(exePath))
        {
            printf("  main.exe launched successfully!\n\n");
        }
        else
        {
            DWORD err = GetLastError();
            printf("  [WARNING] Failed to launch main.exe (error: %u)\n", err);
            printf("  Continuing with file analysis...\n\n");
        }
    }
    else
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
        printf("\n  Press Enter to exit...");
        getchar();
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
        printf("\n  Press Enter to exit...");
        getchar();
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

    if (userChoice == '1')
    {
        Logger_Write(COLOR_INFO,
            "  main.exe is running. Offset analysis is complete.\n");
    }

    Logger_Write(COLOR_INFO,
        "  Press Enter to close logger... (Nazhmi Enter dlya zakrytiya)\n");

    Logger_Shutdown();

    /* Освобождение памяти */
    VirtualFree(imageBuffer, 0, MEM_RELEASE);

    /* Ожидание нажатия Enter */
    getchar();

    return 0;
}
