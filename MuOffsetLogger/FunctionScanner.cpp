/*
 * FunctionScanner.cpp
 * MuOffsetLogger - Система логирования офсетов main.exe MU Online
 *
 * Реализация сканера функций: поиск по прологам, CALL-целям, строковым ссылкам
 * Совместимость: Visual Studio 2010 (v100), Windows 10 x86/x64
 */

#include "FunctionScanner.h"
#include "Logger.h"
#include <string.h>

/* Буфер обнаруженных функций */
static DISCOVERED_FUNCTION g_Functions[MAX_DISCOVERED_FUNCTIONS];
static DWORD g_FunctionCount = 0;

/* Статистика сканирования */
static DWORD g_PrologueCount   = 0;
static DWORD g_CallTargetCount = 0;
static DWORD g_HiddenCount     = 0;
static DWORD g_StringRefCount  = 0;

/* Буфер для строковых ссылок */
#define MAX_STRING_REFS 2048

typedef struct _STRING_REF
{
    DWORD VA;
    DWORD FileOffset;
    char  Value[256];
} STRING_REF;

static STRING_REF g_StringRefs[MAX_STRING_REFS];
static DWORD g_StringRefListCount = 0;

/* Буфер для автоклассифицированных функций */
#define MAX_AUTO_CLASSIFIED 4096

typedef struct _AUTO_CLASSIFIED_FUNC
{
    DWORD VA;
    DWORD FileOffset;
    char  AutoName[128];
    char  AutoDescription[256];
    char  Category[64];
} AUTO_CLASSIFIED_FUNC;

static AUTO_CLASSIFIED_FUNC g_AutoClassified[MAX_AUTO_CLASSIFIED];
static DWORD g_AutoClassifiedCount = 0;

/*
 * Безопасное чтение памяти
 */
static BOOL SafeRead(LPCVOID address, LPVOID buffer, SIZE_T size)
{
    __try
    {
        memcpy(buffer, address, size);
        return TRUE;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
}

/*
 * Проверяет, является ли адрес началом функции (пролог push ebp; mov ebp, esp)
 * Паттерн: 55 8B EC  (push ebp; mov ebp, esp)
 */
static BOOL IsFunctionPrologue(BYTE* addr)
{
    BYTE bytes[3];

    if (!SafeRead(addr, bytes, 3))
        return FALSE;

    /* push ebp (0x55); mov ebp, esp (0x8B 0xEC) */
    return (bytes[0] == 0x55 && bytes[1] == 0x8B && bytes[2] == 0xEC);
}

/*
 * Проверяет, является ли байт NOP (0x90) или INT3 (0xCC)
 */
static BOOL IsNopOrInt3(BYTE b)
{
    return (b == 0x90 || b == 0xCC);
}

/*
 * Проверяет, что строка содержит печатные ASCII символы
 */
static BOOL IsPrintableString(const char* str, DWORD minLen)
{
    DWORD i;

    for (i = 0; str[i] != '\0'; i++)
    {
        if ((unsigned char)str[i] < 0x20 || (unsigned char)str[i] > 0x7E)
            return FALSE;
    }

    return (i >= minLen);
}

/*
 * Добавление функции в буфер (с проверкой дубликатов)
 */
static void AddFunction(DWORD va, DWORD fileOffset,
                        BOOL hasPrologue, BOOL isCallTarget, BOOL isHidden)
{
    DWORD i;

    if (g_FunctionCount >= MAX_DISCOVERED_FUNCTIONS)
        return;

    /* Проверка дубликатов */
    for (i = 0; i < g_FunctionCount; i++)
    {
        if (g_Functions[i].VA == va)
        {
            /* Обновляем флаги */
            if (hasPrologue)  g_Functions[i].HasPrologue  = TRUE;
            if (isCallTarget) g_Functions[i].IsCallTarget = TRUE;
            if (isHidden)     g_Functions[i].IsHidden     = TRUE;
            return;
        }
    }

    g_Functions[g_FunctionCount].VA           = va;
    g_Functions[g_FunctionCount].FileOffset   = fileOffset;
    g_Functions[g_FunctionCount].HasPrologue  = hasPrologue;
    g_Functions[g_FunctionCount].IsCallTarget = isCallTarget;
    g_Functions[g_FunctionCount].IsHidden     = isHidden;
    g_Functions[g_FunctionCount].StringRefVA  = 0;
    g_FunctionCount++;
}

DWORD FuncScanner_ScanTextSection(const PE_FILE_INFO* pInfo,
                                  BYTE* baseAddress)
{
    DWORD textVA    = 0;
    DWORD textSize  = 0;
    DWORD textRaw   = 0;
    BYTE* textStart;
    DWORD i, si;
    BOOL  foundText = FALSE;

    if (pInfo == NULL || baseAddress == NULL)
        return 0;

    g_FunctionCount    = 0;
    g_PrologueCount    = 0;
    g_CallTargetCount  = 0;
    g_HiddenCount      = 0;

    /* Находим .text секцию */
    for (si = 0; si < pInfo->SectionCount; si++)
    {
        if (strcmp(pInfo->Sections[si].Name, ".text") == 0)
        {
            textVA   = pInfo->Sections[si].VirtualAddress;
            textSize = pInfo->Sections[si].VirtualSize;
            textRaw  = pInfo->Sections[si].RawOffset;
            foundText = TRUE;
            break;
        }
    }

    if (!foundText)
    {
        Logger_Write(COLOR_WARN,
            "[WARNING] .text section not found!\n");
        return 0;
    }

    textStart = baseAddress + (textVA - pInfo->ImageBase);

    Logger_Write(COLOR_INFO,
        "  Scanning .text section: VA=0x%08X, Size=0x%08X\n",
        textVA, textSize);

    /* Проход 1: Поиск функций по прологу (push ebp; mov ebp, esp) */
    Logger_Write(COLOR_INFO,
        "  Pass 1: Scanning for function prologues (55 8B EC)...\n");

    for (i = 0; i < textSize - 3; i++)
    {
        if (IsFunctionPrologue(textStart + i))
        {
            DWORD funcVA     = textVA + i;
            DWORD funcFile   = textRaw + i;
            BOOL  isHidden   = FALSE;

            /* Проверяем, есть ли NOP/INT3 перед прологом (скрытая функция) */
            if (i > 0)
            {
                BYTE prevByte;
                if (SafeRead(textStart + i - 1, &prevByte, 1))
                {
                    if (IsNopOrInt3(prevByte))
                        isHidden = TRUE;
                }
            }

            AddFunction(funcVA, funcFile, TRUE, FALSE, isHidden);
            g_PrologueCount++;

            if (isHidden)
                g_HiddenCount++;
        }
    }

    Logger_Write(COLOR_INFO,
        "    Found %u function prologues (%u hidden after NOP/INT3)\n",
        g_PrologueCount, g_HiddenCount);

    /* Проход 2: Поиск CALL-целей (E8 xx xx xx xx) */
    Logger_Write(COLOR_INFO,
        "  Pass 2: Scanning for CALL targets (E8 relative calls)...\n");

    for (i = 0; i < textSize - 5; i++)
    {
        BYTE opcode;

        if (!SafeRead(textStart + i, &opcode, 1))
            continue;

        if (opcode == 0xE8) /* CALL rel32 */
        {
            DWORD offset;
            DWORD targetVA;

            if (!SafeRead(textStart + i + 1, &offset, 4))
                continue;

            targetVA = textVA + i + 5 + offset;

            /* Проверяем, что цель находится в .text секции */
            if (targetVA >= textVA && targetVA < textVA + textSize)
            {
                DWORD targetFile = textRaw + (targetVA - textVA);

                AddFunction(targetVA, targetFile, FALSE, TRUE, FALSE);
                g_CallTargetCount++;
            }
        }
    }

    Logger_Write(COLOR_INFO,
        "    Found %u CALL targets within .text section\n",
        g_CallTargetCount);

    Logger_Write(COLOR_OFFSET,
        "  Total unique functions discovered: %u\n",
        g_FunctionCount);

    return g_FunctionCount;
}

void FuncScanner_LogResults(void)
{
    DWORD i;
    DWORD confirmed = 0;

    Logger_WriteHeader("DISCOVERED FUNCTIONS (OBNARUZHENNYE FUNKTSII)");

    /* Подсчет подтвержденных функций (и пролог, и CALL) */
    for (i = 0; i < g_FunctionCount; i++)
    {
        if (g_Functions[i].HasPrologue && g_Functions[i].IsCallTarget)
            confirmed++;
    }

    Logger_Write(COLOR_INFO,
        "  Statistics:\n");
    Logger_Write(COLOR_DEFAULT,
        "    Total unique functions:    %u\n", g_FunctionCount);
    Logger_Write(COLOR_DEFAULT,
        "    With prologue (55 8B EC):  %u\n", g_PrologueCount);
    Logger_Write(COLOR_DEFAULT,
        "    CALL targets:              %u\n", g_CallTargetCount);
    Logger_Write(COLOR_DEFAULT,
        "    Confirmed (both):          %u\n", confirmed);
    Logger_Write(COLOR_DEFAULT,
        "    Hidden (after NOP/INT3):   %u\n", g_HiddenCount);

    /* Логирование первых 500 подтвержденных функций (краткий список) */
    Logger_Write(COLOR_DEFAULT, "\n");
    Logger_Write(COLOR_SECTION,
        "  --- Confirmed functions (prologue + CALL target, first 500) ---\n");

    {
        DWORD logged = 0;
        for (i = 0; i < g_FunctionCount && logged < 500; i++)
        {
            if (g_Functions[i].HasPrologue && g_Functions[i].IsCallTarget)
            {
                char name[64];
                sprintf(name, "sub_%08X", g_Functions[i].VA);

                Logger_WriteFunction(g_Functions[i].VA,
                                     g_Functions[i].FileOffset,
                                     name,
                                     g_Functions[i].IsHidden ?
                                        "Hidden function (after NOP/INT3)" :
                                        "Confirmed function (prologue + CALL target)");
                logged++;
            }
        }
    }

    /* Логирование первых 200 скрытых функций */
    Logger_Write(COLOR_DEFAULT, "\n");
    Logger_Write(COLOR_SECTION,
        "  --- Hidden functions (not directly called, first 200) ---\n");

    {
        DWORD logged = 0;
        for (i = 0; i < g_FunctionCount && logged < 200; i++)
        {
            if (g_Functions[i].IsHidden && !g_Functions[i].IsCallTarget)
            {
                char name[64];
                sprintf(name, "hidden_%08X", g_Functions[i].VA);

                Logger_WriteFunction(g_Functions[i].VA,
                                     g_Functions[i].FileOffset,
                                     name,
                                     "Hidden function (accessed via vtable/pointer)");
                logged++;
            }
        }
    }
}

void FuncScanner_ScanStringRefs(const PE_FILE_INFO* pInfo,
                                BYTE* baseAddress)
{
    DWORD dataVA    = 0;
    DWORD dataSize  = 0;
    DWORD dataRaw   = 0;
    BYTE* dataStart;
    DWORD si, i;
    BOOL  foundData = FALSE;

    if (pInfo == NULL || baseAddress == NULL)
        return;

    g_StringRefListCount = 0;

    /* Находим секцию с данными (без имени или .data) */
    for (si = 0; si < pInfo->SectionCount; si++)
    {
        if (strcmp(pInfo->Sections[si].Name, ".data") == 0 ||
            pInfo->Sections[si].Name[0] == '\0')
        {
            dataVA   = pInfo->Sections[si].VirtualAddress;
            dataSize = pInfo->Sections[si].VirtualSize;
            dataRaw  = pInfo->Sections[si].RawOffset;
            foundData = TRUE;

            if (dataSize > 0x100000) /* Ограничение сканирования 1 МБ */
                dataSize = 0x100000;

            break;
        }
    }

    if (!foundData)
        return;

    dataStart = baseAddress + (dataVA - pInfo->ImageBase);

    Logger_Write(COLOR_INFO,
        "  Scanning data section for strings: VA=0x%08X, Size=0x%08X\n",
        dataVA, dataSize);

    /* Поиск строк ASCII длиной >= 4 символов */
    for (i = 0; i < dataSize - 4 && g_StringRefListCount < MAX_STRING_REFS; i++)
    {
        char testStr[256];
        DWORD maxRead = (dataSize - i < 255) ? (dataSize - i) : 255;

        if (!SafeRead(dataStart + i, testStr, maxRead))
            continue;

        testStr[maxRead] = '\0';

        if (IsPrintableString(testStr, 4))
        {
            DWORD strLen = (DWORD)strlen(testStr);

            g_StringRefs[g_StringRefListCount].VA = dataVA + i;
            g_StringRefs[g_StringRefListCount].FileOffset = dataRaw + i;

            /* Копируем строку (ограниченная длина) */
            if (strLen > 255) strLen = 255;
            memcpy(g_StringRefs[g_StringRefListCount].Value, testStr, strLen);
            g_StringRefs[g_StringRefListCount].Value[strLen] = '\0';

            g_StringRefListCount++;

            /* Пропускаем эту строку */
            i += strLen;
        }
    }

    Logger_Write(COLOR_INFO,
        "    Found %u printable strings in data section\n",
        g_StringRefListCount);
}

void FuncScanner_LogStringRefs(void)
{
    DWORD i;

    Logger_WriteHeader("STRING REFERENCES IN DATA SECTION (STROKOVYE SSYLKI)");

    Logger_Write(COLOR_INFO,
        "  Total strings found: %u\n\n", g_StringRefListCount);

    for (i = 0; i < g_StringRefListCount; i++)
    {
        Logger_WriteOffset(g_StringRefs[i].VA,
                           g_StringRefs[i].FileOffset,
                           "STR",
                           g_StringRefs[i].Value,
                           "Data string reference");
    }
}

DWORD FuncScanner_GetCount(void)
{
    return g_FunctionCount;
}

/*
 * Определение категории функции по имени вызываемого импорта
 */
static const char* ClassifyByImport(const char* importName)
{
    /* Network/Socket */
    if (_stricmp(importName, "send") == 0 ||
        _stricmp(importName, "recv") == 0 ||
        _stricmp(importName, "connect") == 0 ||
        _stricmp(importName, "socket") == 0 ||
        _stricmp(importName, "closesocket") == 0 ||
        _stricmp(importName, "WSAStartup") == 0 ||
        _stricmp(importName, "gethostbyname") == 0 ||
        _stricmp(importName, "sendto") == 0 ||
        _stricmp(importName, "recvfrom") == 0 ||
        _stricmp(importName, "select") == 0 ||
        _stricmp(importName, "bind") == 0)
        return "Network";

    /* Registry */
    if (_stricmp(importName, "RegOpenKeyExA") == 0 ||
        _stricmp(importName, "RegCreateKeyExA") == 0 ||
        _stricmp(importName, "RegQueryValueExA") == 0 ||
        _stricmp(importName, "RegSetValueExA") == 0 ||
        _stricmp(importName, "RegCloseKey") == 0 ||
        _stricmp(importName, "RegDeleteKeyA") == 0)
        return "Config/Registry";

    /* File I/O */
    if (_stricmp(importName, "CreateFileA") == 0 ||
        _stricmp(importName, "CreateFileW") == 0 ||
        _stricmp(importName, "ReadFile") == 0 ||
        _stricmp(importName, "WriteFile") == 0 ||
        _stricmp(importName, "CloseHandle") == 0 ||
        _stricmp(importName, "FindFirstFileA") == 0 ||
        _stricmp(importName, "FindNextFileA") == 0 ||
        _stricmp(importName, "GetFileSize") == 0)
        return "File/IO";

    /* Graphics/Rendering */
    if (_stricmp(importName, "GetDC") == 0 ||
        _stricmp(importName, "ReleaseDC") == 0 ||
        _stricmp(importName, "BitBlt") == 0 ||
        _stricmp(importName, "CreateCompatibleDC") == 0 ||
        _stricmp(importName, "SelectObject") == 0 ||
        _stricmp(importName, "SetPixel") == 0 ||
        _stricmp(importName, "GetPixel") == 0 ||
        _stricmp(importName, "StretchBlt") == 0)
        return "Rendering/GDI";

    /* Crypto */
    if (_stricmp(importName, "CryptAcquireContextA") == 0 ||
        _stricmp(importName, "CryptReleaseContext") == 0 ||
        _stricmp(importName, "CryptGenRandom") == 0 ||
        _stricmp(importName, "CryptCreateHash") == 0 ||
        _stricmp(importName, "CryptHashData") == 0 ||
        _stricmp(importName, "CryptEncrypt") == 0 ||
        _stricmp(importName, "CryptDecrypt") == 0)
        return "Crypto";

    /* Sound */
    if (_stricmp(importName, "DirectSoundCreate") == 0 ||
        _stricmp(importName, "waveOutOpen") == 0 ||
        _stricmp(importName, "mciSendCommandA") == 0 ||
        _stricmp(importName, "PlaySoundA") == 0)
        return "Sound";

    /* Input */
    if (_stricmp(importName, "DirectInputCreateA") == 0 ||
        _stricmp(importName, "DirectInput8Create") == 0 ||
        _stricmp(importName, "GetAsyncKeyState") == 0 ||
        _stricmp(importName, "GetKeyState") == 0)
        return "Input";

    /* Window/UI */
    if (_stricmp(importName, "CreateWindowExA") == 0 ||
        _stricmp(importName, "ShowWindow") == 0 ||
        _stricmp(importName, "UpdateWindow") == 0 ||
        _stricmp(importName, "MessageBoxA") == 0 ||
        _stricmp(importName, "SetWindowTextA") == 0 ||
        _stricmp(importName, "SendMessageA") == 0 ||
        _stricmp(importName, "PostMessageA") == 0 ||
        _stricmp(importName, "DestroyWindow") == 0 ||
        _stricmp(importName, "DialogBoxParamA") == 0)
        return "Window/UI";

    /* Memory */
    if (_stricmp(importName, "VirtualAlloc") == 0 ||
        _stricmp(importName, "VirtualFree") == 0 ||
        _stricmp(importName, "HeapAlloc") == 0 ||
        _stricmp(importName, "HeapFree") == 0 ||
        _stricmp(importName, "GlobalAlloc") == 0)
        return "Memory";

    /* Process/Thread */
    if (_stricmp(importName, "CreateThread") == 0 ||
        _stricmp(importName, "CreateProcessA") == 0 ||
        _stricmp(importName, "ExitProcess") == 0 ||
        _stricmp(importName, "TerminateProcess") == 0 ||
        _stricmp(importName, "GetCurrentProcessId") == 0)
        return "Process/Thread";

    return NULL;
}

/*
 * Поиск IAT-записи по VA адресу
 */
static const char* FindImportByIAT(const PE_FILE_INFO* pInfo, DWORD iatVA,
                                   char* dllNameOut, DWORD dllNameSize)
{
    DWORD d, f;

    for (d = 0; d < pInfo->ImportDllCount; d++)
    {
        for (f = 0; f < pInfo->Imports[d].FunctionCount; f++)
        {
            if (pInfo->Imports[d].Functions[f].IatVA == iatVA)
            {
                if (dllNameOut != NULL)
                    _snprintf(dllNameOut, dllNameSize - 1, "%s",
                              pInfo->Imports[d].DllName);
                return pInfo->Imports[d].Functions[f].FunctionName;
            }
        }
    }

    return NULL;
}

void FuncScanner_AutoClassify(const PE_FILE_INFO* pInfo,
                              BYTE* baseAddress)
{
    DWORD textVA   = 0;
    DWORD textSize = 0;
    DWORD textRaw  = 0;
    DWORD dataVA   = 0;
    DWORD dataSize = 0;
    BYTE* textBase;
    DWORD si, fi;
    BOOL  foundText = FALSE;

    if (pInfo == NULL || baseAddress == NULL)
        return;

    g_AutoClassifiedCount = 0;

    /* Найти .text секцию */
    for (si = 0; si < pInfo->SectionCount; si++)
    {
        if (strcmp(pInfo->Sections[si].Name, ".text") == 0)
        {
            textVA   = pInfo->Sections[si].VirtualAddress;
            textSize = pInfo->Sections[si].VirtualSize;
            textRaw  = pInfo->Sections[si].RawOffset;
            foundText = TRUE;
        }
        if (strcmp(pInfo->Sections[si].Name, ".data") == 0 ||
            pInfo->Sections[si].Name[0] == '\0')
        {
            dataVA   = pInfo->Sections[si].VirtualAddress;
            dataSize = pInfo->Sections[si].VirtualSize;
        }
    }

    if (!foundText)
        return;

    textBase = baseAddress + (textVA - pInfo->ImageBase);

    Logger_Write(COLOR_INFO,
        "  Auto-classifying %u discovered functions...\n", g_FunctionCount);

    /* Для каждой обнаруженной функции */
    for (fi = 0; fi < g_FunctionCount && g_AutoClassifiedCount < MAX_AUTO_CLASSIFIED; fi++)
    {
        DWORD funcVA    = g_Functions[fi].VA;
        DWORD funcFile  = g_Functions[fi].FileOffset;
        DWORD funcStart = funcVA - textVA;
        DWORD scanLen;
        DWORD i;
        char  importsCalled[512];
        char  stringFound[256];
        const char* bestCategory = NULL;
        DWORD importCount = 0;

        /* Только подтверждённые функции (и пролог, и CALL target) */
        if (!g_Functions[fi].HasPrologue || !g_Functions[fi].IsCallTarget)
            continue;

        /* Проверяем границы */
        if (funcStart >= textSize)
            continue;

        /* Сканируем первые 512 байт функции */
        scanLen = textSize - funcStart;
        if (scanLen > 512)
            scanLen = 512;

        importsCalled[0] = '\0';
        stringFound[0]   = '\0';

        for (i = 0; i < scanLen - 6; i++)
        {
            BYTE* ptr = textBase + funcStart + i;
            BYTE  opcode;

            if (!SafeRead(ptr, &opcode, 1))
                continue;

            /* CALL DWORD PTR [imm32]: FF 15 xx xx xx xx */
            if (opcode == 0xFF && i + 5 < scanLen)
            {
                BYTE modRM;
                if (SafeRead(ptr + 1, &modRM, 1) && modRM == 0x15)
                {
                    DWORD targetAddr;
                    if (SafeRead(ptr + 2, &targetAddr, 4))
                    {
                        char dllName[128];
                        const char* impName;
                        const char* cat;

                        dllName[0] = '\0';
                        impName = FindImportByIAT(pInfo, targetAddr,
                                                  dllName, sizeof(dllName));

                        if (impName != NULL)
                        {
                            if (importCount > 0 &&
                                strlen(importsCalled) + strlen(impName) + 2 < sizeof(importsCalled))
                            {
                                strcat(importsCalled, ", ");
                            }
                            if (strlen(importsCalled) + strlen(impName) < sizeof(importsCalled) - 1)
                            {
                                strcat(importsCalled, impName);
                            }

                            cat = ClassifyByImport(impName);
                            if (cat != NULL && bestCategory == NULL)
                                bestCategory = cat;

                            importCount++;
                        }
                    }
                    i += 5; /* Skip past this instruction */
                }
            }

            /* PUSH imm32: 68 xx xx xx xx — возможная строковая ссылка */
            if (opcode == 0x68 && i + 4 < scanLen && stringFound[0] == '\0')
            {
                DWORD pushAddr;
                if (SafeRead(ptr + 1, &pushAddr, 4))
                {
                    /* Проверяем, что адрес указывает на секцию данных */
                    if (dataVA != 0 && pushAddr >= dataVA &&
                        pushAddr < dataVA + dataSize)
                    {
                        BYTE* strAddr = baseAddress + (pushAddr - pInfo->ImageBase);
                        char  testStr[128];

                        if (SafeRead(strAddr, testStr, sizeof(testStr) - 1))
                        {
                            testStr[sizeof(testStr) - 1] = '\0';
                            if (IsPrintableString(testStr, 4))
                            {
                                _snprintf(stringFound, sizeof(stringFound) - 1,
                                    "%s", testStr);
                                stringFound[sizeof(stringFound) - 1] = '\0';
                                /* Truncate long strings for display */
                                if (strlen(stringFound) > 60)
                                {
                                    stringFound[57] = '.';
                                    stringFound[58] = '.';
                                    stringFound[59] = '.';
                                    stringFound[60] = '\0';
                                }
                            }
                        }
                    }
                }
            }

            /* RET instruction — конец функции */
            if (opcode == 0xC3 || opcode == 0xC2)
                break;
        }

        /* Если нашли хотя бы импорт или строку — записываем */
        if (importCount > 0 || stringFound[0] != '\0')
        {
            AUTO_CLASSIFIED_FUNC* ac = &g_AutoClassified[g_AutoClassifiedCount];

            ac->VA         = funcVA;
            ac->FileOffset = funcFile;

            /* Автоимя */
            if (bestCategory != NULL)
            {
                _snprintf(ac->AutoName, sizeof(ac->AutoName) - 1,
                    "auto_%s_%08X", bestCategory, funcVA);
            }
            else
            {
                _snprintf(ac->AutoName, sizeof(ac->AutoName) - 1,
                    "auto_sub_%08X", funcVA);
            }
            ac->AutoName[sizeof(ac->AutoName) - 1] = '\0';

            /* Категория */
            if (bestCategory != NULL)
                _snprintf(ac->Category, sizeof(ac->Category) - 1, "%s", bestCategory);
            else
                _snprintf(ac->Category, sizeof(ac->Category) - 1, "General");
            ac->Category[sizeof(ac->Category) - 1] = '\0';

            /* Автоописание */
            ac->AutoDescription[0] = '\0';
            if (importCount > 0)
            {
                _snprintf(ac->AutoDescription, sizeof(ac->AutoDescription) - 1,
                    "Calls: %s", importsCalled);
            }
            if (stringFound[0] != '\0')
            {
                if (ac->AutoDescription[0] != '\0')
                {
                    DWORD len = (DWORD)strlen(ac->AutoDescription);
                    _snprintf(ac->AutoDescription + len,
                        sizeof(ac->AutoDescription) - 1 - len,
                        " | Ref: \"%s\"", stringFound);
                }
                else
                {
                    _snprintf(ac->AutoDescription, sizeof(ac->AutoDescription) - 1,
                        "Ref: \"%s\"", stringFound);
                }
            }
            ac->AutoDescription[sizeof(ac->AutoDescription) - 1] = '\0';

            g_AutoClassifiedCount++;
        }
    }

    Logger_Write(COLOR_OFFSET,
        "  Auto-classified %u functions with imports/strings\n",
        g_AutoClassifiedCount);
}

void FuncScanner_LogAutoClassified(void)
{
    DWORD i;
    const char* lastCategory = "";

    Logger_WriteHeader("AUTO-CLASSIFIED FUNCTIONS (AVTOKLASSIFIKATSIYA)");

    Logger_Write(COLOR_INFO,
        "  Total auto-classified: %u\n", g_AutoClassifiedCount);
    Logger_Write(COLOR_INFO,
        "  Classification is based on import calls and string references.\n");
    Logger_Write(COLOR_INFO,
        "  This analysis is version-independent (ne zavisit ot versii main.exe).\n\n");

    for (i = 0; i < g_AutoClassifiedCount; i++)
    {
        const AUTO_CLASSIFIED_FUNC* ac = &g_AutoClassified[i];

        /* Разделитель при смене категории */
        if (strcmp(lastCategory, ac->Category) != 0)
        {
            Logger_Write(COLOR_DEFAULT, "\n");
            Logger_Write(COLOR_SECTION,
                "  --- %s ---\n", ac->Category);
            lastCategory = ac->Category;
        }

        Logger_WriteFunction(ac->VA, ac->FileOffset,
                             ac->AutoName, ac->AutoDescription);
    }
}
