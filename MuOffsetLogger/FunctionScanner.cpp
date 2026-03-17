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
