/*
 * FunctionScanner.h
 * MuOffsetLogger - Система логирования офсетов main.exe MU Online
 *
 * Модуль сканирования функций: поиск функций по сигнатурам в .text секции,
 * обнаружение скрытых функций после NOP/INT3, анализ CALL-целей.
 * Совместимость: Visual Studio 2010 (v100), Windows 10 x86/x64
 */

#ifndef FUNCTION_SCANNER_H
#define FUNCTION_SCANNER_H

#include <windows.h>
#include "PEAnalyzer.h"

/* Максимальное количество обнаруженных функций */
#define MAX_DISCOVERED_FUNCTIONS 16384

/* Информация об обнаруженной функции */
typedef struct _DISCOVERED_FUNCTION
{
    DWORD   VA;             /* Virtual Address */
    DWORD   FileOffset;     /* File Offset */
    BOOL    HasPrologue;    /* TRUE если начинается с push ebp; mov ebp, esp */
    BOOL    IsCallTarget;   /* TRUE если является целью CALL инструкции */
    BOOL    IsHidden;       /* TRUE если найдена после NOP/INT3 (не вызывается) */
    DWORD   StringRefVA;    /* VA строковой ссылки (0 если нет) */
} DISCOVERED_FUNCTION;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Сканирует .text секцию для обнаружения функций
 * pInfo       - информация о PE-файле
 * baseAddress - базовый адрес модуля в памяти
 * Возвращает количество обнаруженных функций
 */
DWORD FuncScanner_ScanTextSection(const PE_FILE_INFO* pInfo,
                                  BYTE* baseAddress);

/*
 * Логирует обнаруженные функции (статистику и список)
 */
void FuncScanner_LogResults(void);

/*
 * Получить количество обнаруженных функций
 */
DWORD FuncScanner_GetCount(void);

/*
 * Сканирует строковые ссылки в .data секции
 * pInfo       - информация о PE-файле
 * baseAddress - базовый адрес модуля в памяти
 */
void FuncScanner_ScanStringRefs(const PE_FILE_INFO* pInfo,
                                BYTE* baseAddress);

/*
 * Логирует найденные строковые ссылки
 */
void FuncScanner_LogStringRefs(void);

#ifdef __cplusplus
}
#endif

#endif /* FUNCTION_SCANNER_H */
