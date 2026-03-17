/*
 * PEAnalyzer.h
 * MuOffsetLogger - Система логирования офсетов main.exe MU Online
 *
 * Модуль анализа PE-структуры: разбор заголовков, секций, IAT из памяти процесса
 * Совместимость: Visual Studio 2010 (v100), Windows 10 x86/x64
 */

#ifndef PE_ANALYZER_H
#define PE_ANALYZER_H

#include <windows.h>

/* Максимальное количество секций */
#define MAX_SECTIONS   16
/* Максимальное количество импортированных DLL */
#define MAX_IMPORT_DLL 32
/* Максимальное количество импортированных функций на DLL */
#define MAX_IMPORT_FUNC_PER_DLL 256

/* Информация о секции PE */
typedef struct _PE_SECTION_INFO
{
    char    Name[16];
    DWORD   VirtualAddress;     /* VA = ImageBase + RVA */
    DWORD   VirtualSize;
    DWORD   RawOffset;          /* File Offset */
    DWORD   RawSize;
    DWORD   Characteristics;
} PE_SECTION_INFO;

/* Информация об импортированной функции */
typedef struct _PE_IMPORT_FUNC
{
    char    FunctionName[128];
    DWORD   IatVA;              /* VA записи в IAT */
    DWORD   Ordinal;            /* Ординал (если импорт по ординалу) */
    BOOL    ByOrdinal;          /* TRUE если импорт по ординалу */
} PE_IMPORT_FUNC;

/* Информация об импортированной DLL */
typedef struct _PE_IMPORT_DLL
{
    char            DllName[128];
    PE_IMPORT_FUNC  Functions[MAX_IMPORT_FUNC_PER_DLL];
    DWORD           FunctionCount;
} PE_IMPORT_DLL;

/* Информация о PE-файле */
typedef struct _PE_FILE_INFO
{
    DWORD           ImageBase;
    DWORD           EntryPointRVA;
    DWORD           EntryPointVA;
    DWORD           SizeOfImage;
    DWORD           SizeOfHeaders;
    WORD            Subsystem;
    WORD            Machine;
    WORD            NumberOfSections;
    DWORD           FileAlignment;
    DWORD           SectionAlignment;
    DWORD           SizeOfStackReserve;
    DWORD           SizeOfHeapReserve;

    PE_SECTION_INFO Sections[MAX_SECTIONS];
    DWORD           SectionCount;

    PE_IMPORT_DLL   Imports[MAX_IMPORT_DLL];
    DWORD           ImportDllCount;
} PE_FILE_INFO;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Анализирует PE-структуру модуля в памяти
 * hModule - базовый адрес модуля (HMODULE)
 * pInfo   - структура для записи результатов
 * Возвращает TRUE при успехе
 */
BOOL PEAnalyzer_Parse(HMODULE hModule, PE_FILE_INFO* pInfo);

/*
 * Логирует PE-заголовки в консоль и файл
 */
void PEAnalyzer_LogHeaders(const PE_FILE_INFO* pInfo);

/*
 * Логирует секции PE-файла
 */
void PEAnalyzer_LogSections(const PE_FILE_INFO* pInfo);

/*
 * Логирует таблицу импорта (IAT)
 */
void PEAnalyzer_LogImports(const PE_FILE_INFO* pInfo);

/*
 * Преобразование RVA в File Offset используя таблицу секций
 */
DWORD PEAnalyzer_RvaToFileOffset(const PE_FILE_INFO* pInfo, DWORD rva);

#ifdef __cplusplus
}
#endif

#endif /* PE_ANALYZER_H */
