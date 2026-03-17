/*
 * OffsetDatabase.h
 * MuOffsetLogger - Система логирования офсетов main.exe MU Online
 *
 * База данных известных офсетов из анализа main.exe.
 * Каждый офсет содержит VA, File Offset, категорию, имя и описание.
 * Совместимость: Visual Studio 2010 (v100), Windows 10 x86/x64
 */

#ifndef OFFSET_DATABASE_H
#define OFFSET_DATABASE_H

#include <windows.h>

/* Тип офсета */
typedef enum _OFFSET_TYPE
{
    OT_FUNCTION,     /* Функция */
    OT_VARIABLE,     /* Глобальная переменная */
    OT_STRING,       /* Строковая константа */
    OT_VTABLE,       /* Виртуальная таблица */
    OT_IMPORT,       /* Импортированная функция */
    OT_FLOAT_CONST,  /* Float-константа */
    OT_PACKET,       /* Пакет сетевого протокола */
    OT_CRT,          /* CRT/Runtime функция */
    OT_DATA          /* Данные (пути, ресурсы) */
} OFFSET_TYPE;

/* Запись в базе данных офсетов */
typedef struct _OFFSET_ENTRY
{
    DWORD       VA;             /* Virtual Address */
    DWORD       FileOffset;     /* File Offset в main.exe */
    OFFSET_TYPE Type;           /* Тип офсета */
    const char* Category;       /* Категория (раздел) */
    const char* Name;           /* Имя переменной/функции */
    const char* Description;    /* Описание на русском/английском */
} OFFSET_ENTRY;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Получить массив всех известных офсетов
 * pCount - указатель для записи количества офсетов
 * Возвращает указатель на массив OFFSET_ENTRY
 */
const OFFSET_ENTRY* OffsetDB_GetAllOffsets(DWORD* pCount);

/*
 * Логирует все известные офсеты из базы данных, группируя по категориям
 * baseAddress - базовый адрес загрузки main.exe (для проверки/коррекции)
 */
void OffsetDB_LogAllOffsets(DWORD_PTR baseAddress);

/*
 * Проверяет доступность офсета в памяти и выводит актуальное значение
 * baseAddress - базовый адрес загрузки
 * va          - виртуальный адрес для проверки
 * Возвращает TRUE если адрес доступен
 */
BOOL OffsetDB_VerifyOffset(DWORD_PTR baseAddress, DWORD va);

#ifdef __cplusplus
}
#endif

#endif /* OFFSET_DATABASE_H */
