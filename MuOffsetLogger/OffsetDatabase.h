/*
 * OffsetDatabase.h
 * MuOffsetLogger - Система логирования офсетов main.exe MU Online
 *
 * База данных офсетов main.exe.
 * Стартовая база = 0 (пустая). Заполняется из main.exe после анализа PE.
 * Справочные (reference) офсеты хранятся отдельно для сопоставления.
 * Каждый офсет содержит VA, File Offset, категорию, имя и описание.
 * Совместимость: Visual Studio 2010 (v100), Windows 10 x86/x64
 */

#ifndef OFFSET_DATABASE_H
#define OFFSET_DATABASE_H

#include <windows.h>

/* Максимальное количество офсетов в активной базе */
#define OFFSETDB_MAX_ACTIVE  4096

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
 * Сброс активной базы данных в ноль (стартовое состояние).
 * Вызывать перед началом нового анализа main.exe.
 * После вызова OffsetDB_GetAllOffsets() вернёт 0 записей.
 */
void OffsetDB_Reset(void);

/*
 * Получить массив активных (обнаруженных) офсетов.
 * Стартовая база = 0. Заполняется после анализа main.exe.
 * pCount - указатель для записи количества офсетов
 * Возвращает указатель на массив OFFSET_ENTRY
 */
const OFFSET_ENTRY* OffsetDB_GetAllOffsets(DWORD* pCount);

/*
 * Получить массив справочных (reference) офсетов.
 * Это эталонные офсеты для сопоставления с данными из main.exe.
 * pCount - указатель для записи количества
 */
const OFFSET_ENTRY* OffsetDB_GetReferenceOffsets(DWORD* pCount);

/*
 * Добавить офсет в активную базу данных.
 * Возвращает TRUE если добавлен, FALSE если дубликат или база полна.
 */
BOOL OffsetDB_AddEntry(DWORD va, DWORD fileOffset, OFFSET_TYPE type,
                       const char* category, const char* name,
                       const char* description);

/*
 * Заполнить активную базу из PE-образа main.exe.
 * Сканирует образ, сопоставляет со справочными офсетами,
 * добавляет только те, которые подтверждены в PE.
 * imageBuffer - указатель на замапленный PE-образ
 * imageBase   - базовый адрес загрузки из PE-заголовков
 * imageSize   - размер образа в памяти
 * Возвращает количество добавленных офсетов.
 */
DWORD OffsetDB_PopulateFromScan(const BYTE* imageBuffer,
                                DWORD imageBase, DWORD imageSize);

/*
 * Логирует все офсеты из активной базы данных, группируя по категориям.
 * Если база пуста (стартовое состояние = 0), выводит сообщение об этом.
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
