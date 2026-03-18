/*
 * ProcessMonitor.h
 * MuOffsetLogger - Мониторинг процесса main.exe MU Online
 *
 * Модуль отслеживания состояния процесса и окна игры:
 * - Обнаружение и подключение к процессу main.exe
 * - Мониторинг состояния окна игры (заголовок, позиция, фокус)
 * - Чтение памяти процесса для проверки офсетов
 * - Отслеживание всех событий окна (создание, перемещение, свёрнуто)
 * Совместимость: Visual Studio 2010 (v100), Windows 10 x86/x64
 */

#ifndef PROCESS_MONITOR_H
#define PROCESS_MONITOR_H

#include <windows.h>

/* Состояния игрового процесса */
typedef enum _GAME_STATE
{
    GS_UNKNOWN = 0,
    GS_STARTING,            /* Процесс запущен, окно ещё не найдено */
    GS_WINDOW_CREATED,      /* Окно создано */
    GS_ACTIVE,              /* Окно активно (на переднем плане) */
    GS_INACTIVE,            /* Окно неактивно (в фоне) */
    GS_MINIMIZED,           /* Окно свёрнуто */
    GS_CLOSED               /* Процесс завершён */
} GAME_STATE;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Поиск запущенного процесса по имени
 * processName - имя процесса (например "main.exe")
 * Возвращает PID или 0 если не найден
 */
DWORD ProcessMonitor_FindProcess(const char* processName);

/*
 * Инициализация монитора процесса
 * processId - PID процесса main.exe
 * hProcess  - хэндл процесса (или NULL для автоматического открытия)
 * Возвращает TRUE при успешной инициализации
 */
BOOL ProcessMonitor_Init(DWORD processId, HANDLE hProcess);

/*
 * Обновление мониторинга (вызывать в цикле)
 * Проверяет состояние процесса, окна, фокуса и логирует изменения
 * Возвращает TRUE если процесс жив, FALSE если завершился
 */
BOOL ProcessMonitor_Update(void);

/*
 * Проверка: процесс ещё работает?
 */
BOOL ProcessMonitor_IsRunning(void);

/*
 * Получить текущее состояние игры
 */
GAME_STATE ProcessMonitor_GetState(void);

/*
 * Чтение памяти процесса по виртуальному адресу
 * va     - виртуальный адрес для чтения
 * buffer - буфер для записи данных
 * size   - количество байт для чтения
 * Возвращает TRUE при успехе
 */
BOOL ProcessMonitor_ReadMemory(DWORD va, void* buffer, SIZE_T size);

/*
 * Получить количество зарегистрированных событий
 */
DWORD ProcessMonitor_GetEventCount(void);

/*
 * Завершение мониторинга: закрытие хэндлов и вывод статистики
 */
void ProcessMonitor_Shutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* PROCESS_MONITOR_H */
