/*
 * Logger.h
 * MuOffsetLogger - Система логирования офсетов main.exe MU Online
 *
 * Модуль логирования: вывод в консоль и запись в файл
 * Совместимость: Visual Studio 2010 (v100), Windows 10 x86/x64
 */

#ifndef LOGGER_H
#define LOGGER_H

#include <windows.h>
#include <stdio.h>

/* Цвета консоли */
#define COLOR_DEFAULT   0x07
#define COLOR_HEADER    0x0E  /* Желтый */
#define COLOR_SECTION   0x0B  /* Голубой */
#define COLOR_OFFSET    0x0A  /* Зеленый */
#define COLOR_IMPORT    0x0D  /* Фиолетовый */
#define COLOR_FUNCTION  0x09  /* Синий */
#define COLOR_VARIABLE  0x0C  /* Красный */
#define COLOR_INFO      0x08  /* Серый */
#define COLOR_WARN      0x0E  /* Желтый */

#ifdef __cplusplus
extern "C" {
#endif

/* Инициализация логгера: открытие консоли и файла */
BOOL Logger_Init(const char* logFilePath);

/* Завершение логгера: закрытие файла */
void Logger_Shutdown(void);

/* Вывод заголовка секции */
void Logger_WriteHeader(const char* text);

/* Вывод разделителя */
void Logger_WriteSeparator(void);

/* Вывод строки с цветом в консоль и в файл */
void Logger_Write(WORD color, const char* format, ...);

/* Вывод офсета с описанием */
void Logger_WriteOffset(DWORD va, DWORD fileOffset, const char* category,
                        const char* name, const char* description);

/* Вывод импортированной функции */
void Logger_WriteImport(DWORD iatVA, const char* dllName,
                        const char* funcName, DWORD callCount);

/* Вывод внутренней функции */
void Logger_WriteFunction(DWORD va, DWORD fileOffset,
                          const char* name, const char* description);

/* Вывод глобальной переменной */
void Logger_WriteVariable(DWORD va, DWORD fileOffset,
                          const char* name, const char* description);

/* Получить количество записанных офсетов */
DWORD Logger_GetOffsetCount(void);

#ifdef __cplusplus
}
#endif

#endif /* LOGGER_H */
