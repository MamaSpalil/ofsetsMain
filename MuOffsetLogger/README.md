# MuOffsetLogger

DLL-модуль для перехвата и логирования офсетов, переменных и функций main.exe MU Online.

## Описание

При внедрении в процесс main.exe, DLL:
1. Открывает консольное окно для отображения результатов в реальном времени
2. Анализирует PE-структуру main.exe в памяти (заголовки, секции, таблица импорта)
3. Выводит все известные офсеты с комментариями (имена функций и переменных)
4. Сканирует .text секцию для обнаружения функций по прологам и CALL-целям
5. Сканирует строковые ссылки в секции данных
6. Записывает полный лог в файл `MuOffsetLog.txt`

## Требования для сборки

- **Visual Studio 2010** (Platform Toolset v100)
- **Windows SDK** (встроенный в VS 2010)
- **ОС**: Windows 10 x86 или x64

## Сборка проекта

### Через Visual Studio 2010

1. Откройте `MuOffsetLogger/MuOffsetLogger.sln` в Visual Studio 2010
2. Выберите конфигурацию:
   - `Debug|Win32` или `Release|Win32` — для 32-битной DLL
   - `Debug|x64` или `Release|x64` — для 64-битной DLL
3. Нажмите `Build → Build Solution` (Ctrl+Shift+B)
4. Готовый файл `MuOffsetLogger.dll` будет в папке `Debug/` или `Release/`

### Через командную строку (Developer Command Prompt)

```bat
cd MuOffsetLogger
msbuild MuOffsetLogger.sln /p:Configuration=Release /p:Platform=Win32
```

> **Важно:** main.exe MU Online — 32-битный PE32 файл, поэтому для внедрения необходимо собрать DLL как **Win32** (x86).

## Использование

### Способ 1: DLL-инжектор

1. Соберите проект (конфигурация `Release|Win32`)
2. Запустите main.exe MU Online
3. Используйте любой DLL-инжектор для внедрения `MuOffsetLogger.dll` в процесс main.exe
4. Откроется консольное окно с полным логом офсетов
5. Лог-файл `MuOffsetLog.txt` сохранится рядом с main.exe

### Способ 2: Через экспортируемые функции

DLL экспортирует две функции:
- `StartLogging()` — запуск анализа и логирования
- `StopLogging()` — остановка и закрытие консоли

## Структура проекта

```
MuOffsetLogger/
├── MuOffsetLogger.sln          — Solution файл VS 2010
├── MuOffsetLogger.vcxproj      — Файл проекта VS 2010
├── MuOffsetLogger.vcxproj.filters — Фильтры проекта
├── MuOffsetLogger.def          — Файл экспорта DLL
├── dllmain.cpp                 — Точка входа DLL, главный поток анализа
├── Logger.h / Logger.cpp       — Система логирования (консоль + файл)
├── PEAnalyzer.h / PEAnalyzer.cpp — Анализ PE-структуры из памяти
├── OffsetDatabase.h / OffsetDatabase.cpp — База известных офсетов
└── FunctionScanner.h / FunctionScanner.cpp — Сканер функций и строк
```

## Формат вывода

Каждый офсет выводится в формате:
```
VA  (File: FileOffset)  [Type]  Name -- Description
```

Где:
- **VA** — виртуальный адрес в памяти
- **FileOffset** — смещение в файле main.exe
- **Type** — тип: FUNC (функция), VAR (переменная), STR (строка), IAT (импорт), FLOAT (константа), CRT (Runtime), VTBL (виртуальная таблица)
- **Name** — имя функции или переменной
- **Description** — описание назначения

## Категории офсетов

| Категория | Описание |
|-----------|----------|
| Login/Auth | Функции авторизации и входа в игру |
| STL/String | Реализация std::basic_string (COW) |
| STL/Container | Реализация std::map/std::set (Red-Black tree) |
| CRT/Runtime | Функции C Runtime (malloc, memmove, operator delete) |
| Network | Сетевые функции и серверные адреса |
| Rendering/GDI | Графические функции (GDI, OpenGL) |
| Crypto | Криптографические функции (CryptoAPI) |
| AntiCheat | Строки и функции анти-чит защиты |
| Config/Registry | Конфигурация через реестр Windows |
| Float/Constants | Float-константы с количеством ссылок |
| ASProtect | Строки защиты ASProtect |

## Данные main.exe

- **Тип**: PE32 (GUI) Intel 80386, Windows
- **Размер**: 4,316,672 байт (0x0041DC3D)
- **ImageBase**: 0x00400000
- **Точка входа**: 0x0917C200 (секция .LibHook, защита ASProtect)
- **Секция .text**: VA 0x00401000, Size 0x003B2000 — основной код
- **Секция .data**: VA 0x007B3000, Size 0x0001C000 — глобальные данные
