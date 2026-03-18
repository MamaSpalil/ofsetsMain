# MuOffsetLogger

Консольное EXE-приложение для анализа и логирования офсетов, переменных и функций main.exe MU Online.

## Описание

MuOffsetLogger.exe — автономное консольное приложение. Логика работы:
1. Помещаем `MuOffsetLogger.exe` в папку с игровым клиентом (рядом с `main.exe`)
2. Запускаем `MuOffsetLogger.exe` — открывается консольное окно
3. Программа предлагает запустить `main.exe` — соглашаемся (или отказываемся для анализа без запуска)
4. Запускается `main.exe` из той же папки
5. Консоль анализирует PE-структуру, все внутриигровые офсеты, функции и строки
6. Логи отображаются в консольном окне в реальном времени
7. Логи сохраняются в файл `MuOffsetLog.txt` рядом с `MuOffsetLogger.exe`

### Этапы анализа

1. **PE Structure Analysis** — разбор заголовков PE, секций, таблицы импорта (IAT)
2. **Known Offsets Database** — вывод 137 известных офсетов с комментариями и описаниями
3. **Function Scanning** — сканирование .text секции: поиск функций по прологам (55 8B EC) и CALL-целям
4. **String Reference Scanning** — поиск строковых ссылок в секции данных

## Требования для сборки

- **Visual Studio 2010** (Platform Toolset v100)
- **Windows SDK** (встроенный в VS 2010)
- **ОС**: Windows 10 x86 или x64

## Сборка проекта

### Через Visual Studio 2010

1. Откройте `MuOffsetLogger/MuOffsetLogger.sln` в Visual Studio 2010
2. Выберите конфигурацию:
   - `Debug|Win32` или `Release|Win32` — для 32-битного EXE
   - `Debug|x64` или `Release|x64` — для 64-битного EXE
3. Нажмите `Build → Build Solution` (Ctrl+Shift+B)
4. Готовый файл `MuOffsetLogger.exe` будет в папке `Debug/` или `Release/`

### Через командную строку (Developer Command Prompt)

```bat
cd MuOffsetLogger
msbuild MuOffsetLogger.sln /p:Configuration=Release /p:Platform=Win32
```

> **Важно:** main.exe MU Online — 32-битный PE32 файл. Рекомендуется собирать как **Win32** (x86) для совместимости.

## Использование

1. Соберите проект (конфигурация `Release|Win32`)
2. Скопируйте `MuOffsetLogger.exe` в папку с игровым клиентом MU Online (рядом с `main.exe`)
3. Запустите `MuOffsetLogger.exe`
4. В консоли появится предложение запустить `main.exe`:
   - Введите `1` — main.exe запустится, затем начнётся анализ офсетов
   - Введите `0` — анализ файла main.exe без его запуска
5. Дождитесь завершения анализа
6. Результаты отображаются в консоли и сохраняются в `MuOffsetLog.txt`
7. Нажмите Enter для закрытия программы

## Структура проекта

```
MuOffsetLogger/
├── MuOffsetLogger.sln              — Solution файл VS 2010
├── MuOffsetLogger.vcxproj          — Файл проекта VS 2010
├── MuOffsetLogger.vcxproj.filters  — Фильтры проекта
├── main.cpp                        — Точка входа EXE, чтение файла, запуск main.exe
├── Logger.h / Logger.cpp           — Система логирования (консоль + файл)
├── PEAnalyzer.h / PEAnalyzer.cpp   — Анализ PE-структуры из памяти
├── OffsetDatabase.h / OffsetDatabase.cpp — База известных офсетов (137 записей)
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
