# MuTracker — Трекер внутриигрового процесса MuOnline

## Описание

**MuTracker** — инструмент динамического анализа и мониторинга игрового процесса MuOnline (`main.exe`) в реальном времени. Перехватывает, логирует и отображает все функции и их смещения (offsets), которые выполняются внутри процесса игры.

## Архитектура

```
MuTracker/
├── src/
│   ├── core/
│   │   ├── HookEngine.h/.cpp       # Движок inline-хуков с трамплинами
│   │   ├── PatternScanner.h/.cpp   # Сканер паттернов с wildcard-поддержкой
│   │   ├── CallTracer.h/.cpp       # Трекер вызовов функций
│   │   └── MemoryUtils.h/.cpp      # Утилиты работы с памятью
│   ├── attach/
│   │   ├── ProcessAttacher.h/.cpp  # Привязка к процессу main.exe
│   │   └── DLLInjector.h/.cpp      # Инжектор DLL (CreateRemoteThread)
│   ├── disasm/
│   │   ├── hde32.h/.c              # x86 декодер длины инструкций
│   │   ├── table32.h               # Таблицы опкодов x86
│   │   └── DisasmEngine.h/.cpp     # C++ обёртка дизассемблера
│   ├── log/
│   │   └── Logger.h/.cpp           # Логирование (консоль + файл)
│   └── config/
│       └── Config.h/.cpp           # Парсер JSON-конфигурации
├── dll/
│   └── MuTrackerDLL/
│       └── dllmain.cpp             # Инжектируемая DLL
├── loader/
│   └── MuTrackerLoader/
│       └── main.cpp                # Внешний лоадер/лаунчер
├── config.json                     # Конфиг по умолчанию
├── CMakeLists.txt                  # Сборочная система CMake
└── README.md                       # Этот файл
```

## Возможности

### Реализовано (Шаг 1)

- [x] **PatternScanner** — поиск паттернов в памяти процесса
  - Поддержка wildcard-байт (`??`) в паттернах
  - IDA-style сигнатуры: `"55 8B EC 83 EC ?? 56 57"`
  - Кэширование результатов сканирования
  - Поиск по модулям (main.exe, DLL)
  - Перечисление экспортируемых функций модуля

- [x] **HookEngine** — движок inline-хуков для x86
  - Trampoline-based inline hooking (JMP splice, 5+ байт)
  - Автоматическое определение границ инструкций (hde32)
  - IAT hooking (патчинг таблицы импорта)
  - Корректная фиксация относительных смещений в трамплинах
  - Thread-safe установка/снятие хуков
  - Счётчики вызовов для каждого хука

- [x] **DisasmEngine** — декодер x86 инструкций
  - Определение длины любой x86 инструкции
  - Классификация: CALL, JMP, RET, PUSH, POP, NOP, INT3
  - Форматирование вывода в Intel-синтаксисе
  - Детекция относительных смещений для фиксации

- [x] **CallTracer** — трекер вызовов функций
  - Полный трассинг (каждый вызов)
  - Частотный мониторинг (подсчёт вызовов/сек)
  - Фильтрация по модулям и диапазонам адресов
  - Захват аргументов со стека
  - Экспорт в JSON, CSV, LOG форматы

- [x] **ProcessAttacher** — привязка к процессу
  - Поиск по имени процесса и заголовку окна
  - Мониторинг состояния процесса
  - Автоматическое переподключение

- [x] **DLLInjector** — инжекция DLL
  - CreateRemoteThread + LoadLibrary метод
  - Выгрузка DLL (FreeLibrary)

- [x] **Logger** — система логирования
  - Консоль с цветами + файл
  - Уровни: TRACE, DEBUG, INFO, WARN, ERROR, FATAL
  - Форматированный вывод оффсетов и вызовов

- [x] **Config** — конфигурация
  - JSON-формат конфигурации
  - Паттерны для сканирования
  - Фильтры модулей и адресов
  - Настройки вывода

### Планируется (следующие шаги)

- [ ] VTable Hook — перехват виртуальных методов
- [ ] Hardware Breakpoint Hook — DR0-DR3 регистры
- [ ] In-Game Overlay (ImGui + D3D9)
- [ ] Внешний GUI (ImGui standalone)
- [ ] Symbol Resolver (PDB)
- [ ] Network Monitor (send/recv перехват)
- [ ] Memory Watch (мониторинг изменений памяти)
- [ ] SIMD-ускорение сканирования паттернов (SSE2/AVX2)
- [ ] Многопоточное сканирование
- [ ] Snapshot/Replay системы

## Стек технологий

| Компонент         | Технология                          |
|-------------------|-------------------------------------|
| Язык              | C++17                               |
| Архитектура цели  | x86 (32-bit)                        |
| Дизассемблер      | hde32 (встроенный)                  |
| Сборка            | CMake 3.15+ / MSVC 2022             |
| Конфиг            | Встроенный JSON-парсер              |
| Инжекция          | CreateRemoteThread + LoadLibrary    |
| Хуки              | Inline splice (трамплины)           |
| Логирование       | Консоль (цветная) + файл            |

## Сборка

### Требования

- Windows 10/11
- Visual Studio 2022 (MSVC v143)
- CMake 3.15 или новее
- Windows SDK

### Команды сборки

```bash
# Создание проекта Visual Studio (x86)
mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A Win32

# Сборка Release
cmake --build . --config Release

# Результат: build/bin/
#   - MuTrackerLoader.exe
#   - MuTrackerDLL.dll
#   - config.json
```

### Сборка из командной строки MSVC

```bash
# Открыть Developer Command Prompt for VS 2022 (x86)
mkdir build && cd build
cmake .. -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release
nmake
```

## Использование

### Вариант 1: Инжекция DLL (рекомендуется)

1. Поместите `MuTrackerLoader.exe`, `MuTrackerDLL.dll` и `config.json` рядом с `main.exe`
2. Запустите игру MuOnline
3. Запустите `MuTrackerLoader.exe`
4. Выберите `[1]` — найти процесс main.exe
5. Выберите `[2]` — инжектировать MuTrackerDLL.dll
6. Откроется консоль трекера с результатами анализа

### Вариант 2: Внешний анализ (без инжекции)

1. Запустите игру
2. Запустите `MuTrackerLoader.exe`
3. Выберите `[1]` — найти процесс
4. Выберите `[3]` — запустить внешнее сканирование паттернов

## Конфигурация

Файл `config.json` содержит настройки:

```json
{
  "target": {
    "process": "main.exe",
    "window_title": "MU",
    "auto_attach": true
  },
  "hooks": {
    "mode": "inline",
    "patterns": [
      { "name": "PlayerMove", "sig": "55 8B EC 83 EC ?? 56 57 8B F9", "offset": 0 }
    ]
  },
  "filter": {
    "include_modules": ["main.exe"],
    "capture_args": true
  },
  "output": {
    "log_file": "trace_output.log",
    "log_format": "json"
  }
}
```

## Формат вывода

```
[2025-01-15 14:32:01.337] [CALL] [TID:1234] 0x0052A3F0 (+0x12A3F0) PlayerMove       | calls: 847  | args: [0x1F4, 0x64, 0x00]
[2025-01-15 14:32:01.338] [CALL] [TID:1234] 0x00489B20 (+0x089B20) AttackCalculate  | calls: 12   | args: [0x3E8, 0x0A, 0x01]
[2025-01-15 14:32:01.340] [CALL] [TID:5678] 0x006C1440 (+0x2C1440) RenderEntity     | calls: 3201 | args: [ptr:0x1A2B3C4D]
```

## Совместимость с MuOffsetLogger

MuTracker разработан как продвинутая замена MuOffsetLogger. Он использует ту же базу знаний об оффсетах main.exe и совместим с файлом `offsets_main_exe.txt`.

## Лицензия

Инструмент предназначен для образовательных и исследовательских целей.
