# MuTracker — Трекер внутриигрового процесса MuOnline

## Описание

**MuTracker** — инструмент динамического анализа и мониторинга игрового процесса MuOnline (`main.exe`) в реальном времени. Перехватывает, логирует и отображает все функции и их смещения (offsets), которые выполняются внутри процесса игры.

**MuTrackerLoader.exe** — полноценное GUI-приложение (Win32 API) с тёмной темой, ListView для отображения трейс-данных, и IPC через SharedMemory для связи с инжектированной DLL.

## Архитектура

```
MuTracker/
├── Shared/                             # Общие заголовки IPC
│   ├── SharedStructs.h                 # Структуры SharedMemory
│   └── IPC_Protocol.h                  # Протокол Named Pipe
├── src/
│   ├── core/
│   │   ├── HookEngine.h/.cpp          # Движок inline-хуков с трамплинами
│   │   ├── PatternScanner.h/.cpp      # Сканер паттернов с wildcard-поддержкой
│   │   ├── CallTracer.h/.cpp          # Трекер вызовов функций
│   │   └── MemoryUtils.h/.cpp         # Утилиты работы с памятью
│   ├── attach/
│   │   ├── ProcessAttacher.h/.cpp     # Привязка к процессу main.exe
│   │   └── DLLInjector.h/.cpp         # Инжектор DLL (CreateRemoteThread)
│   ├── disasm/
│   │   ├── hde32.h/.c                 # x86 декодер длины инструкций
│   │   ├── table32.h                  # Таблицы опкодов x86
│   │   └── DisasmEngine.h/.cpp        # C++ обёртка дизассемблера
│   ├── log/
│   │   └── Logger.h/.cpp              # Логирование (консоль + файл)
│   └── config/
│       └── Config.h/.cpp              # Парсер JSON-конфигурации
├── dll/
│   └── MuTrackerDLL/
│       └── dllmain.cpp                # Инжектируемая DLL
├── loader/
│   └── MuTrackerLoader/
│       ├── main.cpp                   # WinMain точка входа (GUI)
│       ├── MainWindow.h/.cpp          # Главное окно (Win32 GUI, тёмная тема)
│       ├── TraceViewer.h/.cpp         # Чтение данных из SharedMemory
│       ├── resource.h                 # Идентификаторы ресурсов
│       ├── MuTracker.rc               # Файл ресурсов (версия, манифест)
│       └── MuTracker.manifest         # Визуальные стили + DPI
├── config.json                        # Конфиг по умолчанию
├── CMakeLists.txt                     # Сборочная система CMake
└── README.md                          # Этот файл
```

## Интерфейс

MuTrackerLoader.exe предоставляет красивый тёмный GUI:

```
┌─────────────────────────────────────────────────────────────┐
│  █ MuOnline Tracker v1.0                                    │
├─────────────────────────────────────────────────────────────┤
│  Process: [main.exe    ] [🔍 Find]  ● Attached  PID: 12345 │
│  DLL:     [C:\...\MuTrackerDLL.dll              ] [...]     │
│─────────────────────────────────────────────────────────────│
│  [  ▶ Inject DLL  ]  [  ■ Eject DLL  ]  [  ⚙ Settings  ]  │
│─────────────────────────────────────────────────────────────│
│  Hooks: 12          Total Calls: 847,291       Dropped: 0   │
│─────────────────────────────────────────────────────────────│
│  Offset    │ Address   │ Name          │ Calls/s │ Total    │
│  0x0052A3F0│ 0x004523F0│ PlayerMove    │   847/s │  12,341  │
│  0x00489B20│ 0x00389B20│ AttackCalc    │    12/s │     421  │
│  0x006C1440│ 0x005C1440│ RenderEntity  │ 3,201/s │ 482,091  │
│─────────────────────────────────────────────────────────────│
│  [Log output area with green text on dark background]       │
│─────────────────────────────────────────────────────────────│
│  [💾 Export CSV]  [🗑 Clear]  [⏸ Pause]                     │
├─────────────────────────────────────────────────────────────┤
│  Ready │ DLL: Connected │ Uptime: 342s                      │
└─────────────────────────────────────────────────────────────┘
```

### Визуальные особенности

- **Тёмная тема** — все элементы стилизованы под тёмный фон (RGB 30,30,35)
- **Цветовое кодирование** — офсеты синие, вызовы/сек зелёные, итого жёлтые
- **ListView** — чередование строк, полная выделка строк, сетка
- **DPI-aware** — корректное отображение на HiDPI-мониторах
- **Visual Styles** — Common Controls v6 через манифест
- **Иммерсивный тёмный заголовок** — DWM API для Windows 10/11

## Возможности

### Реализовано

- [x] **GUI Loader** — красивое Win32 окно с тёмной темой
  - Поиск процесса, инжекция/выгрузка DLL
  - ListView с трейс-данными в реальном времени
  - Лог-область с автопрокруткой
  - Экспорт в CSV через диалог сохранения
  - Пауза/возобновление обновления
  - Статус-бар с информацией о подключении

- [x] **SharedMemory IPC** — обмен данными между DLL и Loader
  - SharedStructs.h — общие структуры данных
  - Кольцевой буфер 4 МБ для записей вызовов
  - Таблица функций для отображения в ListView
  - Heartbeat и статус подключения

- [x] **PatternScanner** — поиск паттернов в памяти процесса
  - Поддержка wildcard-байт (`??`) в паттернах
  - IDA-style сигнатуры: `"55 8B EC 83 EC ?? 56 57"`
  - Кэширование результатов сканирования

- [x] **HookEngine** — движок inline-хуков для x86
  - Trampoline-based inline hooking (JMP splice, 5+ байт)
  - Автоматическое определение границ инструкций (hde32)
  - Thread-safe установка/снятие хуков

- [x] **DisasmEngine** — декодер x86 инструкций
- [x] **CallTracer** — трекер вызовов функций
- [x] **ProcessAttacher** — привязка к процессу
- [x] **DLLInjector** — инжекция/выгрузка DLL
- [x] **Logger** — логирование (файл + GUI)
- [x] **Config** — JSON-конфигурация

### Планируется

- [ ] D3D9 Overlay (in-game отображение через EndScene hook)
- [ ] Named Pipe IPC (двунаправленные команды)
- [ ] VTable Hook / Hardware Breakpoint Hook
- [ ] Symbol Resolver (PDB)
- [ ] Network Monitor

## Стек технологий

| Компонент         | Технология                          |
|-------------------|-------------------------------------|
| Язык              | C++17                               |
| Архитектура цели  | x86 (32-bit)                        |
| GUI               | Win32 API (тёмная тема, Common Controls v6) |
| IPC               | SharedMemory (4 МБ)                 |
| Дизассемблер      | hde32 (встроенный)                  |
| Сборка            | CMake 3.15+ / MSVC 2019/2022       |
| Конфиг            | Встроенный JSON-парсер              |
| Инжекция          | CreateRemoteThread + LoadLibrary    |
| Хуки              | Inline splice (трамплины)           |

## Сборка

### Требования

- Windows 10/11
- Visual Studio 2019 или 2022 (MSVC v142/v143)
- CMake 3.15 или новее
- Windows SDK

### Команды сборки

```bash
# Создание проекта Visual Studio (x86)
cd MuTracker
mkdir build
cd build
cmake .. -G "Visual Studio 16 2019" -A Win32

# Сборка Release
cmake --build . --config Release

# Результат: build/bin/
#   - MuTrackerLoader.exe   (GUI-приложение)
#   - MuTrackerDLL.dll       (инжектируемая DLL)
#   - config.json
```

### Сборка из командной строки MSVC

```bash
# Открыть Developer Command Prompt for VS 2019 (x86)
cd MuTracker
mkdir build && cd build
cmake .. -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release
nmake
```

## Использование

### Вариант 1: GUI Loader (рекомендуется)

1. Поместите `MuTrackerLoader.exe`, `MuTrackerDLL.dll` и `config.json` в одну папку
2. Запустите игру MuOnline (`main.exe`)
3. Запустите `MuTrackerLoader.exe`
4. Введите имя процесса и нажмите **Find**
5. Нажмите **▶ Inject DLL** для инжекции
6. Наблюдайте за трейс-данными в ListView в реальном времени
7. Используйте **💾 Export CSV** для экспорта результатов

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

## Совместимость с MuOffsetLogger

MuTracker разработан как продвинутая замена MuOffsetLogger. Он использует ту же базу знаний об оффсетах main.exe и совместим с файлом `offsets_main_exe.txt`.

## Лицензия

Инструмент предназначен для образовательных и исследовательских целей.
