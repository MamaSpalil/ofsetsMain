# Промт: Разработка трекера внутриигрового процесса MuOnline (main.exe)

---

## Контекст задачи

Необходимо разработать инструмент динамического анализа и мониторинга игрового процесса **MuOnline (main.exe)** в реальном времени. Инструмент должен перехватывать, логировать и отображать все функции и их смещения (offsets), которые выполняются внутри окна игры, без нарушения стабильности процесса.

---

## Технические требования к программе

### 1. Инжекция и перехват (Hooking Engine)

Реализуй движок перехвата функций с поддержкой следующих механизмов:

- **Inline Hook (Trampoline Hook)** — перехват по сплайсингу первых байт функции (5–14 байт), с сохранением оригинального пролога и созданием трамплина для передачи управления.
- **IAT/EAT Hook** — перехват через таблицу импорта/экспорта PE-заголовка `main.exe`.
- **VTable Hook** — перехват виртуальных методов C++ объектов (актуально для игровых сущностей MuOnline).
- **Hardware Breakpoint Hook** — использование регистров DR0–DR3 через контекст потока (SetThreadContext) для установки аппаратных брейкпоинтов без модификации памяти.
- **ETW / API Monitor** — опционально, через Event Tracing for Windows для системных вызовов.

Реализовать поддержку **32-bit x86** архитектуры (main.exe MuOnline является 32-битным приложением).

---

### 2. Сканер смещений и сигнатур (Pattern Scanner)

Реализуй модуль поиска и разрешения смещений:

```cpp
// Интерфейс сканера
class PatternScanner {
public:
    // Поиск паттерна в памяти процесса
    uintptr_t FindPattern(const char* moduleName, 
                          const char* pattern, 
                          const char* mask);
    
    // Поиск по IDA-style сигнатуре: "48 89 5C ? ? 57 48 83 EC"
    uintptr_t FindPatternIDA(const char* moduleName, 
                              std::string_view idaPattern);
    
    // Разрешение относительного смещения (RIP-relative, call/jmp)
    uintptr_t ResolveRelativeOffset(uintptr_t instrAddr, 
                                     int offsetPos, 
                                     int instrSize);
    
    // Дамп всех экспортируемых функций модуля
    std::vector<ExportEntry> DumpExports(const char* moduleName);
};
```

Требования к сканеру:
- Поддержка wildcard-байт (`?` и `??`) в паттернах.
- Кэширование результатов сканирования между сессиями (файл `.cache` с хэшем модуля).
- Многопоточное сканирование по регионам памяти через `VirtualQueryEx`.
- Поддержка SIMD (SSE2/AVX2) для ускорения поиска паттернов.

---

### 3. Дизассемблер и декодер инструкций

Интегрировать один из следующих дизассемблерных движков:

- **Zydis** (предпочтительно — легковесный, C API, x86/x64) 
- **Capstone** (альтернатива, более широкая поддержка архитектур)
- **hde32/hde64** (минималистичный, только длина инструкции)

Функциональность:
- Определение длины инструкции для корректного сплайсинга.
- Декодирование операндов (регистры, непосредственные значения, адреса).
- Форматирование вывода в стиле x86 MASM/Intel syntax.
- Детекция `CALL`, `JMP`, `RET`, `PUSH`/`POP` для построения call-графа.

---

### 4. Трекер вызовов функций (Call Tracer)

Реализуй систему отслеживания в реальном времени:

```cpp
struct FunctionCallRecord {
    uintptr_t   address;          // Абсолютный адрес функции
    uintptr_t   offset;           // Смещение относительно базы модуля
    std::string moduleName;        // Имя модуля (main.exe, .dll)
    std::string symbolName;        // Имя символа (если доступно)
    uint64_t    callCount;         // Счётчик вызовов
    uint64_t    timestamp;         // RDTSC / QPC timestamp
    uint32_t    threadId;          // ID потока вызова
    uintptr_t   callerAddress;     // Адрес вызывающей стороны
    std::vector<uintptr_t> args;   // Аргументы (ESP+4, ESP+8, ...)
    CONTEXT     threadCtx;         // Снимок контекста потока
};
```

Режимы трекинга:
- **Полный трассинг** — логирование каждого вызова (высокая нагрузка, для анализа).
- **Частотный мониторинг** — только подсчёт частоты вызовов без полного лога.
- **Фильтрованный** — только функции по заданной маске адресов или имён.
- **Дифференциальный** — логирование только новых/изменившихся функций.

---

### 5. Таргетирование окна MuOnline

Реализуй привязку к процессу и окну игры:

```cpp
class GameProcessAttacher {
public:
    // Поиск процесса по имени
    DWORD FindProcessByName(const wchar_t* processName); // L"main.exe"
    
    // Поиск по заголовку окна
    HWND FindGameWindow(const wchar_t* windowTitle);     // L"MU"
    
    // Инжекция DLL в процесс
    bool InjectDLL(DWORD pid, const std::wstring& dllPath);
    
    // Получение базового адреса модуля
    uintptr_t GetModuleBase(DWORD pid, const wchar_t* moduleName);
    
    // Мониторинг состояния процесса (жив/завершён)
    void WatchProcess(DWORD pid, std::function<void()> onExit);
};
```

Дополнительно:
- Автоматическое переподключение при перезапуске игры.
- Обработка смены базового адреса (ASLR — если включён).
- Поддержка работы как внешний процесс (`ReadProcessMemory`) и как инжектированная DLL.

---

### 6. Система фильтрации и конфигурации

Реализуй JSON/YAML конфиг для гибкой настройки:

```json
{
  "target": {
    "process": "main.exe",
    "window_title": "MU",
    "auto_attach": true,
    "reconnect_interval_ms": 2000
  },
  "hooks": {
    "mode": "inline",
    "scan_on_attach": true,
    "patterns": [
      { "name": "PlayerMove",  "sig": "55 8B EC 83 EC ?? 56 57 8B F9", "offset": 0 },
      { "name": "AttackFunc",  "sig": "55 8B EC 53 8B 5D 08 56",       "offset": 0 },
      { "name": "RenderFrame", "sig": "55 8B EC 83 E4 F8 81 EC",       "offset": 0 }
    ]
  },
  "filter": {
    "include_modules": ["main.exe", "GameMain.dll"],
    "exclude_ranges": [
      { "from": "0x00400000", "to": "0x00401000" }
    ],
    "min_call_frequency": 1,
    "capture_args": true,
    "capture_stack": true,
    "stack_depth": 8
  },
  "output": {
    "log_file": "trace_output.log",
    "real_time_ui": true,
    "log_format": "json",
    "max_records": 100000
  }
}
```

---

### 7. Интерфейс реального времени (Real-Time UI)

Реализуй оверлей или внешнее окно для отображения данных:

**Вариант A — Внешний GUI (ImGui / WinForms / Qt)**:
- Таблица активных функций с колонками: `Offset | Address | Name | Calls/sec | Total Calls | Thread | Last Args`.
- Сортировка по частоте вызовов в реальном времени.
- Поиск и фильтрация по имени / диапазону адресов.
- Граф вызовов (Call Graph) в виде дерева или DAG.
- Экспорт снимка в `.csv`, `.json`, `.idb` (IDA Pro).

**Вариант B — In-Game Overlay (D3D9/D3D11 Hook)**:
- Перехват `IDirect3DDevice9::EndScene` или `IDXGISwapChain::Present`.
- Рендеринг ImGui поверх игры.
- Горячие клавиши для показа/скрытия оверлея.
- Минимальное влияние на FPS (рендеринг не чаще 30 FPS).

---

### 8. Логирование и сохранение трассы

```
[2025-01-15 14:32:01.337] [CALL] [TID:1234] 0x0052A3F0 (+0x12A3F0) PlayerMove       | calls: 847  | args: [0x1F4, 0x64, 0x00]
[2025-01-15 14:32:01.338] [CALL] [TID:1234] 0x00489B20 (+0x089B20) AttackCalculate  | calls: 12   | args: [0x3E8, 0x0A, 0x01]
[2025-01-15 14:32:01.340] [CALL] [TID:5678] 0x006C1440 (+0x2C1440) RenderEntity     | calls: 3201 | args: [ptr:0x1A2B3C4D]
```

Формат хранения:
- **Бинарный** (.trc) — компактный, быстрая запись (struct-pack).
- **JSON Lines** (.jsonl) — для последующего анализа.
- **Совместимый с x64dbg** — экспорт меток и комментариев.

---

### 9. Архитектура проекта

```
MuTracker/
├── src/
│   ├── core/
│   │   ├── HookEngine.h/.cpp       # Движок перехвата
│   │   ├── PatternScanner.h/.cpp   # Сканер паттернов
│   │   ├── CallTracer.h/.cpp       # Трекер вызовов
│   │   └── MemoryUtils.h/.cpp      # Утилиты работы с памятью
│   ├── attach/
│   │   ├── ProcessAttacher.h/.cpp  # Привязка к процессу
│   │   └── DLLInjector.h/.cpp      # Инжектор DLL
│   ├── disasm/
│   │   └── DisasmEngine.h/.cpp     # Обёртка дизассемблера
│   ├── ui/
│   │   ├── OverlayRenderer.h/.cpp  # D3D9 оверлей
│   │   └── ExternalWindow.h/.cpp   # Внешний GUI (ImGui)
│   ├── log/
│   │   └── Logger.h/.cpp           # Система логирования
│   └── config/
│       └── Config.h/.cpp           # Парсер конфигурации
├── deps/
│   ├── zydis/                      # Дизассемблер Zydis
│   ├── imgui/                      # Dear ImGui
│   └── nlohmann_json/              # JSON парсер
├── dll/
│   └── MuTrackerDLL/               # Инжектируемая DLL
├── loader/
│   └── MuTrackerLoader/            # Внешний лоадер/UI
├── config.json                     # Конфиг по умолчанию
└── CMakeLists.txt                  # Сборка
```

---

### 10. Стек технологий

| Компонент         | Технология                          |
|-------------------|-------------------------------------|
| Язык              | C++17 / C++20                       |
| Архитектура цели  | x86 (32-bit)                        |
| Дизассемблер      | Zydis или Capstone                  |
| GUI               | Dear ImGui + DirectX 9              |
| Сборка            | CMake + MSVC / MinGW                |
| Конфиг            | nlohmann/json                       |
| Инжекция          | CreateRemoteThread + LoadLibrary    |
| Хуки              | Inline splice + VEH (опционально)   |

---

### 11. Критерии качества реализации

- [ ] Перехват не вызывает краш или зависание `main.exe`.
- [ ] Работа при 60+ FPS без ощутимого дропа производительности.
- [ ] Корректное снятие хуков при выгрузке (unhook on unload).
- [ ] Поддержка многопоточной среды (thread-safe буфер событий).
- [ ] Корректная обработка исключений внутри хуков (SEH/C++ try-catch).
- [ ] Автоматическое восстановление при патче памяти игрой.
- [ ] Логирование ошибок инжекции/хукинга с кодами ошибок WinAPI.

---

### 12. Дополнительные модули (опционально)

- **Snapshot/Replay** — сохранение полного состояния трассы и воспроизведение.
- **Symbol Resolver** — подгрузка PDB/символов для именования функций.
- **Network Monitor** — перехват `send`/`recv` для анализа игрового протокола.
- **Memory Watch** — мониторинг изменений в заданных адресах памяти в реальном времени.
- **Anti-Detection Bypass** — техники скрытия хуков от внутренних проверок игры.

---

## Пример первого шага реализации

Начни с реализации модуля `PatternScanner` и базового `InlineHookEngine` для x86. Продемонстрируй:

1. Поиск паттерна `55 8B EC` (стандартный пролог функции) в `main.exe`.
2. Установку inline hook на найденный адрес с трамплином.
3. Логирование адреса, смещения и счётчика вызовов в консоль.
4. Корректное снятие хука по команде.

Код должен компилироваться под **MSVC 2022, x86 (32-bit)**, без внешних зависимостей на первом этапе.
