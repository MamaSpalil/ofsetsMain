# Промт: Полная реализация MuOnline Process Tracker — VS2019, Windows 10 Pro x86/x64

---

## СИСТЕМНЫЕ ТРЕБОВАНИЯ К ГЕНЕРИРУЕМОМУ КОДУ

```
IDE:            Visual Studio 2019 (v142 toolset)
OS Target:      Windows 10 Pro (минимум 1903+)
Архитектуры:    Win32 (x86) и x64 — оба конфига должны собираться
Стандарт:       C++17 (/std:c++17)
Runtime:        MT (статический) для Release, MTd для Debug
Subsystem:      Windows (GUI) для Loader; DLL для инжектируемой библиотеки
WinAPI:         Win32 API, не использовать UWP/WinRT
Предупреждения: /W3, нет /WX — предупреждения допустимы, ошибки недопустимы
```

**ОБЯЗАТЕЛЬНОЕ ПРАВИЛО:** Каждый файл должен компилироваться `cl.exe` из VS2019 без единой ошибки C2xxx/C3xxx. Все includes, forward declarations, pragma comment(lib) — явно прописаны. Никаких C++20 концептов, coroutines, modules.

---

## СТРУКТУРА SOLUTION (MuTracker.sln)

```
MuTracker.sln
├── MuTrackerDLL/          ← Инжектируемая DLL (Win32 DLL проект)
│   ├── dllmain.cpp
│   ├── HookEngine.h
│   ├── HookEngine.cpp
│   ├── PatternScanner.h
│   ├── PatternScanner.cpp
│   ├── CallTracer.h
│   ├── CallTracer.cpp
│   ├── DisasmEngine.h
│   ├── DisasmEngine.cpp
│   ├── MemoryUtils.h
│   ├── MemoryUtils.cpp
│   ├── Overlay.h
│   ├── Overlay.cpp
│   └── MuTrackerDLL.vcxproj
│
├── MuTrackerLoader/       ← Внешний GUI-лоадер (Win32 Application)
│   ├── main.cpp
│   ├── InjectorEngine.h
│   ├── InjectorEngine.cpp
│   ├── MainWindow.h
│   ├── MainWindow.cpp
│   ├── TraceViewer.h
│   ├── TraceViewer.cpp
│   ├── resource.h
│   ├── MuTracker.rc
│   └── MuTrackerLoader.vcxproj
│
└── Shared/                ← Общие заголовки (Static Library или просто Include)
    ├── SharedStructs.h
    ├── IPC_Protocol.h
    └── Config.h
```

---

## БЛОК 1 — ОБЩИЕ СТРУКТУРЫ (Shared/SharedStructs.h)

Сгенерируй файл `SharedStructs.h` — единственный хедер, подключаемый и в DLL, и в Loader:

```cpp
#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

// Версия протокола IPC
#define MUTRACKER_VERSION   0x0102
#define MUTRACKER_PIPE_NAME L"\\\\.\\pipe\\MuTrackerIPC"
#define MUTRACKER_SHMEM     L"MuTrackerSharedMem"
#define SHMEM_SIZE          (1024 * 1024 * 4)   // 4 MB ring buffer

#pragma pack(push, 1)

enum class RecordType : uint8_t {
    FunctionCall  = 0x01,
    MemoryAccess  = 0x02,
    ExceptionInfo = 0x03,
    ModuleLoad    = 0x04,
    Heartbeat     = 0x05
};

struct FunctionCallRecord {
    RecordType  type;               // RecordType::FunctionCall
    uint32_t    recordSize;         // sizeof полной структуры
    uint64_t    timestamp;          // QueryPerformanceCounter
    uintptr_t   absoluteAddress;    // Абсолютный VA функции
    uintptr_t   moduleBase;         // База модуля
    uintptr_t   offset;             // = absoluteAddress - moduleBase
    uintptr_t   callerAddress;      // Адрес CALL инструкции
    uint32_t    threadId;
    uint64_t    callCount;
    uint32_t    argCount;
    uintptr_t   args[8];            // Первые 8 аргументов со стека
    char        moduleName[64];
    char        symbolName[128];    // Имя из PDB/экспортов или "sub_XXXXXX"
};

struct ModuleInfo {
    uintptr_t   baseAddress;
    uint32_t    sizeOfImage;
    char        moduleName[MAX_PATH];
    char        modulePath[MAX_PATH];
    bool        isMainExe;
};

struct SharedMemHeader {
    volatile uint32_t   writeIndex;     // Запись в кольцевой буфер
    volatile uint32_t   readIndex;      // Чтение лоадером
    uint32_t            bufferSize;
    uint32_t            version;
    DWORD               injectedPid;
    bool                dllReady;
    bool                tracingEnabled;
    uint32_t            totalRecords;
    uint32_t            droppedRecords;
};

#pragma pack(pop)
```

---

## БЛОК 2 — ДВИЖОК ХУКОВ (MuTrackerDLL/HookEngine.h + .cpp)

### HookEngine.h

```cpp
#pragma once
#include "../Shared/SharedStructs.h"
#include <unordered_map>
#include <mutex>
#include <functional>

// Размер трамплина для x86 (5 байт JMP) и x64 (14 байт ABS JMP)
#ifdef _WIN64
  #define HOOK_TRAMPOLINE_SIZE  14
  #define HOOK_JMP_SIZE         14
#else
  #define HOOK_TRAMPOLINE_SIZE  5
  #define HOOK_JMP_SIZE         5
#endif

struct HookEntry {
    uintptr_t   targetAddress;
    uintptr_t   trampolineAddress;      // Адрес трамплина (VirtualAlloc)
    uint8_t     originalBytes[16];      // Сохранённые оригинальные байты
    size_t      prologSize;             // Реальный размер скопированного пролога
    bool        isActive;
    std::string name;
    std::function<void(FunctionCallRecord&)> callback;
};

class HookEngine {
public:
    static HookEngine& Get();

    // Установить inline hook
    bool Install(const std::string& name,
                 uintptr_t targetAddress,
                 std::function<void(FunctionCallRecord&)> callback);

    // Снять hook
    bool Remove(uintptr_t targetAddress);

    // Снять все hooks (вызывается при DLL_PROCESS_DETACH)
    void RemoveAll();

    // Получить трамплин (для вызова оригинала из хука)
    uintptr_t GetTrampoline(uintptr_t original) const;

    bool IsHooked(uintptr_t address) const;

private:
    HookEngine() = default;

    bool WriteMemory(uintptr_t dest, const void* src, size_t size);
    bool MakeExecutable(uintptr_t address, size_t size);
    size_t CopyPrologInstructions(uintptr_t src, uint8_t* dest, size_t minBytes);
    uintptr_t AllocateTrampoline(uintptr_t nearAddress);

    std::unordered_map<uintptr_t, HookEntry> m_hooks;
    mutable std::mutex m_mutex;
};

// Универсальный прокси-обработчик (naked function для x86)
// Для x64 используется отдельный .asm файл
```

### HookEngine.cpp — требования к реализации:

Реализуй `HookEngine.cpp` со следующими требованиями:

**Для x86 (Win32 config):**
- `JMP rel32` (5 байт: `E9 XX XX XX XX`) для inline-hook.
- `__declspec(naked)` generic proxy с `__asm { pushad; pushfd; ... call handler ... popad; popfd; jmp trampoline }`.
- Копирование пролога с учётом длины инструкций через Zydis/hde32.
- Трамплин: скопированные байты пролога + `JMP` назад к `target + prologSize`.

**Для x64 (x64 config):**
- Абсолютный JMP через `FF 25 00 00 00 00 [8 байт адреса]` (14 байт) — не требует близкого расположения.
- Трамплин аналогично, с корректным копированием RIP-relative инструкций.
- Использование `CONTEXT` структуры через `RtlCaptureContext`.

**Общее:**
- `VirtualProtect` до и после записи (PAGE_EXECUTE_READWRITE → восстановить).
- `FlushInstructionCache` после установки хука.
- Thread-safe через `std::mutex`.
- Полный `try/except` через `__try/__except (EXCEPTION_EXECUTE_HANDLER)` для защиты от AV.

---

## БЛОК 3 — СКАНЕР ПАТТЕРНОВ (MuTrackerDLL/PatternScanner.h + .cpp)

```cpp
#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <cstdint>

struct PatternResult {
    uintptr_t   address;
    uintptr_t   offset;         // Относительно базы модуля
    std::string moduleName;
};

class PatternScanner {
public:
    // IDA-стиль: "55 8B EC ? ? 56 57"
    static std::vector<PatternResult> FindAll(
        const char* moduleName,
        const std::string& idaPattern);

    static PatternResult FindFirst(
        const char* moduleName,
        const std::string& idaPattern);

    // Получить все загруженные модули процесса
    static std::vector<ModuleInfo> GetLoadedModules();

    // Разрешить относительный адрес из CALL/JMP инструкции
    // instrAddr — адрес инструкции, offsetPos — байт смещения, instrSize — полный размер
    static uintptr_t ResolveRelCall(uintptr_t instrAddr, int offsetPos = 1, int instrSize = 5);

    // Получить все экспорты модуля
    static std::vector<std::pair<std::string, uintptr_t>> GetExports(const char* moduleName);

private:
    static std::vector<uint8_t> ParsePattern(const std::string& pat, std::string& maskOut);
    static uintptr_t SearchInRange(const uint8_t* data, size_t size,
                                   const uint8_t* pattern, const char* mask,
                                   size_t patLen);
};
```

Требования к `PatternScanner.cpp`:
- `CreateToolhelp32Snapshot` + `Module32FirstW`/`Module32NextW` для перечисления модулей.
- `ReadProcessMemory` НЕ использовать — работаем как инжектированная DLL, прямой доступ к памяти.
- `VirtualQuery` для проверки доступности страниц (`MEM_COMMIT`, `PAGE_*` без `GUARD`/`NOACCESS`).
- Поддержка wildcard `?` и `??` (одинаковое поведение).
- Парсинг IDA-паттерна через `std::istringstream` + `std::stoi(..., 16)`.

---

## БЛОК 4 — ТРЕКЕР ВЫЗОВОВ (MuTrackerDLL/CallTracer.h + .cpp)

```cpp
#pragma once
#include "../Shared/SharedStructs.h"
#include "HookEngine.h"
#include <atomic>
#include <thread>

class CallTracer {
public:
    static CallTracer& Get();

    // Инициализация: подключение к SharedMemory
    bool Initialize(HANDLE hSharedMem, SharedMemHeader* pHeader);

    // Начать трассировку: установить хуки на найденные функции
    bool StartTracing(const std::vector<uintptr_t>& targets);

    // Остановить трассировку
    void StopTracing();

    // Обработчик вызова (вызывается из HookEngine)
    void OnFunctionCall(uintptr_t funcAddress, uintptr_t callerAddress,
                        uintptr_t* stackArgs, uint32_t argCount);

    // Запись в кольцевой буфер SharedMemory
    bool WriteRecord(const FunctionCallRecord& record);

    uint64_t GetTotalCalls() const { return m_totalCalls.load(); }

private:
    CallTracer() = default;

    SharedMemHeader*    m_pHeader   = nullptr;
    uint8_t*            m_pBuffer   = nullptr;
    std::atomic<uint64_t> m_totalCalls{ 0 };
    std::atomic<bool>   m_tracing{ false };

    // Кэш: address → symbolName (чтобы не форматировать каждый раз)
    std::unordered_map<uintptr_t, std::string> m_symbolCache;
    std::mutex m_cacheMutex;

    std::string ResolveSymbol(uintptr_t address);
};
```

---

## БЛОК 5 — ДВИЖОК ДИЗАССЕМБЛИРОВАНИЯ (MuTrackerDLL/DisasmEngine.h + .cpp)

**Важно:** Использовать **hde32/hde64** — минималистичный дизассемблер, состоящий из ОДНОГО `.h` и ОДНОГО `.c` файла. Не требует сборки внешних проектов. Встроить исходники напрямую в проект.

Источник: `https://github.com/leo-yuriev/hde` (или embedded inline).

```cpp
#pragma once
#include <cstdint>
#include <cstddef>

struct InstrInfo {
    size_t      length;         // Длина инструкции в байтах
    bool        isCall;         // CALL rel32 / CALL r/m
    bool        isJmp;          // JMP rel32 / JMP r/m
    bool        isRet;          // RET / RETN
    bool        isRelative;     // Инструкция с относительным операндом
    uintptr_t   absoluteTarget; // Абсолютный адрес цели (если isRelative)
    uint8_t     opcode[4];
};

class DisasmEngine {
public:
    // Декодировать одну инструкцию
    static InstrInfo Decode(uintptr_t address);

    // Посчитать минимум N байт пролога (целое число инструкций)
    static size_t GetPrologSize(uintptr_t address, size_t minBytes);

    // Проверить, содержит ли N байт пролога RIP-relative адресацию (x64)
    static bool HasRipRelative(uintptr_t address, size_t prologSize);

    // Исправить RIP-relative инструкции в скопированном прологе
    static void FixRipRelative(uint8_t* dest, uintptr_t origAddress,
                                uintptr_t newAddress, size_t size);
};
```

Встрой `hde32.h` / `hde32.c` и `hde64.h` / `hde64.c` напрямую — предоставь полный исходный код этих файлов, не ссылки.

---

## БЛОК 6 — D3D9 ОВЕРЛЕЙ (MuTrackerDLL/Overlay.h + .cpp)

MuOnline использует DirectX 9. Реализуй оверлей через перехват `IDirect3DDevice9::EndScene`.

```cpp
#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <d3d9.h>
#pragma comment(lib, "d3d9.lib")
#include <string>
#include <vector>

struct OverlayLine {
    std::string text;
    COLORREF    color;
};

class D3D9Overlay {
public:
    static D3D9Overlay& Get();

    // Найти D3D9 Device через создание временного окна
    bool Initialize();

    // Установить хук на EndScene через VTable
    bool HookEndScene();

    void Shutdown();

    // Добавить строку в оверлей (thread-safe)
    void AddLine(const std::string& text, COLORREF color = 0x00FFFFFF);
    void ClearLines();

    bool IsVisible() const { return m_visible; }
    void ToggleVisible() { m_visible = !m_visible; }

private:
    D3D9Overlay() = default;

    // VTable hook: EndScene
    static HRESULT WINAPI Hooked_EndScene(IDirect3DDevice9* pDevice);
    static HRESULT(WINAPI* Original_EndScene)(IDirect3DDevice9*);

    void RenderOverlay(IDirect3DDevice9* pDevice);
    void DrawText_D3D9(IDirect3DDevice9* pDevice, int x, int y,
                       const std::string& text, COLORREF color);

    IDirect3DDevice9*       m_pDevice   = nullptr;
    ID3DXFont*              m_pFont     = nullptr;  // d3dx9.lib
    bool                    m_initialized = false;
    volatile bool           m_visible   = true;

    std::vector<OverlayLine> m_lines;
    std::mutex               m_linesMutex;

    // Для нахождения VTable: временное окно + D3D9 device
    static IDirect3DDevice9* CreateDummyDevice(HWND hwnd);
};
```

**pragma comment(lib) обязательны:**
```cpp
#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "d3dx9.lib")
```

Примечание: `d3dx9.lib` входит в **DirectX SDK (June 2010)** — укажи в промте, что он должен быть установлен. Путь к SDK добавить в `VC++ Directories` проекта.

Альтернатива без D3DX: реализовать рендеринг текста через `DrawText` на GDI поверх `GetDC(hwnd)` — менее предпочтительно, но не требует DXSDK.

---

## БЛОК 7 — DLL MAIN (MuTrackerDLL/dllmain.cpp)

```cpp
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include "HookEngine.h"
#include "PatternScanner.h"
#include "CallTracer.h"
#include "Overlay.h"
#include "../Shared/SharedStructs.h"

// Форвард-деклы
static void InitTrackerThread();
static DWORD WINAPI TrackerMain(LPVOID lpParam);
static void Cleanup();

static HANDLE  g_hSharedMem  = nullptr;
static void*   g_pSharedView  = nullptr;
static HANDLE  g_hWorkerThread = nullptr;
static bool    g_initialized   = false;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL);
        // Запустить init в отдельном потоке, чтобы не блокировать LoaderLock
        g_hWorkerThread = CreateThread(nullptr, 0, TrackerMain, hinstDLL, 0, nullptr);
        break;

    case DLL_PROCESS_DETACH:
        if (lpvReserved == nullptr) {  // Явная выгрузка (FreeLibrary)
            Cleanup();
        }
        break;
    }
    return TRUE;
}

static DWORD WINAPI TrackerMain(LPVOID lpParam) {
    // 1. Подключиться к SharedMemory, созданной лоадером
    g_hSharedMem = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, MUTRACKER_SHMEM);
    if (!g_hSharedMem) {
        // Лоадер не запущен — работаем автономно (лог в файл)
    }

    if (g_hSharedMem) {
        g_pSharedView = MapViewOfFile(g_hSharedMem, FILE_MAP_ALL_ACCESS, 0, 0, SHMEM_SIZE);
        auto* header = static_cast<SharedMemHeader*>(g_pSharedView);
        header->injectedPid = GetCurrentProcessId();
        header->dllReady = true;

        CallTracer::Get().Initialize(g_hSharedMem,
            static_cast<SharedMemHeader*>(g_pSharedView));
    }

    // 2. Просканировать main.exe
    auto modules = PatternScanner::GetLoadedModules();

    // 3. Найти стандартные паттерны MuOnline
    // Эти паттерны — примеры. ИИ должен сгенерировать реальные для версии Season 6+
    std::vector<uintptr_t> targets;
    const char* muPatterns[] = {
        "55 8B EC 83 EC ? 56 57 8B F9",   // PlayerMove / EntityUpdate
        "55 8B EC 53 8B 5D 08 56 8B 75",  // SkillAttack
        "55 8B EC 81 EC ? ? ? ? A1",      // RenderFrame
        nullptr
    };

    for (int i = 0; muPatterns[i] != nullptr; ++i) {
        auto result = PatternScanner::FindFirst("main.exe", muPatterns[i]);
        if (result.address != 0) {
            targets.push_back(result.address);
        }
    }

    // 4. Запустить трассировку
    CallTracer::Get().StartTracing(targets);

    // 5. Инициализировать D3D9 Overlay
    D3D9Overlay::Get().Initialize();
    D3D9Overlay::Get().HookEndScene();

    g_initialized = true;

    // 6. Главный цикл: горячая клавиша INSERT = toggle оверлей, DELETE = выгрузить
    while (true) {
        if (GetAsyncKeyState(VK_INSERT) & 0x8000) {
            D3D9Overlay::Get().ToggleVisible();
            Sleep(300);
        }
        if (GetAsyncKeyState(VK_DELETE) & 0x8000) {
            break;
        }
        Sleep(50);
    }

    Cleanup();
    FreeLibraryAndExitThread(static_cast<HMODULE>(lpParam), 0);
    return 0;
}

static void Cleanup() {
    CallTracer::Get().StopTracing();
    HookEngine::Get().RemoveAll();
    D3D9Overlay::Get().Shutdown();

    if (g_pSharedView) {
        auto* header = static_cast<SharedMemHeader*>(g_pSharedView);
        header->dllReady = false;
        UnmapViewOfFile(g_pSharedView);
        g_pSharedView = nullptr;
    }
    if (g_hSharedMem) {
        CloseHandle(g_hSharedMem);
        g_hSharedMem = nullptr;
    }
}
```

---

## БЛОК 8 — ИНЖЕКТОР (MuTrackerLoader/InjectorEngine.h + .cpp)

```cpp
#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include "../Shared/SharedStructs.h"

class InjectorEngine {
public:
    // Найти процесс по имени (все сессии)
    static DWORD FindProcess(const std::wstring& processName);

    // Найти окно по частичному заголовку
    static HWND  FindGameWindow(const std::wstring& titleSubstring = L"MU");

    // Инжектировать DLL через CreateRemoteThread + LoadLibraryW
    static bool InjectDLL(DWORD pid, const std::wstring& dllPath);

    // Выгрузить DLL через CreateRemoteThread + FreeLibrary
    static bool EjectDLL(DWORD pid, const std::wstring& dllName);

    // Проверить, инжектирована ли DLL уже
    static bool IsDllInjected(DWORD pid, const std::wstring& dllName);

    // Создать/открыть SharedMemory для IPC
    static HANDLE CreateSharedMemory(SharedMemHeader** ppHeader);

    // Получить список модулей процесса
    static std::vector<ModuleInfo> GetProcessModules(DWORD pid);

    // Получить привилегию SeDebugPrivilege
    static bool EnableDebugPrivilege();
};
```

Реализация `InjectorEngine.cpp`:
- `CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32"), "LoadLibraryW"), lpBaseAddress, 0, NULL)`.
- Выделить память под путь к DLL: `VirtualAllocEx` + `WriteProcessMemory`.
- Освободить после инжекции: `VirtualFreeEx`.
- Обработка ошибок: каждый WinAPI вызов проверяется, `GetLastError()` логируется.
- `EnableDebugPrivilege`: `OpenProcessToken` + `AdjustTokenPrivileges`.

---

## БЛОК 9 — ГЛАВНОЕ ОКНО ЛОАДЕРА (MuTrackerLoader/MainWindow.h + .cpp)

Реализуй нативное Win32 окно (НЕ MFC, НЕ WTL — чистый Win32 API):

**Элементы окна:**
```
[MuOnline Tracker v1.0]
─────────────────────────────────────────────────
Процесс:  [main.exe    ] [🔍 Найти] Статус: ● ПИД: 12345
DLL:      [C:\...\MuTrackerDLL.dll ] [📂]

[  ▶ Инжектировать  ]  [  ■ Выгрузить  ]  [  ⚙ Настройки  ]
─────────────────────────────────────────────────
Функций перехвачено: 12   Вызовов всего: 847,291   Dropped: 0
─────────────────────────────────────────────────
[  ListView: Offset | Address | Name | Calls/sec | Total | Thread  ]
0x0052A3F0  0x004523F0  PlayerMove      847/s    12,341    1234
0x00489B20  0x00389B20  AttackCalc       12/s       421    1234
0x006C1440  0x005C1440  RenderEntity   3201/s   482,091    5678
─────────────────────────────────────────────────
[ Лог: .............................................................. ]
[  💾 Экспорт CSV  ]  [  🗑 Очистить  ]  [  ⏸ Пауза  ]
```

**Controls (Win32 API):**
- `HWND hEdit_Process` — `CreateWindowExW(... "EDIT" ...)`.
- `HWND hBtn_Find` — кнопка поиска процесса.
- `HWND hListView` — `WC_LISTVIEW` с `LVS_REPORT | LVS_SORTASCENDING`.
- `HWND hEdit_Log` — многострочный `ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL`.
- Статус-бар через `CreateStatusWindowW`.

**Таймер обновления:**
- `SetTimer(hWnd, 1, 500, NULL)` — обновление ListView каждые 500 мс.
- В `WM_TIMER`: читать SharedMemory, обновить `LVM_SETITEM` строки.

**Экспорт CSV:**
- Открыть `OPENFILENAMEW` диалог → `GetSaveFileNameW`.
- Записать через `_wfopen_s` + `fwprintf`.

---

## БЛОК 10 — ПРОЕКТНЫЕ ФАЙЛЫ (.vcxproj)

### MuTrackerDLL.vcxproj — требования:

```xml
<!-- Критические настройки -->
<ConfigurationType>DynamicLibrary</ConfigurationType>
<PlatformToolset>v142</PlatformToolset>

<!-- Win32 Config -->
<TargetMachine>MachineX86</TargetMachine>
<AdditionalIncludeDirectories>
  $(ProjectDir)..\Shared;
  $(DXSDK_DIR)Include;
  %(AdditionalIncludeDirectories)
</AdditionalIncludeDirectories>
<AdditionalLibraryDirectories>
  $(DXSDK_DIR)Lib\x86;
  %(AdditionalLibraryDirectories)
</AdditionalLibraryDirectories>

<!-- x64 Config -->
<TargetMachine>MachineX64</TargetMachine>
<AdditionalLibraryDirectories>
  $(DXSDK_DIR)Lib\x64;
</AdditionalLibraryDirectories>

<!-- Оба конфига -->
<RuntimeLibrary>MultiThreaded</RuntimeLibrary>           <!-- Release -->
<RuntimeLibrary>MultiThreadedDebug</RuntimeLibrary>      <!-- Debug -->
<LanguageStandard>stdcpp17</LanguageStandard>
<CharacterSet>Unicode</CharacterSet>
<DefinitionFile>MuTrackerDLL.def</DefinitionFile>
```

### MuTrackerDLL.def:
```
LIBRARY MuTrackerDLL
EXPORTS
    GetTrackerVersion
```

### MuTrackerLoader.vcxproj — требования:
```xml
<ConfigurationType>Application</ConfigurationType>
<SubSystem>Windows</SubSystem>  <!-- НЕ Console -->
<EntryPointSymbol>wWinMainCRTStartup</EntryPointSymbol>
```

---

## БЛОК 11 — КРИТИЧЕСКИЕ ПРАВИЛА КОМПИЛЯЦИИ

Каждая единица трансляции (.cpp файл) ОБЯЗАНА:

### Заголовок каждого .cpp файла:
```cpp
// Этот блок — ПЕРВЫЕ строки КАЖДОГО .cpp файла
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
```

### Обязательные pragma comment(lib):
```cpp
// HookEngine.cpp
#pragma comment(lib, "ntdll.lib")

// Overlay.cpp
#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "d3dx9.lib")

// InjectorEngine.cpp
#pragma comment(lib, "advapi32.lib")  // AdjustTokenPrivileges

// PatternScanner.cpp
#pragma comment(lib, "psapi.lib")     // GetModuleInformation (если используется)
```

### Запрещённые конструкции (вызывают ошибки в VS2019):
```
❌ std::format(...)           → использовать sprintf_s / swprintf_s
❌ #include <format>          → не существует в C++17
❌ co_await / co_yield        → C++20
❌ [[likely]] / [[unlikely]]  → C++20
❌ requires / concept         → C++20
❌ std::span (частично)       → только C++20 полная поддержка
❌ designated initializers    → C++20
❌ __builtin_* функции        → GCC/Clang, не MSVC
✅ _NODISCARD → использовать [[nodiscard]]
✅ Для форматирования строк → sprintf_s, swprintf_s, std::ostringstream
✅ Для thread_local переменных → правильно, поддерживается
```

### Обработка предупреждений:
```cpp
// Подавить конкретные предупреждения где необходимо:
#pragma warning(push)
#pragma warning(disable: 4100)  // unreferenced formal parameter
#pragma warning(disable: 4201)  // nameless struct/union
#pragma warning(disable: 4996)  // deprecated CRT functions
// ... код ...
#pragma warning(pop)
```

---

## БЛОК 12 — IPC ЧЕРЕЗ NAMED PIPE (опционально, для расширенного взаимодействия)

```cpp
// Shared/IPC_Protocol.h
#pragma once
#include <Windows.h>
#include <cstdint>

#define PIPE_BUFFER_SIZE 65536

enum class IpcCommand : uint32_t {
    Ping            = 0x01,
    StartTrace      = 0x02,
    StopTrace       = 0x03,
    AddHookByOffset = 0x04,
    RemoveHook      = 0x05,
    GetStats        = 0x06,
    SetFilter       = 0x07,
};

#pragma pack(push, 1)
struct IpcMessage {
    uint32_t    magic;      // 0xMUTR
    IpcCommand  command;
    uint32_t    payloadSize;
    uint8_t     payload[1]; // flexible
};

struct IpcResponse {
    uint32_t    magic;      // 0xMUTR
    uint32_t    status;     // 0 = OK
    uint32_t    payloadSize;
    uint8_t     payload[1];
};
#pragma pack(pop)

class PipeServer {
public:
    bool Start(const wchar_t* pipeName = MUTRACKER_PIPE_NAME);
    void Stop();
private:
    static DWORD WINAPI PipeThread(LPVOID lpParam);
    HANDLE m_hPipe = INVALID_HANDLE_VALUE;
    HANDLE m_hThread = nullptr;
    volatile bool m_running = false;
};

class PipeClient {
public:
    bool Connect(const wchar_t* pipeName = MUTRACKER_PIPE_NAME);
    bool SendCommand(IpcCommand cmd, const void* payload = nullptr, uint32_t size = 0);
    bool ReadResponse(IpcResponse* pResp, uint32_t maxSize);
    void Disconnect();
private:
    HANDLE m_hPipe = INVALID_HANDLE_VALUE;
};
```

---

## БЛОК 13 — КОНФИГУРАЦИОННЫЙ ФАЙЛ (config.json)

```json
{
  "_version": "1.0.2",
  "_comment": "MuOnline Tracker Configuration",

  "target": {
    "process_name":       "main.exe",
    "window_title":       "MU",
    "auto_attach":        true,
    "reconnect_delay_ms": 3000,
    "require_window":     true
  },

  "injection": {
    "dll_path":           "MuTrackerDLL.dll",
    "method":             "LoadLibraryW",
    "require_debug_priv": true
  },

  "hooks": {
    "engine":     "inline",
    "auto_scan":  true,
    "scan_depth": "full",

    "known_patterns": [
      { "name": "PlayerMove",      "pattern": "55 8B EC 83 EC ? 56 57 8B F9",     "enabled": true  },
      { "name": "AttackCalc",      "pattern": "55 8B EC 53 8B 5D 08 56 8B 75 0C", "enabled": true  },
      { "name": "RenderFrame",     "pattern": "55 8B EC 83 E4 F8 81 EC ? ? ? ?",  "enabled": true  },
      { "name": "NetworkSend",     "pattern": "55 8B EC 8B 45 08 85 C0 74",        "enabled": false },
      { "name": "NetworkRecv",     "pattern": "55 8B EC 83 EC ? 8B 45 08 8B 4D",  "enabled": false }
    ],

    "manual_offsets": []
  },

  "filter": {
    "include_modules":        ["main.exe"],
    "min_calls_per_second":   0,
    "capture_args":           true,
    "arg_count":              4,
    "capture_caller":         true,
    "capture_thread_id":      true
  },

  "overlay": {
    "enabled":            true,
    "toggle_key":         "INSERT",
    "unload_key":         "DELETE",
    "max_display_lines":  20,
    "update_interval_ms": 100,
    "font_size":          14,
    "position_x":         10,
    "position_y":         10,
    "alpha":              200
  },

  "logging": {
    "enabled":          true,
    "file_path":        "mutracker_%date%.log",
    "format":           "text",
    "max_file_size_mb": 100,
    "rotate_on_start":  true
  },

  "ipc": {
    "use_shared_memory": true,
    "use_named_pipe":    false,
    "shmem_size_mb":     4
  }
}
```

---

## БЛОК 14 — ПОРЯДОК ГЕНЕРАЦИИ КОДА

Генерируй файлы В СЛЕДУЮЩЕМ ПОРЯДКЕ — каждый последующий зависит от предыдущего:

```
Шаг 1:  Shared/SharedStructs.h          ← без зависимостей
Шаг 2:  Shared/IPC_Protocol.h           ← зависит от SharedStructs.h
Шаг 3:  hde32.h + hde32.c               ← встроенный дизассемблер, без зависимостей
Шаг 4:  hde64.h + hde64.c               ← аналогично для x64
Шаг 5:  MuTrackerDLL/DisasmEngine.h     ← зависит от hde32/hde64
Шаг 6:  MuTrackerDLL/DisasmEngine.cpp
Шаг 7:  MuTrackerDLL/MemoryUtils.h      ← базовые операции с памятью
Шаг 8:  MuTrackerDLL/MemoryUtils.cpp
Шаг 9:  MuTrackerDLL/PatternScanner.h
Шаг 10: MuTrackerDLL/PatternScanner.cpp
Шаг 11: MuTrackerDLL/HookEngine.h
Шаг 12: MuTrackerDLL/HookEngine.cpp     ← зависит от DisasmEngine + MemoryUtils
Шаг 13: MuTrackerDLL/CallTracer.h       ← зависит от HookEngine
Шаг 14: MuTrackerDLL/CallTracer.cpp
Шаг 15: MuTrackerDLL/Overlay.h
Шаг 16: MuTrackerDLL/Overlay.cpp        ← зависит от d3d9.h, HookEngine
Шаг 17: MuTrackerDLL/dllmain.cpp        ← зависит от всего выше
Шаг 18: MuTrackerLoader/InjectorEngine.h
Шаг 19: MuTrackerLoader/InjectorEngine.cpp
Шаг 20: MuTrackerLoader/TraceViewer.h
Шаг 21: MuTrackerLoader/TraceViewer.cpp ← читает SharedMemory
Шаг 22: MuTrackerLoader/MainWindow.h
Шаг 23: MuTrackerLoader/MainWindow.cpp  ← главное Win32 окно
Шаг 24: MuTrackerLoader/main.cpp        ← WinMain точка входа
Шаг 25: MuTrackerDLL/MuTrackerDLL.vcxproj
Шаг 26: MuTrackerLoader/MuTrackerLoader.vcxproj
Шаг 27: MuTracker.sln
```

---

## БЛОК 15 — ФИНАЛЬНЫЙ ЧЕКЛИСТ ПЕРЕД ВЫДАЧЕЙ КОДА

Перед выдачей каждого файла ИИ обязан проверить:

- [ ] Все `#include` файлы существуют или явно объявлены в этом же проекте.
- [ ] Нет функций из C++20 (`std::format`, `std::ranges`, `std::span` без заголовка).
- [ ] Все типы Windows (`DWORD`, `HANDLE`, `HWND`) используют после `#include <Windows.h>`.
- [ ] Для x86: `__asm` блоки корректны для MSVC (не AT&T синтаксис).
- [ ] Для x64: `__asm` не используется — только intrinsics или отдельный `.asm` (MASM).
- [ ] `pragma comment(lib, ...)` присутствует для всех используемых системных библиотек.
- [ ] Нет `using namespace std;` в заголовочных файлах.
- [ ] Все forward declarations корректны.
- [ ] Singleton-паттерн через `static T& Get()` — thread-safe через `std::call_once` или `static` локальная переменная (Meyers Singleton, безопасно в C++11+).
- [ ] `VirtualProtect` вызывается парно (save old → set RWX → write → restore old).
- [ ] `HANDLE` ресурсы закрыты в деструкторах / `Cleanup()` функциях.
- [ ] Нет raw `new/delete` без RAII обёрток там, где возможны исключения.

---

## ОЖИДАЕМЫЙ РЕЗУЛЬТАТ

После выполнения промта должен быть получен полный исходный код проекта, который:

1. **Компилируется в VS2019** (v142 toolset) без ошибок в конфигурациях: `Debug|Win32`, `Release|Win32`, `Debug|x64`, `Release|x64`.
2. **Инжектируется** в `main.exe` MuOnline и перехватывает функции в реальном времени.
3. **Отображает оверлей** поверх игры (D3D9 EndScene hook) с текущей статистикой.
4. **Передаёт данные** в Loader через SharedMemory — таблица обновляется каждые 500 мс.
5. **Горячие клавиши**: `INSERT` — показать/скрыть оверлей, `DELETE` — безопасно выгрузить DLL.
6. **Экспортирует** лог вызовов в `.csv` из Loader.
7. **Не крашит** игру при инжекции, трассировке и выгрузке.
