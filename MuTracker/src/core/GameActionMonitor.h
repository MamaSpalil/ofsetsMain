/*
 * GameActionMonitor.h - Complete Game Action Monitoring System
 *
 * Monitors ALL actions in the MuOnline main.exe game client:
 *   - Keyboard input (all keys)
 *   - HP / MP / Level / Zen changes
 *   - Player kills and deaths
 *   - Map transitions (teleport / warp)
 *   - Inventory / shop / trade actions
 *   - Chat messages
 *   - Skill usage
 *   - Party / guild events
 *   - Combat events (damage dealt/received)
 *   - Mouse actions (clicks, movement)
 *
 * For each detected action the monitor:
 *   1. Logs the action description
 *   2. Searches for offset   -> logs "offset found"
 *   3. Searches for function -> logs "function found"
 *   4. Searches for variable -> logs "variable found"
 *   5. Searches for module   -> logs "module found"
 *
 * The results are written to the persistent database file
 * (MuTrackerDB.csv) which is fully rewritten on every launch.
 *
 * Compile: MSVC 2019+ (v142), C++17, x86
 */

#ifndef MUTRACKER_GAME_ACTION_MONITOR_H
#define MUTRACKER_GAME_ACTION_MONITOR_H

#include <cstdint>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <functional>
#include <unordered_map>

#ifdef _WIN32
#include <windows.h>
#endif

namespace MuTracker {

/* Forward declarations */
class MemoryUtils;
class PatternScanner;

/* ================================================================== */
/*  Game Action Types                                                   */
/* ================================================================== */

enum class GameActionType : uint32_t {
    /* Input */
    KeyPress        = 0x0001,
    KeyRelease      = 0x0002,
    MouseClick      = 0x0003,
    MouseMove       = 0x0004,

    /* Character stats */
    HPChanged       = 0x0010,
    MPChanged       = 0x0011,
    LevelUp         = 0x0012,
    ExpGained       = 0x0013,
    ZenChanged      = 0x0014,
    StatPointGained = 0x0015,
    StrChanged      = 0x0016,
    AgiChanged      = 0x0017,
    VitChanged      = 0x0018,
    EneChanged      = 0x0019,

    /* Combat */
    PlayerKill      = 0x0020,
    PlayerDeath     = 0x0021,
    MonsterKill     = 0x0022,
    DamageDealt     = 0x0023,
    DamageReceived  = 0x0024,
    SkillUsed       = 0x0025,
    BuffApplied     = 0x0026,

    /* World */
    MapChanged      = 0x0030,
    MapListOpened   = 0x0031,
    TeleportUsed    = 0x0032,

    /* Social */
    ChatMessage     = 0x0040,
    PartyJoined     = 0x0041,
    PartyLeft       = 0x0042,
    GuildAction     = 0x0043,
    TradeStarted    = 0x0044,
    TradeCompleted  = 0x0045,

    /* Inventory */
    ItemPickedUp    = 0x0050,
    ItemDropped     = 0x0051,
    ItemEquipped    = 0x0052,
    ItemUnequipped  = 0x0053,
    ShopOpened      = 0x0054,
    ShopClosed      = 0x0055,
    ItemBought      = 0x0056,
    ItemSold        = 0x0057,

    /* UI / Windows */
    CharWindowOpened = 0x0060,
    InventoryOpened  = 0x0061,
    SkillTreeOpened  = 0x0062,
    QuestLogOpened   = 0x0063,
    MiniMapToggled   = 0x0064,
    MenuOpened       = 0x0065,

    /* Connection */
    ServerConnected    = 0x0070,
    ServerDisconnected = 0x0071,
    LoginSuccess       = 0x0072,
    CharacterSelected  = 0x0073,
    SceneChanged       = 0x0074,

    /* Generic */
    Unknown         = 0xFFFF
};

/* ================================================================== */
/*  Lookup Result - what was found for each action                     */
/* ================================================================== */

struct ActionLookupResult {
    bool        offsetFound;
    uintptr_t   offset;
    bool        functionFound;
    uintptr_t   functionAddress;
    char        functionName[128];
    bool        variableFound;
    uintptr_t   variableAddress;
    char        variableName[128];
    bool        moduleFound;
    char        moduleName[64];
    uintptr_t   moduleBase;
};

/* ================================================================== */
/*  Game Action Event                                                   */
/* ================================================================== */

struct GameActionEvent {
    GameActionType  type;
    uint64_t        timestamp;          /* QPC value */
    char            description[512];   /* Human-readable description */
    ActionLookupResult lookup;          /* Offset/func/var/module */

    /* Extra data depending on type */
    union {
        struct { uint32_t vkCode; bool isDown; }  key;
        struct { int32_t  oldVal; int32_t newVal; } stat;
        struct { uint32_t mapId; char mapName[64]; } map;
        struct { char targetName[64]; uint32_t damage; } combat;
        struct { uint32_t amount; }                 currency;
        struct { uint32_t x; uint32_t y; uint32_t button; } mouse;
    } data;
};

/* ================================================================== */
/*  Known MuOnline Memory Offsets (.data section relative to base)     */
/*  These are common offsets found in MuOnline Season 6 clients.       */
/*  Actual addresses = ImageBase (0x00400000) + offset                 */
/* ================================================================== */

struct MuGameOffsets {
    /* Character stats (relative to .data base 0x007B3000) */
    uintptr_t   characterHP;        /* Current HP */
    uintptr_t   characterMaxHP;     /* Max HP */
    uintptr_t   characterMP;        /* Current MP */
    uintptr_t   characterMaxMP;     /* Max MP */
    uintptr_t   characterLevel;     /* Character level */
    uintptr_t   characterExp;       /* Experience points */
    uintptr_t   characterZen;       /* Zen (currency) */
    uintptr_t   characterStr;       /* Strength */
    uintptr_t   characterAgi;       /* Agility */
    uintptr_t   characterVit;       /* Vitality */
    uintptr_t   characterEne;       /* Energy */
    uintptr_t   characterName;      /* Player name string */

    /* Game state */
    uintptr_t   currentScene;       /* Current scene/screen ID */
    uintptr_t   currentMapId;       /* Current map ID */
    uintptr_t   isLoggedIn;         /* Login state flag */
    uintptr_t   isInGame;           /* In-game state flag */
    uintptr_t   serverIp;           /* Connected server IP */

    /* Combat */
    uintptr_t   targetObjectId;     /* Current target object */
    uintptr_t   killCount;          /* PvP kill count */
    uintptr_t   deathCount;         /* Death count */

    /* UI state */
    uintptr_t   inventoryOpen;      /* Inventory window state */
    uintptr_t   charWindowOpen;     /* Character window state */
    uintptr_t   skillTreeOpen;      /* Skill tree window state */
    uintptr_t   mapListOpen;        /* Map selection list state */
    uintptr_t   chatInputActive;    /* Chat input active flag */

    /* Position */
    uintptr_t   playerX;            /* Player X coordinate */
    uintptr_t   playerY;            /* Player Y coordinate */
};

/* ================================================================== */
/*  Action Definition (loaded from reference files)                    */
/* ================================================================== */

struct ActionDefinition {
    char        sectionName[128];   /* Section name from file */
    char        actionId[32];       /* e.g. "9.001" */
    char        description[512];   /* Full description text */
    uint32_t    sectionNum;         /* Section number */
    uint32_t    entryNum;           /* Entry number within section */
};

/* ================================================================== */
/*  Database Entry (for CSV output)                                    */
/* ================================================================== */

struct DatabaseEntry {
    GameActionType  actionType;
    char            actionDescription[256];
    uintptr_t       offset;
    char            functionName[128];
    char            variableName[128];
    char            moduleName[64];
    uint64_t        timestamp;
};

/* ================================================================== */
/*  GameActionMonitor Class                                            */
/* ================================================================== */

class GameActionMonitor {
public:
    GameActionMonitor();
    ~GameActionMonitor();

    /*
     * Initialize the monitor.
     *
     * @param memory        Pointer to memory utils (for reading game memory)
     * @param scanner       Pointer to pattern scanner
     * @param mainBase      Base address of main.exe
     * @param dbFilePath    Path to database file (rewritten each launch)
     * @return              true if initialized
     */
    bool Init(MemoryUtils* memory, PatternScanner* scanner,
              uintptr_t mainBase, const char* dbFilePath = "MuTrackerDB.csv");

    /* Shutdown and flush database */
    void Shutdown();

    /*
     * Load action definitions from the two reference files:
     *   MuOnline_S3E1_Actions_1.02Q_Part1.txt
     *   MuOnline_S3E1_Actions_1.02Q_Part2.txt
     *
     * @param part1Path  Path to Part1 reference file
     * @param part2Path  Path to Part2 reference file
     * @return           Total number of action definitions loaded
     */
    size_t LoadActionDefinitions(const char* part1Path, const char* part2Path);

    /*
     * Check whether the main.exe game window is currently the
     * foreground (active) window. When the game is minimized or
     * another window is in focus, offset search is paused.
     *
     * @return true if main.exe window is in the foreground
     */
    bool IsGameWindowActive() const;

    /*
     * Get the number of loaded action definitions.
     */
    size_t GetActionDefinitionCount() const { return m_actionDefs.size(); }

    /*
     * Poll game state and detect changes.
     * Should be called from the monitoring loop (~100ms interval).
     */
    void Update();

    /*
     * Check keyboard state and detect key presses.
     * Should be called frequently (every ~50ms).
     */
    void CheckKeyboard();

    /*
     * Get the total number of tracked events.
     */
    uint32_t GetEventCount() const { return m_eventCount; }

    /*
     * Get recent events (thread-safe copy).
     *
     * @param maxEvents Maximum events to return
     * @return          Recent game action events
     */
    std::vector<GameActionEvent> GetRecentEvents(size_t maxEvents = 50) const;

    /*
     * Flush all events to the database file.
     * The file is fully rewritten with all collected data.
     */
    void FlushDatabase();

    /*
     * Get the game offsets structure (for external use).
     */
    const MuGameOffsets& GetOffsets() const { return m_offsets; }

    /*
     * Try to auto-detect game offsets by scanning .data section.
     * Populates m_offsets with found addresses.
     */
    void AutoDetectOffsets();

private:
    MemoryUtils*        m_memory;
    PatternScanner*     m_scanner;
    uintptr_t           m_mainBase;
    bool                m_initialized;
    std::string         m_dbFilePath;
    mutable std::mutex  m_mutex;
    std::atomic<uint32_t> m_eventCount;

    /* Game offsets */
    MuGameOffsets       m_offsets;

    /* Previous state for change detection */
    struct GameState {
        int32_t     hp;
        int32_t     maxHp;
        int32_t     mp;
        int32_t     maxMp;
        int32_t     level;
        uint32_t    exp;
        uint32_t    zen;
        int32_t     str;
        int32_t     agi;
        int32_t     vit;
        int32_t     ene;
        uint32_t    currentScene;
        uint32_t    currentMapId;
        uint32_t    isLoggedIn;
        uint32_t    isInGame;
        uint32_t    killCount;
        uint32_t    deathCount;
        uint32_t    inventoryOpen;
        uint32_t    charWindowOpen;
        uint32_t    skillTreeOpen;
        uint32_t    mapListOpen;
        uint32_t    chatInputActive;
        float       playerX;
        float       playerY;
        char        playerName[64];
        bool        initialized;
    };

    GameState           m_prevState;
    GameState           m_currState;

    /* Keyboard state tracking */
    uint8_t             m_prevKeyState[256];

    /* Event history */
    std::vector<GameActionEvent> m_events;
    static const size_t MAX_EVENTS = 10000;

    /* Database entries */
    std::vector<DatabaseEntry>   m_dbEntries;

    /* Action definitions loaded from reference files */
    std::vector<ActionDefinition> m_actionDefs;

    /* Section name to action definition index mapping */
    std::unordered_map<uint32_t, std::string> m_sectionNames;

    /* Cached game window handle for foreground check */
    mutable HWND                m_gameHwnd;
    mutable DWORD               m_gamePid;

    /* ---- Internal methods ---- */

    /* Read current game state from memory */
    void ReadGameState(GameState& state);

    /* Compare states and emit events */
    void DetectChanges();

    /* Perform lookup: find offset, function, variable, module */
    ActionLookupResult PerformLookup(uintptr_t address,
                                      const char* context);

    /* Add event to the log and database */
    void EmitEvent(const GameActionEvent& event);

    /* Log event in the required format */
    void LogAction(const GameActionEvent& event);

    /* Write full database to CSV file */
    void WriteDatabaseCSV();

    /* Get key name for virtual key code */
    static const char* GetKeyName(uint32_t vkCode);

    /* Get action type name */
    static const char* GetActionTypeName(GameActionType type);

    /* Get map name from ID */
    static const char* GetMapName(uint32_t mapId);

    /* Scan .data section for HP/MP/Level/Zen patterns */
    void ScanDataSection();

    /* Parse a single reference file and append to m_actionDefs */
    size_t ParseActionFile(const char* filePath);

    /* Find the best matching action definition for an event */
    const ActionDefinition* FindActionDef(GameActionType type,
                                           const char* context) const;

    /* Find game window by PID (helper for IsGameWindowActive) */
    void CacheGameWindow() const;
};

} /* namespace MuTracker */

#endif /* MUTRACKER_GAME_ACTION_MONITOR_H */
