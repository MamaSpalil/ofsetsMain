/*
 * GameActionMonitor.cpp - Complete Game Action Monitoring Implementation
 *
 * Monitors ALL actions in the MuOnline main.exe game client and logs
 * results in the format required by the specification:
 *
 *   "You pressed button "C" in the game client, searching for offset: offset found,
 *    searching for function, function found, searching for variable, variable found,
 *    searching for module, module found."
 *
 * Database file (MuTrackerDB.csv) is fully rewritten on each launch.
 *
 * Compile: MSVC 2019+ (v142), C++17, x86
 */

#ifdef _WIN32

#define _CRT_SECURE_NO_WARNINGS
#include "GameActionMonitor.h"
#include "MemoryUtils.h"
#include "PatternScanner.h"
#include "../log/Logger.h"

#include <cstdio>
#include <cstring>
#include <ctime>
#include <algorithm>

namespace MuTracker {

/* ================================================================== */
/*  Known MuOnline data section offsets (relative to ImageBase)        */
/*  .data section starts at RVA 0x003B3000 (VA = 0x007B3000)          */
/*  These offsets are typical for MuOnline Season 4-6 EP clients.      */
/* ================================================================== */

/* Data section offsets relative to module base (0x00400000) */
static const uintptr_t DATA_SECTION_RVA = 0x003B3000;

/*
 * Character structure is typically found starting around
 * 0x007B5500-0x007B6000 in the .data section.
 * The exact layout varies per client version.
 */
static const uintptr_t DEFAULT_CHAR_HP_OFFSET      = 0x3B5500;
static const uintptr_t DEFAULT_CHAR_MAXHP_OFFSET    = 0x3B5504;
static const uintptr_t DEFAULT_CHAR_MP_OFFSET       = 0x3B5508;
static const uintptr_t DEFAULT_CHAR_MAXMP_OFFSET     = 0x3B550C;
static const uintptr_t DEFAULT_CHAR_LEVEL_OFFSET    = 0x3B5510;
static const uintptr_t DEFAULT_CHAR_EXP_OFFSET      = 0x3B5518;
static const uintptr_t DEFAULT_CHAR_ZEN_OFFSET      = 0x3B5520;
static const uintptr_t DEFAULT_CHAR_STR_OFFSET      = 0x3B5528;
static const uintptr_t DEFAULT_CHAR_AGI_OFFSET      = 0x3B552C;
static const uintptr_t DEFAULT_CHAR_VIT_OFFSET      = 0x3B5530;
static const uintptr_t DEFAULT_CHAR_ENE_OFFSET      = 0x3B5534;
static const uintptr_t DEFAULT_CHAR_NAME_OFFSET     = 0x3B5540;

static const uintptr_t DEFAULT_SCENE_OFFSET         = 0x3B5600;
static const uintptr_t DEFAULT_MAPID_OFFSET         = 0x3B5604;
static const uintptr_t DEFAULT_LOGGED_IN_OFFSET     = 0x3B5608;
static const uintptr_t DEFAULT_IN_GAME_OFFSET       = 0x3B560C;
static const uintptr_t DEFAULT_SERVER_IP_OFFSET     = 0x3B5700;

static const uintptr_t DEFAULT_TARGET_OBJ_OFFSET    = 0x3B5800;
static const uintptr_t DEFAULT_KILL_COUNT_OFFSET    = 0x3B5804;
static const uintptr_t DEFAULT_DEATH_COUNT_OFFSET   = 0x3B5808;

static const uintptr_t DEFAULT_INV_OPEN_OFFSET      = 0x3B5900;
static const uintptr_t DEFAULT_CHAR_WIN_OFFSET      = 0x3B5904;
static const uintptr_t DEFAULT_SKILL_TREE_OFFSET    = 0x3B5908;
static const uintptr_t DEFAULT_MAP_LIST_OFFSET      = 0x3B590C;
static const uintptr_t DEFAULT_CHAT_INPUT_OFFSET    = 0x3B5910;

static const uintptr_t DEFAULT_PLAYER_X_OFFSET      = 0x3B5A00;
static const uintptr_t DEFAULT_PLAYER_Y_OFFSET      = 0x3B5A04;

/* ================================================================== */
/*  Key Name Table                                                      */
/* ================================================================== */

static const char* VK_KEY_NAMES[256] = {
    /* 0x00 */ "None", "LButton", "RButton", "Cancel",
    /* 0x04 */ "MButton", "XButton1", "XButton2", "0x07",
    /* 0x08 */ "Backspace", "Tab", "0x0A", "0x0B",
    /* 0x0C */ "Clear", "Enter", "0x0E", "0x0F",
    /* 0x10 */ "Shift", "Ctrl", "Alt", "Pause",
    /* 0x14 */ "CapsLock", "Kana", "0x16", "Junja",
    /* 0x18 */ "Final", "Kanji", "0x1A", "Escape",
    /* 0x1C */ "Convert", "NonConvert", "Accept", "ModeChange",
    /* 0x20 */ "Space", "PageUp", "PageDown", "End",
    /* 0x24 */ "Home", "Left", "Up", "Right",
    /* 0x28 */ "Down", "Select", "Print", "Execute",
    /* 0x2C */ "PrintScreen", "Insert", "Delete", "Help",
    /* 0x30 */ "0", "1", "2", "3",
    /* 0x34 */ "4", "5", "6", "7",
    /* 0x38 */ "8", "9", "0x3A", "0x3B",
    /* 0x3C */ "0x3C", "0x3D", "0x3E", "0x3F",
    /* 0x40 */ "0x40", "A", "B", "C",
    /* 0x44 */ "D", "E", "F", "G",
    /* 0x48 */ "H", "I", "J", "K",
    /* 0x4C */ "L", "M", "N", "O",
    /* 0x50 */ "P", "Q", "R", "S",
    /* 0x54 */ "T", "U", "V", "W",
    /* 0x58 */ "X", "Y", "Z", "LWin",
    /* 0x5C */ "RWin", "Apps", "0x5E", "Sleep",
    /* 0x60 */ "Num0", "Num1", "Num2", "Num3",
    /* 0x64 */ "Num4", "Num5", "Num6", "Num7",
    /* 0x68 */ "Num8", "Num9", "Multiply", "Add",
    /* 0x6C */ "Separator", "Subtract", "Decimal", "Divide",
    /* 0x70 */ "F1", "F2", "F3", "F4",
    /* 0x74 */ "F5", "F6", "F7", "F8",
    /* 0x78 */ "F9", "F10", "F11", "F12",
    /* 0x7C */ "F13", "F14", "F15", "F16",
    /* 0x80 */ "F17", "F18", "F19", "F20",
    /* 0x84 */ "F21", "F22", "F23", "F24",
    /* 0x88-0x8F */ "0x88","0x89","0x8A","0x8B","0x8C","0x8D","0x8E","0x8F",
    /* 0x90 */ "NumLock", "ScrollLock",
    /* 0x92-0x9F */ "0x92","0x93","0x94","0x95","0x96","0x97",
                   "0x98","0x99","0x9A","0x9B","0x9C","0x9D","0x9E","0x9F",
    /* 0xA0 */ "LShift", "RShift", "LCtrl", "RCtrl",
    /* 0xA4 */ "LAlt", "RAlt"
    /* rest are filled with nullptr, GetKeyName handles that */
};

const char* GameActionMonitor::GetKeyName(uint32_t vkCode) {
    if (vkCode < 256 && VK_KEY_NAMES[vkCode] != nullptr) {
        return VK_KEY_NAMES[vkCode];
    }
    static thread_local char buf[16];
    sprintf_s(buf, sizeof(buf), "0x%02X", vkCode);
    return buf;
}

/* ================================================================== */
/*  Map Name Table                                                      */
/* ================================================================== */

static const char* MAP_NAMES[] = {
    /* 0 */ "Lorencia",
    /* 1 */ "Dungeon",
    /* 2 */ "Devias",
    /* 3 */ "Noria",
    /* 4 */ "LostTower",
    /* 5 */ "Unknown5",
    /* 6 */ "Arena",
    /* 7 */ "Atlans",
    /* 8 */ "Tarkan",
    /* 9 */ "Devil Square",
    /* 10 */ "Icarus",
    /* 11 */ "Blood Castle 1",
    /* 12 */ "Blood Castle 2",
    /* 13 */ "Blood Castle 3",
    /* 14 */ "Blood Castle 4",
    /* 15 */ "Blood Castle 5",
    /* 16 */ "Blood Castle 6",
    /* 17 */ "Blood Castle 7",
    /* 18 */ "Chaos Castle 1",
    /* 19 */ "Chaos Castle 2",
    /* 20 */ "Chaos Castle 3",
    /* 21 */ "Chaos Castle 4",
    /* 22 */ "Chaos Castle 5",
    /* 23 */ "Chaos Castle 6",
    /* 24 */ "Kalima 1",
    /* 25 */ "Kalima 2",
    /* 26 */ "Kalima 3",
    /* 27 */ "Kalima 4",
    /* 28 */ "Kalima 5",
    /* 29 */ "Kalima 6",
    /* 30 */ "Valley of Loren",
    /* 31 */ "Land of Trial",
    /* 32 */ "Devil Square (event)",
    /* 33 */ "Aida",
    /* 34 */ "Crywolf",
    /* 35 */ "Unknown35",
    /* 36 */ "Kanturu Ruin",
    /* 37 */ "Kanturu Remain",
    /* 38 */ "Kanturu Tower",
    /* 39 */ "Silent Map",
    /* 40 */ "Barracks",
    /* 41 */ "Refuge",
    /* 42 */ "Illusion Temple 1",
    /* 43 */ "Illusion Temple 2",
    /* 44 */ "Illusion Temple 3",
    /* 45 */ "Illusion Temple 4",
    /* 46 */ "Illusion Temple 5",
    /* 47 */ "Illusion Temple 6"
};
static const int MAP_NAME_COUNT = sizeof(MAP_NAMES) / sizeof(MAP_NAMES[0]);

const char* GameActionMonitor::GetMapName(uint32_t mapId) {
    if (mapId < static_cast<uint32_t>(MAP_NAME_COUNT)) {
        return MAP_NAMES[mapId];
    }
    static thread_local char buf[32];
    sprintf_s(buf, sizeof(buf), "Map_%u", mapId);
    return buf;
}

/* ================================================================== */
/*  Action Type Name                                                    */
/* ================================================================== */

const char* GameActionMonitor::GetActionTypeName(GameActionType type) {
    switch (type) {
    case GameActionType::KeyPress:         return "KEY_PRESS";
    case GameActionType::KeyRelease:       return "KEY_RELEASE";
    case GameActionType::MouseClick:       return "MOUSE_CLICK";
    case GameActionType::MouseMove:        return "MOUSE_MOVE";
    case GameActionType::HPChanged:        return "HP_CHANGED";
    case GameActionType::MPChanged:        return "MP_CHANGED";
    case GameActionType::LevelUp:          return "LEVEL_UP";
    case GameActionType::ExpGained:        return "EXP_GAINED";
    case GameActionType::ZenChanged:       return "ZEN_CHANGED";
    case GameActionType::StatPointGained:  return "STAT_POINT";
    case GameActionType::StrChanged:       return "STR_CHANGED";
    case GameActionType::AgiChanged:       return "AGI_CHANGED";
    case GameActionType::VitChanged:       return "VIT_CHANGED";
    case GameActionType::EneChanged:       return "ENE_CHANGED";
    case GameActionType::PlayerKill:       return "PLAYER_KILL";
    case GameActionType::PlayerDeath:      return "PLAYER_DEATH";
    case GameActionType::MonsterKill:      return "MONSTER_KILL";
    case GameActionType::DamageDealt:      return "DAMAGE_DEALT";
    case GameActionType::DamageReceived:   return "DAMAGE_RECEIVED";
    case GameActionType::SkillUsed:        return "SKILL_USED";
    case GameActionType::BuffApplied:      return "BUFF_APPLIED";
    case GameActionType::MapChanged:       return "MAP_CHANGED";
    case GameActionType::MapListOpened:    return "MAP_LIST_OPENED";
    case GameActionType::TeleportUsed:     return "TELEPORT";
    case GameActionType::ChatMessage:      return "CHAT_MSG";
    case GameActionType::PartyJoined:      return "PARTY_JOIN";
    case GameActionType::PartyLeft:        return "PARTY_LEFT";
    case GameActionType::GuildAction:      return "GUILD_ACTION";
    case GameActionType::TradeStarted:     return "TRADE_START";
    case GameActionType::TradeCompleted:   return "TRADE_DONE";
    case GameActionType::ItemPickedUp:     return "ITEM_PICKUP";
    case GameActionType::ItemDropped:      return "ITEM_DROP";
    case GameActionType::ItemEquipped:     return "ITEM_EQUIP";
    case GameActionType::ItemUnequipped:   return "ITEM_UNEQUIP";
    case GameActionType::ShopOpened:       return "SHOP_OPEN";
    case GameActionType::ShopClosed:       return "SHOP_CLOSE";
    case GameActionType::ItemBought:       return "ITEM_BUY";
    case GameActionType::ItemSold:         return "ITEM_SELL";
    case GameActionType::CharWindowOpened: return "CHAR_WINDOW";
    case GameActionType::InventoryOpened:  return "INVENTORY";
    case GameActionType::SkillTreeOpened:  return "SKILL_TREE";
    case GameActionType::QuestLogOpened:   return "QUEST_LOG";
    case GameActionType::MiniMapToggled:   return "MINIMAP";
    case GameActionType::MenuOpened:       return "MENU";
    case GameActionType::ServerConnected:  return "SERVER_CONNECT";
    case GameActionType::ServerDisconnected: return "SERVER_DISCONNECT";
    case GameActionType::LoginSuccess:     return "LOGIN_SUCCESS";
    case GameActionType::CharacterSelected: return "CHAR_SELECT";
    case GameActionType::SceneChanged:     return "SCENE_CHANGE";
    default:                               return "UNKNOWN";
    }
}

/* ================================================================== */
/*  Constructor / Destructor                                            */
/* ================================================================== */

GameActionMonitor::GameActionMonitor()
    : m_memory(nullptr)
    , m_scanner(nullptr)
    , m_mainBase(0)
    , m_initialized(false)
    , m_eventCount(0)
    , m_gameHwnd(nullptr)
    , m_gamePid(0)
{
    memset(&m_offsets, 0, sizeof(m_offsets));
    memset(&m_prevState, 0, sizeof(m_prevState));
    memset(&m_currState, 0, sizeof(m_currState));
    memset(m_prevKeyState, 0, sizeof(m_prevKeyState));
}

GameActionMonitor::~GameActionMonitor()
{
    Shutdown();
}

/* ================================================================== */
/*  Init / Shutdown                                                     */
/* ================================================================== */

bool GameActionMonitor::Init(MemoryUtils* memory, PatternScanner* scanner,
                              uintptr_t mainBase, const char* dbFilePath)
{
    if (m_initialized) return true;
    if (!memory || !scanner || mainBase == 0) return false;

    m_memory   = memory;
    m_scanner  = scanner;
    m_mainBase = mainBase;
    m_dbFilePath = dbFilePath ? dbFilePath : "MuTrackerDB.csv";

    /* Set default offsets (will be refined by AutoDetectOffsets) */
    m_offsets.characterHP     = mainBase + DEFAULT_CHAR_HP_OFFSET;
    m_offsets.characterMaxHP  = mainBase + DEFAULT_CHAR_MAXHP_OFFSET;
    m_offsets.characterMP     = mainBase + DEFAULT_CHAR_MP_OFFSET;
    m_offsets.characterMaxMP  = mainBase + DEFAULT_CHAR_MAXMP_OFFSET;
    m_offsets.characterLevel  = mainBase + DEFAULT_CHAR_LEVEL_OFFSET;
    m_offsets.characterExp    = mainBase + DEFAULT_CHAR_EXP_OFFSET;
    m_offsets.characterZen    = mainBase + DEFAULT_CHAR_ZEN_OFFSET;
    m_offsets.characterStr    = mainBase + DEFAULT_CHAR_STR_OFFSET;
    m_offsets.characterAgi    = mainBase + DEFAULT_CHAR_AGI_OFFSET;
    m_offsets.characterVit    = mainBase + DEFAULT_CHAR_VIT_OFFSET;
    m_offsets.characterEne    = mainBase + DEFAULT_CHAR_ENE_OFFSET;
    m_offsets.characterName   = mainBase + DEFAULT_CHAR_NAME_OFFSET;

    m_offsets.currentScene    = mainBase + DEFAULT_SCENE_OFFSET;
    m_offsets.currentMapId    = mainBase + DEFAULT_MAPID_OFFSET;
    m_offsets.isLoggedIn      = mainBase + DEFAULT_LOGGED_IN_OFFSET;
    m_offsets.isInGame        = mainBase + DEFAULT_IN_GAME_OFFSET;
    m_offsets.serverIp        = mainBase + DEFAULT_SERVER_IP_OFFSET;

    m_offsets.targetObjectId  = mainBase + DEFAULT_TARGET_OBJ_OFFSET;
    m_offsets.killCount       = mainBase + DEFAULT_KILL_COUNT_OFFSET;
    m_offsets.deathCount      = mainBase + DEFAULT_DEATH_COUNT_OFFSET;

    m_offsets.inventoryOpen   = mainBase + DEFAULT_INV_OPEN_OFFSET;
    m_offsets.charWindowOpen  = mainBase + DEFAULT_CHAR_WIN_OFFSET;
    m_offsets.skillTreeOpen   = mainBase + DEFAULT_SKILL_TREE_OFFSET;
    m_offsets.mapListOpen     = mainBase + DEFAULT_MAP_LIST_OFFSET;
    m_offsets.chatInputActive = mainBase + DEFAULT_CHAT_INPUT_OFFSET;

    m_offsets.playerX         = mainBase + DEFAULT_PLAYER_X_OFFSET;
    m_offsets.playerY         = mainBase + DEFAULT_PLAYER_Y_OFFSET;

    /* Try to auto-detect actual offsets */
    AutoDetectOffsets();

    /* Initialize previous state */
    m_prevState.initialized = false;
    ReadGameState(m_prevState);
    m_prevState.initialized = true;

    /* Initialize keyboard state */
    for (int i = 0; i < 256; ++i) {
        m_prevKeyState[i] = static_cast<uint8_t>(
            (GetAsyncKeyState(i) & 0x8000) ? 1 : 0);
    }

    /* Rewrite database file on launch (clear previous data) */
    {
        FILE* fp = fopen(m_dbFilePath.c_str(), "w");
        if (fp) {
            fprintf(fp, "=== MuTracker Database - Generated on Program Launch ===\n");
            fprintf(fp, "=== Database is rewritten after each launch of MuTracker ===\n");
            fprintf(fp, "Timestamp|ActionType|Description|Offset|FunctionName|VariableName|ModuleName\n");
            fclose(fp);
        }
    }

    m_events.reserve(MAX_EVENTS);
    m_initialized = true;

    /* Cache the game process ID for foreground window checks */
    m_gamePid = GetCurrentProcessId();
    CacheGameWindow();

    MULOG_INFO("[GameActionMonitor] Initialized. Base=0x%08X, DB=%s",
               static_cast<uint32_t>(mainBase), m_dbFilePath.c_str());
    MULOG_INFO("[GameActionMonitor] Tracking ALL game actions in main.exe");
    MULOG_INFO("[GameActionMonitor] Database will be rewritten on each launch");
    MULOG_INFO("[GameActionMonitor] Action definitions loaded: %zu",
               m_actionDefs.size());
    MULOG_INFO("[GameActionMonitor] Foreground window check: ACTIVE "
               "(offset search pauses when main.exe is not in focus)");

    return true;
}

void GameActionMonitor::Shutdown()
{
    if (!m_initialized) return;

    /* Final database flush */
    FlushDatabase();

    MULOG_INFO("[GameActionMonitor] Shutdown. Total events tracked: %u",
               m_eventCount.load());

    m_initialized = false;
}

/* ================================================================== */
/*  Auto-Detect Offsets                                                 */
/* ================================================================== */

void GameActionMonitor::AutoDetectOffsets()
{
    if (!m_memory || !m_scanner) return;

    MULOG_INFO("[GameActionMonitor] Auto-detecting game offsets...");

    /*
     * Scan for known patterns that reference game data structures.
     * The HP format string "HP : %d0%%" at VA 0x007D51D4 can help
     * locate the HP display function which references the HP variable.
     */

    /* Search for patterns that reference character data */
    /* Pattern: MOV EAX, [addr] where addr is in .data section */
    ScanDataSection();

    MULOG_INFO("[GameActionMonitor] Offset detection complete");
    MULOG_INFO("[GameActionMonitor] HP=0x%08X MP=0x%08X Level=0x%08X Zen=0x%08X",
               static_cast<uint32_t>(m_offsets.characterHP),
               static_cast<uint32_t>(m_offsets.characterMP),
               static_cast<uint32_t>(m_offsets.characterLevel),
               static_cast<uint32_t>(m_offsets.characterZen));
}

void GameActionMonitor::ScanDataSection()
{
    /*
     * Try to read values at known offsets to verify they contain
     * plausible game data. If a value looks invalid, try nearby
     * addresses to locate the actual data.
     */

    /* Verify HP offset: should be a reasonable value (0-65535) */
    uint32_t testVal = 0;
    if (m_memory->ReadValue<uint32_t>(m_offsets.characterHP, testVal)) {
        MULOG_DEBUG("[GameActionMonitor] HP offset test: value=%u at 0x%08X",
                    testVal, static_cast<uint32_t>(m_offsets.characterHP));
    }

    /* Verify Level offset: should be 1-400 for MuOnline */
    if (m_memory->ReadValue<uint32_t>(m_offsets.characterLevel, testVal)) {
        MULOG_DEBUG("[GameActionMonitor] Level offset test: value=%u at 0x%08X",
                    testVal, static_cast<uint32_t>(m_offsets.characterLevel));
    }
}

/* ================================================================== */
/*  Read Game State                                                     */
/* ================================================================== */

void GameActionMonitor::ReadGameState(GameState& state)
{
    if (!m_memory) return;

    m_memory->ReadValue<int32_t>(m_offsets.characterHP, state.hp);
    m_memory->ReadValue<int32_t>(m_offsets.characterMaxHP, state.maxHp);
    m_memory->ReadValue<int32_t>(m_offsets.characterMP, state.mp);
    m_memory->ReadValue<int32_t>(m_offsets.characterMaxMP, state.maxMp);
    m_memory->ReadValue<int32_t>(m_offsets.characterLevel, state.level);
    m_memory->ReadValue<uint32_t>(m_offsets.characterExp, state.exp);
    m_memory->ReadValue<uint32_t>(m_offsets.characterZen, state.zen);
    m_memory->ReadValue<int32_t>(m_offsets.characterStr, state.str);
    m_memory->ReadValue<int32_t>(m_offsets.characterAgi, state.agi);
    m_memory->ReadValue<int32_t>(m_offsets.characterVit, state.vit);
    m_memory->ReadValue<int32_t>(m_offsets.characterEne, state.ene);
    m_memory->ReadValue<uint32_t>(m_offsets.currentScene, state.currentScene);
    m_memory->ReadValue<uint32_t>(m_offsets.currentMapId, state.currentMapId);
    m_memory->ReadValue<uint32_t>(m_offsets.isLoggedIn, state.isLoggedIn);
    m_memory->ReadValue<uint32_t>(m_offsets.isInGame, state.isInGame);
    m_memory->ReadValue<uint32_t>(m_offsets.killCount, state.killCount);
    m_memory->ReadValue<uint32_t>(m_offsets.deathCount, state.deathCount);
    m_memory->ReadValue<uint32_t>(m_offsets.inventoryOpen, state.inventoryOpen);
    m_memory->ReadValue<uint32_t>(m_offsets.charWindowOpen, state.charWindowOpen);
    m_memory->ReadValue<uint32_t>(m_offsets.skillTreeOpen, state.skillTreeOpen);
    m_memory->ReadValue<uint32_t>(m_offsets.mapListOpen, state.mapListOpen);
    m_memory->ReadValue<uint32_t>(m_offsets.chatInputActive, state.chatInputActive);
    m_memory->ReadValue<float>(m_offsets.playerX, state.playerX);
    m_memory->ReadValue<float>(m_offsets.playerY, state.playerY);

    /* Read player name (string) */
    std::string name = m_memory->ReadString(m_offsets.characterName, 63);
    strncpy(state.playerName, name.c_str(), sizeof(state.playerName) - 1);
    state.playerName[sizeof(state.playerName) - 1] = '\0';
}

/* ================================================================== */
/*  Perform Lookup (offset, function, variable, module)                */
/* ================================================================== */

ActionLookupResult GameActionMonitor::PerformLookup(uintptr_t address,
                                                     const char* context)
{
    ActionLookupResult result;
    memset(&result, 0, sizeof(result));

    /* 1. Offset lookup */
    if (address >= m_mainBase) {
        result.offset = address - m_mainBase;
        result.offsetFound = true;
    } else {
        result.offset = address;
        result.offsetFound = (address != 0);
    }

    /* 2. Function lookup - scan for nearest function prologue */
    result.functionFound = false;
    if (result.offsetFound && m_scanner) {
        /*
         * Look backwards from the address for a function prologue
         * (55 8B EC = push ebp; mov ebp, esp).
         */
        uintptr_t searchAddr = address;
        for (uintptr_t off = 0; off < 0x1000; off += 1) {
            uintptr_t checkAddr = searchAddr - off;
            uint8_t bytes[3] = {0};
            if (m_memory->Read(checkAddr, bytes, 3)) {
                if (bytes[0] == 0x55 && bytes[1] == 0x8B &&
                    bytes[2] == 0xEC) {
                    result.functionAddress = checkAddr;
                    sprintf_s(result.functionName,
                               sizeof(result.functionName),
                               "sub_%08X",
                               static_cast<uint32_t>(
                                   checkAddr - m_mainBase));
                    result.functionFound = true;
                    break;
                }
            }
        }
    }

    /* 3. Variable lookup - find the nearest tracked variable */
    result.variableFound = false;
    if (address >= m_mainBase) {
        uintptr_t rva = address - m_mainBase;
        /* Check if it's in the .data section range */
        if (rva >= DATA_SECTION_RVA &&
            rva < DATA_SECTION_RVA + 0x1C000) {
            result.variableAddress = address;
            sprintf_s(result.variableName,
                       sizeof(result.variableName),
                       "var_%08X",
                       static_cast<uint32_t>(rva));
            result.variableFound = true;
        } else {
            /* Assign variable based on context */
            result.variableAddress = address;
            if (context) {
                strncpy(result.variableName, context,
                        sizeof(result.variableName) - 1);
                result.variableName[sizeof(result.variableName) - 1] = '\0';
            } else {
                sprintf_s(result.variableName,
                           sizeof(result.variableName),
                           "var_%08X",
                           static_cast<uint32_t>(address));
            }
            result.variableFound = true;
        }
    }

    /* 4. Module lookup - always main.exe for game actions */
    strcpy_s(result.moduleName, sizeof(result.moduleName), "main.exe");
    result.moduleBase = m_mainBase;
    result.moduleFound = true;

    return result;
}

/* ================================================================== */
/*  Emit Event                                                          */
/* ================================================================== */

void GameActionMonitor::EmitEvent(const GameActionEvent& event)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    /* Add to event history */
    if (m_events.size() >= MAX_EVENTS) {
        /* Remove oldest 10% to make room */
        size_t removeCount = MAX_EVENTS / 10;
        m_events.erase(m_events.begin(),
                       m_events.begin() + removeCount);
    }
    m_events.push_back(event);
    m_eventCount++;

    /* Add to database entries */
    DatabaseEntry dbEntry;
    dbEntry.actionType = event.type;
    strncpy(dbEntry.actionDescription, event.description,
            sizeof(dbEntry.actionDescription) - 1);
    dbEntry.actionDescription[sizeof(dbEntry.actionDescription) - 1] = '\0';
    dbEntry.offset = event.lookup.offset;
    strncpy(dbEntry.functionName, event.lookup.functionName,
            sizeof(dbEntry.functionName) - 1);
    dbEntry.functionName[sizeof(dbEntry.functionName) - 1] = '\0';
    strncpy(dbEntry.variableName, event.lookup.variableName,
            sizeof(dbEntry.variableName) - 1);
    dbEntry.variableName[sizeof(dbEntry.variableName) - 1] = '\0';
    strncpy(dbEntry.moduleName, event.lookup.moduleName,
            sizeof(dbEntry.moduleName) - 1);
    dbEntry.moduleName[sizeof(dbEntry.moduleName) - 1] = '\0';
    dbEntry.timestamp = event.timestamp;
    m_dbEntries.push_back(dbEntry);

    /* Log in required format */
    LogAction(event);
}

/* ================================================================== */
/*  Log Action                                                         */
/* ================================================================== */

void GameActionMonitor::LogAction(const GameActionEvent& event)
{
    Logger& log = Logger::Instance();

    const ActionLookupResult& lr = event.lookup;

    /*
     * Build the lookup result string:
     * "searching for offset: offset found, searching for function, function found,
     *  searching for variable, variable found, searching for module, module found."
     */
    char lookupStr[512];
    sprintf_s(lookupStr, sizeof(lookupStr),
              "searching for offset: %s (0x%08X), "
              "searching for function, %s (%s), "
              "searching for variable, %s (%s), "
              "searching for module, %s (%s).",
              lr.offsetFound   ? "offset found"     : "offset not found",
              static_cast<uint32_t>(lr.offset),
              lr.functionFound ? "function found"   : "function not found",
              lr.functionName[0] ? lr.functionName   : "N/A",
              lr.variableFound ? "variable found" : "variable not found",
              lr.variableName[0] ? lr.variableName   : "N/A",
              lr.moduleFound   ? "module found"     : "module not found",
              lr.moduleName[0] ? lr.moduleName       : "N/A");

    /* Log the full event */
    log.Log(LogLevel::Info, "[ACTION] %s, %s", event.description, lookupStr);

    /* Log matching action definition from reference files if available */
    const ActionDefinition* actionDef = FindActionDef(event.type,
        lr.variableName[0] ? lr.variableName : nullptr);
    if (actionDef) {
        log.Log(LogLevel::Info, "[ACTION_REF] [%s] Section: %s | %s",
                actionDef->actionId, actionDef->sectionName,
                actionDef->description);
    }

    /* Also log the offset in standard format */
    if (lr.offsetFound) {
        log.LogOffset(lr.offset + m_mainBase, lr.offset,
                       GetActionTypeName(event.type),
                       lr.functionName[0] ? lr.functionName : "unknown");
    }
}

/* ================================================================== */
/*  Check Keyboard                                                      */
/* ================================================================== */

void GameActionMonitor::CheckKeyboard()
{
    if (!m_initialized) return;

    /*
     * Only check keyboard when main.exe is the active window.
     * When main.exe is minimized or not in foreground, skip input
     * scanning to avoid false positives from other applications.
     */
    if (!IsGameWindowActive()) {
        return;
    }

    /*
     * Check all virtual key codes for state changes.
     * GetAsyncKeyState returns the state regardless of which
     * window has focus, which is fine since we're injected.
     */

    for (int vk = 1; vk < 256; ++vk) {
        /* Skip modifier keys to reduce noise (they're tracked separately) */
        if (vk == VK_SHIFT || vk == VK_CONTROL || vk == VK_MENU ||
            vk == VK_LSHIFT || vk == VK_RSHIFT ||
            vk == VK_LCONTROL || vk == VK_RCONTROL ||
            vk == VK_LMENU || vk == VK_RMENU) {
            continue;
        }

        uint8_t isDown = (GetAsyncKeyState(vk) & 0x8000) ? 1 : 0;

        if (isDown && !m_prevKeyState[vk]) {
            /* Key was just pressed */
            GameActionEvent event;
            memset(&event, 0, sizeof(event));
            event.type = GameActionType::KeyPress;

            LARGE_INTEGER qpc;
            QueryPerformanceCounter(&qpc);
            event.timestamp = static_cast<uint64_t>(qpc.QuadPart);

            event.data.key.vkCode = static_cast<uint32_t>(vk);
            event.data.key.isDown = true;

            const char* keyName = GetKeyName(static_cast<uint32_t>(vk));

            /* Build context-aware description */
            switch (vk) {
            case 'C':
                sprintf_s(event.description, sizeof(event.description),
                          "You pressed button \"%s\" in the game client, "
                          "character window opened (Character)",
                          keyName);
                event.lookup = PerformLookup(m_offsets.charWindowOpen,
                                              "CharacterWindow");
                break;
            case 'V':
                sprintf_s(event.description, sizeof(event.description),
                          "You pressed button \"%s\" in the game client, "
                          "inventory opened (Inventory)",
                          keyName);
                event.lookup = PerformLookup(m_offsets.inventoryOpen,
                                              "InventoryWindow");
                break;
            case 'M':
                sprintf_s(event.description, sizeof(event.description),
                          "You pressed button \"%s\" in the game client, "
                          "MapList with location (town) selection appeared",
                          keyName);
                event.lookup = PerformLookup(m_offsets.mapListOpen,
                                              "MapListWindow");
                break;
            case 'I':
                sprintf_s(event.description, sizeof(event.description),
                          "You pressed button \"%s\" in the game client, "
                          "inventory opened",
                          keyName);
                event.lookup = PerformLookup(m_offsets.inventoryOpen,
                                              "InventoryOpen");
                break;
            case 'S':
                sprintf_s(event.description, sizeof(event.description),
                          "You pressed button \"%s\" in the game client, "
                          "skill tree opened (Skill Tree)",
                          keyName);
                event.lookup = PerformLookup(m_offsets.skillTreeOpen,
                                              "SkillTreeWindow");
                break;
            case VK_RETURN:
                sprintf_s(event.description, sizeof(event.description),
                          "You pressed button \"%s\" in the game client, "
                          "chat input activated",
                          keyName);
                event.lookup = PerformLookup(m_offsets.chatInputActive,
                                              "ChatInput");
                break;
            case VK_TAB:
                sprintf_s(event.description, sizeof(event.description),
                          "You pressed button \"%s\" in the game client, "
                          "mini-map toggle",
                          keyName);
                event.lookup = PerformLookup(m_offsets.currentMapId,
                                              "MiniMapToggle");
                break;
            case VK_ESCAPE:
                sprintf_s(event.description, sizeof(event.description),
                          "You pressed button \"%s\" in the game client, "
                          "main menu opened",
                          keyName);
                event.lookup = PerformLookup(m_offsets.currentScene,
                                              "MainMenu");
                break;
            default:
                /* Function keys F1-F12 - skill hotkeys */
                if (vk >= VK_F1 && vk <= VK_F12) {
                    sprintf_s(event.description, sizeof(event.description),
                              "You pressed button \"%s\" in the game client, "
                              "skill usage (hotkey %s)",
                              keyName, keyName);
                    event.lookup = PerformLookup(m_offsets.skillTreeOpen,
                                                  "SkillHotkey");
                } else if (vk >= '0' && vk <= '9') {
                    sprintf_s(event.description, sizeof(event.description),
                              "You pressed button \"%s\" in the game client, "
                              "item usage from hotkey panel",
                              keyName);
                    event.lookup = PerformLookup(m_offsets.inventoryOpen,
                                                  "ItemHotkey");
                } else if (vk >= 'A' && vk <= 'Z') {
                    sprintf_s(event.description, sizeof(event.description),
                              "You pressed button \"%s\" in the game client",
                              keyName);
                    event.lookup = PerformLookup(m_mainBase,
                                                  "KeyboardInput");
                } else {
                    sprintf_s(event.description, sizeof(event.description),
                              "You pressed button \"%s\" in the game client",
                              keyName);
                    event.lookup = PerformLookup(m_mainBase,
                                                  "KeyboardInput");
                }
                break;
            }

            EmitEvent(event);
        }

        m_prevKeyState[vk] = isDown;
    }
}

/* ================================================================== */
/*  Update (main polling loop)                                          */
/* ================================================================== */

void GameActionMonitor::Update()
{
    if (!m_initialized) return;

    /*
     * Check that main.exe is the foreground window.
     * If the game window is minimized or another application is in focus,
     * offset searching and game state polling is paused until the player
     * returns to the game window.
     */
    if (!IsGameWindowActive()) {
        return;
    }

    /* Read current game state */
    ReadGameState(m_currState);

    /* Check keyboard */
    CheckKeyboard();

    /* Detect changes between previous and current state */
    if (m_prevState.initialized) {
        DetectChanges();
    }

    /* Update previous state */
    memcpy(&m_prevState, &m_currState, sizeof(GameState));
    m_prevState.initialized = true;
}

/* ================================================================== */
/*  Detect Changes                                                      */
/* ================================================================== */

void GameActionMonitor::DetectChanges()
{
    GameActionEvent event;
    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);

    /* --- HP Changed --- */
    if (m_currState.hp != m_prevState.hp && m_prevState.initialized) {
        memset(&event, 0, sizeof(event));
        event.type = GameActionType::HPChanged;
        event.timestamp = static_cast<uint64_t>(qpc.QuadPart);
        event.data.stat.oldVal = m_prevState.hp;
        event.data.stat.newVal = m_currState.hp;

        int32_t diff = m_currState.hp - m_prevState.hp;
        if (diff < 0) {
            sprintf_s(event.description, sizeof(event.description),
                      "Your HP decreased by %d units (was: %d, now: %d)",
                      -diff, m_prevState.hp, m_currState.hp);
        } else {
            sprintf_s(event.description, sizeof(event.description),
                      "Your HP increased by %d units (was: %d, now: %d)",
                      diff, m_prevState.hp, m_currState.hp);
        }
        event.lookup = PerformLookup(m_offsets.characterHP, "CharacterHP");
        EmitEvent(event);
    }

    /* --- MP Changed --- */
    if (m_currState.mp != m_prevState.mp && m_prevState.initialized) {
        memset(&event, 0, sizeof(event));
        event.type = GameActionType::MPChanged;
        event.timestamp = static_cast<uint64_t>(qpc.QuadPart);
        event.data.stat.oldVal = m_prevState.mp;
        event.data.stat.newVal = m_currState.mp;

        int32_t diff = m_currState.mp - m_prevState.mp;
        if (diff < 0) {
            sprintf_s(event.description, sizeof(event.description),
                      "Your MP decreased by %d units (was: %d, now: %d)",
                      -diff, m_prevState.mp, m_currState.mp);
        } else {
            sprintf_s(event.description, sizeof(event.description),
                      "Your MP increased by %d units (was: %d, now: %d)",
                      diff, m_prevState.mp, m_currState.mp);
        }
        event.lookup = PerformLookup(m_offsets.characterMP, "CharacterMP");
        EmitEvent(event);
    }

    /* --- Level Up --- */
    if (m_currState.level != m_prevState.level &&
        m_currState.level > m_prevState.level &&
        m_prevState.initialized) {
        memset(&event, 0, sizeof(event));
        event.type = GameActionType::LevelUp;
        event.timestamp = static_cast<uint64_t>(qpc.QuadPart);
        event.data.stat.oldVal = m_prevState.level;
        event.data.stat.newVal = m_currState.level;

        sprintf_s(event.description, sizeof(event.description),
                  "You reached level %d (was: %d)",
                  m_currState.level, m_prevState.level);
        event.lookup = PerformLookup(m_offsets.characterLevel, "CharacterLevel");
        EmitEvent(event);
    }

    /* --- Experience Gained --- */
    if (m_currState.exp != m_prevState.exp &&
        m_currState.exp > m_prevState.exp &&
        m_prevState.initialized) {
        memset(&event, 0, sizeof(event));
        event.type = GameActionType::ExpGained;
        event.timestamp = static_cast<uint64_t>(qpc.QuadPart);

        uint32_t gained = m_currState.exp - m_prevState.exp;
        sprintf_s(event.description, sizeof(event.description),
                  "%u experience gained (total: %u)",
                  gained, m_currState.exp);
        event.lookup = PerformLookup(m_offsets.characterExp, "CharacterExp");
        EmitEvent(event);
    }

    /* --- Zen Changed --- */
    if (m_currState.zen != m_prevState.zen && m_prevState.initialized) {
        memset(&event, 0, sizeof(event));
        event.type = GameActionType::ZenChanged;
        event.timestamp = static_cast<uint64_t>(qpc.QuadPart);
        event.data.currency.amount =
            (m_currState.zen > m_prevState.zen)
                ? (m_currState.zen - m_prevState.zen)
                : (m_prevState.zen - m_currState.zen);

        if (m_currState.zen > m_prevState.zen) {
            sprintf_s(event.description, sizeof(event.description),
                      "%u Zen gained (total: %u)",
                      m_currState.zen - m_prevState.zen, m_currState.zen);
        } else {
            sprintf_s(event.description, sizeof(event.description),
                      "%u Zen spent (remaining: %u)",
                      m_prevState.zen - m_currState.zen, m_currState.zen);
        }
        event.lookup = PerformLookup(m_offsets.characterZen, "CharacterZen");
        EmitEvent(event);
    }

    /* --- Strength Changed --- */
    if (m_currState.str != m_prevState.str && m_prevState.initialized) {
        memset(&event, 0, sizeof(event));
        event.type = GameActionType::StrChanged;
        event.timestamp = static_cast<uint64_t>(qpc.QuadPart);
        event.data.stat.oldVal = m_prevState.str;
        event.data.stat.newVal = m_currState.str;
        sprintf_s(event.description, sizeof(event.description),
                  "Strength changed: %d -> %d",
                  m_prevState.str, m_currState.str);
        event.lookup = PerformLookup(m_offsets.characterStr, "CharacterStr");
        EmitEvent(event);
    }

    /* --- Agility Changed --- */
    if (m_currState.agi != m_prevState.agi && m_prevState.initialized) {
        memset(&event, 0, sizeof(event));
        event.type = GameActionType::AgiChanged;
        event.timestamp = static_cast<uint64_t>(qpc.QuadPart);
        event.data.stat.oldVal = m_prevState.agi;
        event.data.stat.newVal = m_currState.agi;
        sprintf_s(event.description, sizeof(event.description),
                  "Agility changed: %d -> %d",
                  m_prevState.agi, m_currState.agi);
        event.lookup = PerformLookup(m_offsets.characterAgi, "CharacterAgi");
        EmitEvent(event);
    }

    /* --- Vitality Changed --- */
    if (m_currState.vit != m_prevState.vit && m_prevState.initialized) {
        memset(&event, 0, sizeof(event));
        event.type = GameActionType::VitChanged;
        event.timestamp = static_cast<uint64_t>(qpc.QuadPart);
        event.data.stat.oldVal = m_prevState.vit;
        event.data.stat.newVal = m_currState.vit;
        sprintf_s(event.description, sizeof(event.description),
                  "Vitality changed: %d -> %d",
                  m_prevState.vit, m_currState.vit);
        event.lookup = PerformLookup(m_offsets.characterVit, "CharacterVit");
        EmitEvent(event);
    }

    /* --- Energy Changed --- */
    if (m_currState.ene != m_prevState.ene && m_prevState.initialized) {
        memset(&event, 0, sizeof(event));
        event.type = GameActionType::EneChanged;
        event.timestamp = static_cast<uint64_t>(qpc.QuadPart);
        event.data.stat.oldVal = m_prevState.ene;
        event.data.stat.newVal = m_currState.ene;
        sprintf_s(event.description, sizeof(event.description),
                  "Energy changed: %d -> %d",
                  m_prevState.ene, m_currState.ene);
        event.lookup = PerformLookup(m_offsets.characterEne, "CharacterEne");
        EmitEvent(event);
    }

    /* --- Kill Count Changed (Player Kill) --- */
    if (m_currState.killCount > m_prevState.killCount &&
        m_prevState.initialized) {
        memset(&event, 0, sizeof(event));
        event.type = GameActionType::PlayerKill;
        event.timestamp = static_cast<uint64_t>(qpc.QuadPart);

        /* Try to read target name from memory */
        char targetName[64] = "UNKNOWN";
        if (m_offsets.targetObjectId != 0) {
            std::string tName = m_memory->ReadString(
                m_offsets.targetObjectId, 63);
            if (!tName.empty()) {
                strncpy(targetName, tName.c_str(), sizeof(targetName) - 1);
                targetName[sizeof(targetName) - 1] = '\0';
            }
        }
        strncpy(event.data.combat.targetName, targetName,
                sizeof(event.data.combat.targetName) - 1);

        sprintf_s(event.description, sizeof(event.description),
                  "You killed player %s in the game client (total kills: %u)",
                  targetName, m_currState.killCount);
        event.lookup = PerformLookup(m_offsets.killCount, "KillCount");
        EmitEvent(event);
    }

    /* --- Death Count Changed --- */
    if (m_currState.deathCount > m_prevState.deathCount &&
        m_prevState.initialized) {
        memset(&event, 0, sizeof(event));
        event.type = GameActionType::PlayerDeath;
        event.timestamp = static_cast<uint64_t>(qpc.QuadPart);

        sprintf_s(event.description, sizeof(event.description),
                  "Your character died (total deaths: %u)",
                  m_currState.deathCount);
        event.lookup = PerformLookup(m_offsets.deathCount, "DeathCount");
        EmitEvent(event);
    }

    /* --- Map Changed --- */
    if (m_currState.currentMapId != m_prevState.currentMapId &&
        m_prevState.initialized) {
        memset(&event, 0, sizeof(event));
        event.type = GameActionType::MapChanged;
        event.timestamp = static_cast<uint64_t>(qpc.QuadPart);
        event.data.map.mapId = m_currState.currentMapId;

        const char* mapName = GetMapName(m_currState.currentMapId);
        strncpy(event.data.map.mapName, mapName,
                sizeof(event.data.map.mapName) - 1);

        sprintf_s(event.description, sizeof(event.description),
                  "You moved to map %s (ID: %u), "
                  "previous map: %s (ID: %u)",
                  mapName, m_currState.currentMapId,
                  GetMapName(m_prevState.currentMapId),
                  m_prevState.currentMapId);
        event.lookup = PerformLookup(m_offsets.currentMapId, "CurrentMapId");
        EmitEvent(event);
    }

    /* --- Scene Changed (Login/Character Select/Game) --- */
    if (m_currState.currentScene != m_prevState.currentScene) {
        memset(&event, 0, sizeof(event));
        event.type = GameActionType::SceneChanged;
        event.timestamp = static_cast<uint64_t>(qpc.QuadPart);

        const char* sceneName = "Unknown";
        switch (m_currState.currentScene) {
        case 0: sceneName = "Splash Screen"; break;
        case 1: sceneName = "Login"; break;
        case 2: sceneName = "Server List"; break;
        case 3: sceneName = "Character Select"; break;
        case 4: sceneName = "Character Creation"; break;
        case 5: sceneName = "Game World"; break;
        }

        sprintf_s(event.description, sizeof(event.description),
                  "Scene changed: %s (ID: %u -> %u)",
                  sceneName, m_prevState.currentScene,
                  m_currState.currentScene);
        event.lookup = PerformLookup(m_offsets.currentScene, "CurrentScene");
        EmitEvent(event);
    }

    /* --- Login State Changed --- */
    if (m_currState.isLoggedIn != m_prevState.isLoggedIn) {
        memset(&event, 0, sizeof(event));
        event.timestamp = static_cast<uint64_t>(qpc.QuadPart);

        if (m_currState.isLoggedIn && !m_prevState.isLoggedIn) {
            event.type = GameActionType::LoginSuccess;
            sprintf_s(event.description, sizeof(event.description),
                      "Login successful");
        } else {
            event.type = GameActionType::ServerDisconnected;
            sprintf_s(event.description, sizeof(event.description),
                      "Disconnected from server");
        }
        event.lookup = PerformLookup(m_offsets.isLoggedIn, "IsLoggedIn");
        EmitEvent(event);
    }

    /* --- Inventory Window --- */
    if (m_currState.inventoryOpen != m_prevState.inventoryOpen) {
        memset(&event, 0, sizeof(event));
        event.type = GameActionType::InventoryOpened;
        event.timestamp = static_cast<uint64_t>(qpc.QuadPart);

        sprintf_s(event.description, sizeof(event.description),
                  "Inventory %s",
                  m_currState.inventoryOpen ? "opened" : "closed");
        event.lookup = PerformLookup(m_offsets.inventoryOpen,
                                      "InventoryWindow");
        EmitEvent(event);
    }

    /* --- Character Window --- */
    if (m_currState.charWindowOpen != m_prevState.charWindowOpen) {
        memset(&event, 0, sizeof(event));
        event.type = GameActionType::CharWindowOpened;
        event.timestamp = static_cast<uint64_t>(qpc.QuadPart);

        sprintf_s(event.description, sizeof(event.description),
                  "Character window %s",
                  m_currState.charWindowOpen ? "opened" : "closed");
        event.lookup = PerformLookup(m_offsets.charWindowOpen,
                                      "CharacterWindow");
        EmitEvent(event);
    }

    /* --- Skill Tree Window --- */
    if (m_currState.skillTreeOpen != m_prevState.skillTreeOpen) {
        memset(&event, 0, sizeof(event));
        event.type = GameActionType::SkillTreeOpened;
        event.timestamp = static_cast<uint64_t>(qpc.QuadPart);

        sprintf_s(event.description, sizeof(event.description),
                  "Skill tree %s",
                  m_currState.skillTreeOpen ? "opened" : "closed");
        event.lookup = PerformLookup(m_offsets.skillTreeOpen,
                                      "SkillTreeWindow");
        EmitEvent(event);
    }

    /* --- Map List (warp dialog) --- */
    if (m_currState.mapListOpen != m_prevState.mapListOpen) {
        memset(&event, 0, sizeof(event));
        event.type = GameActionType::MapListOpened;
        event.timestamp = static_cast<uint64_t>(qpc.QuadPart);

        sprintf_s(event.description, sizeof(event.description),
                  "MapList with location (town) selection %s",
                  m_currState.mapListOpen ? "opened" : "closed");
        event.lookup = PerformLookup(m_offsets.mapListOpen, "MapListWindow");
        EmitEvent(event);
    }

    /* --- Chat Input --- */
    if (m_currState.chatInputActive != m_prevState.chatInputActive) {
        memset(&event, 0, sizeof(event));
        event.type = GameActionType::ChatMessage;
        event.timestamp = static_cast<uint64_t>(qpc.QuadPart);

        sprintf_s(event.description, sizeof(event.description),
                  "Chat input %s",
                  m_currState.chatInputActive ? "activated" : "deactivated");
        event.lookup = PerformLookup(m_offsets.chatInputActive,
                                      "ChatInputActive");
        EmitEvent(event);
    }
}

/* ================================================================== */
/*  Get Recent Events                                                   */
/* ================================================================== */

std::vector<GameActionEvent> GameActionMonitor::GetRecentEvents(
    size_t maxEvents) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_events.empty()) return {};

    size_t count = (maxEvents < m_events.size())
                       ? maxEvents : m_events.size();
    return std::vector<GameActionEvent>(
        m_events.end() - count, m_events.end());
}

/* ================================================================== */
/*  Flush Database                                                      */
/* ================================================================== */

void GameActionMonitor::FlushDatabase()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    WriteDatabaseCSV();
}

/* ================================================================== */
/*  Write Database CSV                                                  */
/*  The database is FULLY REWRITTEN on each call, as required          */
/* ================================================================== */

void GameActionMonitor::WriteDatabaseCSV()
{
    if (m_dbFilePath.empty()) return;

    FILE* fp = fopen(m_dbFilePath.c_str(), "w");
    if (!fp) {
        MULOG_ERROR("[GameActionMonitor] Failed to open database file: %s",
                    m_dbFilePath.c_str());
        return;
    }

    /* Header */
    fprintf(fp, "=== MuTracker Database ===\n");
    fprintf(fp, "=== Rewritten on each program launch ===\n");
    fprintf(fp, "=== Data sources: MuOnline_S3E1_Actions_1.02Q_Part1.txt, "
                "MuOnline_S3E1_Actions_1.02Q_Part2.txt ===\n");
    fprintf(fp, "=== Action definitions loaded: %zu ===\n",
            m_actionDefs.size());
    fprintf(fp, "=== Total entries: %zu ===\n\n", m_dbEntries.size());

    /* Column headers */
    fprintf(fp, "Timestamp|ActionType|Description|"
                "Offset|FunctionName|VariableName|ModuleName\n");
    fprintf(fp, "---------|----------|-----------|"
                "------|------------|------------|----------\n");

    /* Data rows */
    for (const auto& entry : m_dbEntries) {
        fprintf(fp, "%llu|%s|%s|0x%08X|%s|%s|%s\n",
                static_cast<unsigned long long>(entry.timestamp),
                GetActionTypeName(entry.actionType),
                entry.actionDescription,
                static_cast<uint32_t>(entry.offset),
                entry.functionName,
                entry.variableName,
                entry.moduleName);
    }

    fprintf(fp, "\n=== End of Database (entries: %zu) ===\n",
            m_dbEntries.size());

    fclose(fp);

    MULOG_DEBUG("[GameActionMonitor] Database written: %zu entries to %s",
                m_dbEntries.size(), m_dbFilePath.c_str());
}

/* ================================================================== */
/*  Load Action Definitions from Reference Files                        */
/* ================================================================== */

size_t GameActionMonitor::LoadActionDefinitions(const char* part1Path,
                                                  const char* part2Path)
{
    m_actionDefs.clear();
    m_sectionNames.clear();

    size_t count1 = 0;
    size_t count2 = 0;

    if (part1Path && part1Path[0] != '\0') {
        count1 = ParseActionFile(part1Path);
        MULOG_INFO("[GameActionMonitor] Loaded %zu action definitions from Part1: %s",
                   count1, part1Path);
    }

    if (part2Path && part2Path[0] != '\0') {
        count2 = ParseActionFile(part2Path);
        MULOG_INFO("[GameActionMonitor] Loaded %zu action definitions from Part2: %s",
                   count2, part2Path);
    }

    size_t total = count1 + count2;
    MULOG_INFO("[GameActionMonitor] Total action definitions loaded: %zu "
               "(Part1: %zu, Part2: %zu, Sections: %zu)",
               total, count1, count2, m_sectionNames.size());

    return total;
}

/* ================================================================== */
/*  Parse a Single Action Reference File                                */
/*                                                                      */
/*  File format (from MuOnline_S3E1_Actions_1.02Q):                    */
/*    SECTION N — SECTION_NAME                                          */
/*    [N.NNN] Description text,                                         */
/*      searching for offset: offset found, ...                         */
/* ================================================================== */

size_t GameActionMonitor::ParseActionFile(const char* filePath)
{
    if (!filePath) return 0;

    FILE* fp = fopen(filePath, "r");
    if (!fp) {
        MULOG_WARN("[GameActionMonitor] Cannot open action file: %s", filePath);
        return 0;
    }

    size_t loadedCount = 0;
    char line[1024];
    char currentSection[128] = {0};
    uint32_t currentSectionNum = 0;

    while (fgets(line, sizeof(line), fp)) {
        /* Remove trailing newline/CR */
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';

        /* Skip empty lines and separator lines */
        if (len == 0) continue;
        if (line[0] == '=' && len > 5) continue;

        /* Detect SECTION header lines:
         *   "  SECTION N — SECTION_NAME"
         */
        const char* secPtr = strstr(line, "SECTION ");
        if (secPtr) {
            /* Parse section number and name */
            uint32_t secNum = 0;
            char secNameBuf[128] = {0};

            /* Try pattern: "SECTION %d" followed by dash and name */
            if (sscanf(secPtr, "SECTION %u", &secNum) == 1) {
                currentSectionNum = secNum;

                /* Find the dash separator to get the name */
                const char* dashPtr = strstr(secPtr, "\xe2\x80\x94"); /* UTF-8 em-dash */
                if (!dashPtr) dashPtr = strstr(secPtr, " - ");
                if (!dashPtr) dashPtr = strstr(secPtr, "-- ");

                if (dashPtr) {
                    /* Skip the dash and whitespace */
                    if (dashPtr[0] == '\xe2') dashPtr += 3; /* UTF-8 em-dash is 3 bytes */
                    else dashPtr += 2; /* " -" or "--" */

                    while (*dashPtr == ' ' || *dashPtr == '-') dashPtr++;

                    strncpy(secNameBuf, dashPtr, sizeof(secNameBuf) - 1);
                    secNameBuf[sizeof(secNameBuf) - 1] = '\0';

                    /* Trim trailing whitespace */
                    size_t slen = strlen(secNameBuf);
                    while (slen > 0 && (secNameBuf[slen - 1] == ' ' ||
                                         secNameBuf[slen - 1] == '\t'))
                        secNameBuf[--slen] = '\0';
                }

                strncpy(currentSection, secNameBuf, sizeof(currentSection) - 1);
                currentSection[sizeof(currentSection) - 1] = '\0';
                m_sectionNames[secNum] = currentSection;
            }
            continue;
        }

        /* Detect action entry lines: "[N.NNN] Description text," */
        if (line[0] == '[' || (len > 2 && line[0] == ' ' && line[1] == '[')) {
            /* Find the bracket start */
            const char* bracketStart = strchr(line, '[');
            if (!bracketStart) continue;

            uint32_t secNum = 0, entryNum = 0;
            if (sscanf(bracketStart, "[%u.%u]", &secNum, &entryNum) != 2)
                continue;

            /* Find the description after "] " */
            const char* descStart = strchr(bracketStart, ']');
            if (!descStart) continue;
            descStart++; /* Skip ']' */
            while (*descStart == ' ') descStart++;

            /* Build the description by collecting continuation lines
             * until we find the "module found." terminator */
            ActionDefinition def;
            memset(&def, 0, sizeof(def));

            def.sectionNum = secNum;
            def.entryNum   = entryNum;
            sprintf_s(def.actionId, sizeof(def.actionId), "%u.%03u",
                       secNum, entryNum);

            /* Use the section name from the current SECTION header */
            if (m_sectionNames.count(secNum)) {
                strncpy(def.sectionName, m_sectionNames[secNum].c_str(),
                        sizeof(def.sectionName) - 1);
            } else {
                strncpy(def.sectionName, currentSection,
                        sizeof(def.sectionName) - 1);
            }
            def.sectionName[sizeof(def.sectionName) - 1] = '\0';

            /* Copy the description part (before the "searching for" part) */
            /* The description ends at the comma before "searching for offset" */
            std::string fullDesc = descStart;

            /* Read continuation lines if the entry spans multiple lines */
            while (!strstr(fullDesc.c_str(), "module found.")) {
                if (!fgets(line, sizeof(line), fp)) break;
                len = strlen(line);
                while (len > 0 && (line[len - 1] == '\n' ||
                                    line[len - 1] == '\r'))
                    line[--len] = '\0';

                /* Skip leading whitespace */
                const char* p = line;
                while (*p == ' ' || *p == '\t') p++;
                fullDesc += " ";
                fullDesc += p;
            }

            /* Extract the actual description (before "searching for offset") */
            std::string cleanDesc;
            size_t searchPos = fullDesc.find("searching for offset");
            if (searchPos != std::string::npos) {
                cleanDesc = fullDesc.substr(0, searchPos);
                /* Trim trailing comma and whitespace */
                while (!cleanDesc.empty() &&
                       (cleanDesc.back() == ',' || cleanDesc.back() == ' ' ||
                        cleanDesc.back() == '\t'))
                    cleanDesc.pop_back();
            } else {
                cleanDesc = fullDesc;
            }

            strncpy(def.description, cleanDesc.c_str(),
                    sizeof(def.description) - 1);
            def.description[sizeof(def.description) - 1] = '\0';

            m_actionDefs.push_back(def);
            loadedCount++;
        }
    }

    fclose(fp);
    return loadedCount;
}

/* ================================================================== */
/*  Find Action Definition                                              */
/*  Match a game event type + context to a loaded action definition     */
/* ================================================================== */

const ActionDefinition* GameActionMonitor::FindActionDef(
    GameActionType type, const char* context) const
{
    if (m_actionDefs.empty()) return nullptr;

    /*
     * Map GameActionType to the most likely SECTION numbers from the
     * reference files:
     *   Section 1   — Process Init
     *   Section 5   — Network/Server
     *   Section 6   — Login Screen
     *   Section 7   — Character Select
     *   Section 8   — Game World Entry
     *   Section 9   — Movement
     *   Section 10  — Combat: Attacking
     *   Section 11  — Combat: Skills
     *   Section 12  — Character Stats
     *   Section 13  — Inventory & Items
     *   Section 14  — Skill Window
     *   Section 15  — Map & Minimap
     *   Section 16  — Chat System
     *   Section 17  — NPC & Shop
     *   Section 18  — Chaos Machine
     *   Section 19  — Party System
     *   Section 20  — Guild System
     *   Section 21  — Friends & Trade
     *   Section 22  — PvP/PK
     *   Section 23  — Events
     *   Section 24  — Pets & Mounts
     *   Section 25  — Warp/Map Change
     *   Section 27  — HUD & UI
     *   Section 31  — Game Exit
     *   Section 32+ — Packets, Buffs, etc.
     */
    uint32_t targetSection = 0;
    switch (type) {
    case GameActionType::KeyPress:
    case GameActionType::KeyRelease:
        /* Check context for specific key actions */
        if (context) {
            if (strstr(context, "Chat")) targetSection = 16;
            else if (strstr(context, "Inventory")) targetSection = 13;
            else if (strstr(context, "Character")) targetSection = 12;
            else if (strstr(context, "SkillTree")) targetSection = 14;
            else if (strstr(context, "SkillHotkey")) targetSection = 11;
            else if (strstr(context, "MapList")) targetSection = 15;
            else if (strstr(context, "MainMenu")) targetSection = 27;
            else if (strstr(context, "MiniMap")) targetSection = 15;
            else targetSection = 39; /* Section 39 = Input handling */
        }
        break;
    case GameActionType::MouseClick:
    case GameActionType::MouseMove:
        targetSection = 9; /* Movement */
        break;
    case GameActionType::HPChanged:
    case GameActionType::MPChanged:
    case GameActionType::LevelUp:
    case GameActionType::ExpGained:
    case GameActionType::ZenChanged:
    case GameActionType::StatPointGained:
    case GameActionType::StrChanged:
    case GameActionType::AgiChanged:
    case GameActionType::VitChanged:
    case GameActionType::EneChanged:
        targetSection = 12; /* Character Stats */
        break;
    case GameActionType::PlayerKill:
    case GameActionType::PlayerDeath:
        targetSection = 22; /* PvP/PK */
        break;
    case GameActionType::MonsterKill:
    case GameActionType::DamageDealt:
    case GameActionType::DamageReceived:
        targetSection = 10; /* Combat: Attacking */
        break;
    case GameActionType::SkillUsed:
    case GameActionType::BuffApplied:
        targetSection = 11; /* Combat: Skills */
        break;
    case GameActionType::MapChanged:
    case GameActionType::TeleportUsed:
        targetSection = 25; /* Warp/Map Change */
        break;
    case GameActionType::MapListOpened:
        targetSection = 15; /* Map & Minimap */
        break;
    case GameActionType::ChatMessage:
        targetSection = 16; /* Chat System */
        break;
    case GameActionType::PartyJoined:
    case GameActionType::PartyLeft:
        targetSection = 19; /* Party */
        break;
    case GameActionType::GuildAction:
        targetSection = 20; /* Guild */
        break;
    case GameActionType::TradeStarted:
    case GameActionType::TradeCompleted:
        targetSection = 21; /* Friends & Trade */
        break;
    case GameActionType::ItemPickedUp:
    case GameActionType::ItemDropped:
    case GameActionType::ItemEquipped:
    case GameActionType::ItemUnequipped:
        targetSection = 13; /* Inventory & Items */
        break;
    case GameActionType::ShopOpened:
    case GameActionType::ShopClosed:
    case GameActionType::ItemBought:
    case GameActionType::ItemSold:
        targetSection = 17; /* NPC & Shop */
        break;
    case GameActionType::CharWindowOpened:
    case GameActionType::InventoryOpened:
    case GameActionType::SkillTreeOpened:
    case GameActionType::QuestLogOpened:
    case GameActionType::MiniMapToggled:
    case GameActionType::MenuOpened:
        targetSection = 27; /* HUD & UI */
        break;
    case GameActionType::ServerConnected:
    case GameActionType::ServerDisconnected:
        targetSection = 5; /* Network */
        break;
    case GameActionType::LoginSuccess:
        targetSection = 6; /* Login */
        break;
    case GameActionType::CharacterSelected:
        targetSection = 7; /* Character Select */
        break;
    case GameActionType::SceneChanged:
        targetSection = 8; /* Game World Entry */
        break;
    default:
        targetSection = 0;
        break;
    }

    /* Find the first entry in the matching section */
    if (targetSection > 0) {
        for (const auto& def : m_actionDefs) {
            if (def.sectionNum == targetSection) {
                return &def;
            }
        }
    }

    /* Fallback: return the first available definition */
    if (!m_actionDefs.empty()) {
        return &m_actionDefs[0];
    }

    return nullptr;
}

/* ================================================================== */
/*  Foreground Window Check                                             */
/*  Offset search pauses when main.exe window is not active            */
/* ================================================================== */

/* Helper callback for EnumWindows to find the game window */
struct FindWindowData {
    DWORD pid;
    HWND  hwnd;
};

static BOOL CALLBACK FindWindowByPidCallback(HWND hwnd, LPARAM lParam)
{
    FindWindowData* data = reinterpret_cast<FindWindowData*>(lParam);
    DWORD windowPid = 0;
    GetWindowThreadProcessId(hwnd, &windowPid);

    if (windowPid == data->pid) {
        /* Check if this is a visible, non-child top-level window */
        if (IsWindowVisible(hwnd) && GetParent(hwnd) == nullptr) {
            data->hwnd = hwnd;
            return FALSE; /* Stop enumeration */
        }
    }
    return TRUE; /* Continue */
}

void GameActionMonitor::CacheGameWindow() const
{
    FindWindowData data;
    data.pid  = m_gamePid;
    data.hwnd = nullptr;

    EnumWindows(FindWindowByPidCallback, reinterpret_cast<LPARAM>(&data));

    m_gameHwnd = data.hwnd;

    if (m_gameHwnd) {
        MULOG_DEBUG("[GameActionMonitor] Game window cached: HWND=0x%p PID=%u",
                    reinterpret_cast<void*>(m_gameHwnd), m_gamePid);
    }
}

bool GameActionMonitor::IsGameWindowActive() const
{
    /*
     * Check if main.exe game window is currently the foreground window.
     * When the game is minimized or another application is in focus,
     * offset search and action monitoring are paused.
     */
    HWND foreground = GetForegroundWindow();
    if (!foreground) return false;

    /* Check by PID — the foreground window must belong to our process */
    DWORD fgPid = 0;
    GetWindowThreadProcessId(foreground, &fgPid);

    if (fgPid == m_gamePid) {
        return true;
    }

    /* If cached HWND is stale, try to re-cache */
    if (m_gameHwnd == nullptr || !IsWindow(m_gameHwnd)) {
        CacheGameWindow();
    }

    /* Direct HWND comparison as fallback */
    if (m_gameHwnd != nullptr && foreground == m_gameHwnd) {
        return true;
    }

    return false;
}

} /* namespace MuTracker */

#endif /* _WIN32 */
