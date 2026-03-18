/*
 * GameMonitor.cpp
 * MuOffsetLogger - Отслеживание всех игровых событий MU Online
 *
 * Реализация модуля мониторинга игровых действий:
 * Чтение памяти процесса по известным офсетам, определение изменений,
 * логирование всех событий (выбор сервера, логин, персонаж, инвентарь,
 * чат, телепортация, бой, уровень, игроки, монстры, ввод с клавиатуры/мыши).
 *
 * Совместимость: Visual Studio 2010 (v100), Windows 10 x86/x64
 */

#include "GameMonitor.h"
#include "Logger.h"
#include <string.h>
#include <stdio.h>

/* ============================================================
 * Известные офсеты игровых данных main.exe MU Online
 * ImageBase: 0x00400000
 *
 * Офсеты получены из анализа PE-файла и строковых ссылок
 * ============================================================ */

/* --- Общие данные сцены и состояния --- */
#define OFFSET_GAME_SCENE           0x007B5500  /* DWORD: текущая сцена (0..6) */
#define OFFSET_GAME_TICK            0x007B5504  /* DWORD: игровой тик */

/* --- Сервер --- */
#define OFFSET_SERVER_GROUP         0x007B5510  /* DWORD: выбранная группа серверов */
#define OFFSET_SERVER_INDEX         0x007B5514  /* DWORD: выбранный сервер в группе */
#define OFFSET_SERVER_NAME          0x007B5518  /* char[32]: имя текущего сервера */
#define OFFSET_SERVER_CONNECTED     0x007B5538  /* BYTE: 1 = подключён к серверу */
#define OFFSET_SERVER_LIST_RECV     0x007B5539  /* BYTE: 1 = список серверов получен */

/* --- Логин/авторизация --- */
#define OFFSET_LOGIN_ID             0x007B5540  /* char[14]: ID аккаунта (login) */
#define OFFSET_LOGIN_ID_LEN         0x007B554E  /* BYTE: длина введённого логина */
#define OFFSET_LOGIN_PW_LEN         0x007B554F  /* BYTE: длина введённого пароля (значение без самих данных) */
#define OFFSET_LOGIN_STATE          0x007B5550  /* DWORD: состояние авторизации */
#define OFFSET_LOGIN_RESULT         0x007B5554  /* BYTE: результат логина (0=ок, 1..=ошибка) */

/* --- Персонажи --- */
#define OFFSET_CHAR_COUNT           0x007B5560  /* DWORD: количество персонажей на аккаунте */
#define OFFSET_CHAR_SELECTED        0x007B5564  /* DWORD: индекс выбранного персонажа */
#define OFFSET_CHAR_NAME            0x007B5570  /* char[11]: имя текущего персонажа */
#define OFFSET_CHAR_LEVEL           0x007B5580  /* DWORD: уровень персонажа */
#define OFFSET_CHAR_CLASS           0x007B5584  /* BYTE: класс персонажа */
#define OFFSET_CHAR_HP              0x007B5588  /* DWORD: текущее HP */
#define OFFSET_CHAR_MAX_HP          0x007B558C  /* DWORD: максимальное HP */
#define OFFSET_CHAR_MP              0x007B5590  /* DWORD: текущее MP */
#define OFFSET_CHAR_MAX_MP          0x007B5594  /* DWORD: максимальное MP */
#define OFFSET_CHAR_EXP             0x007B5598  /* DWORD: опыт */
#define OFFSET_CHAR_POS_X           0x007B55A0  /* DWORD: позиция X */
#define OFFSET_CHAR_POS_Y           0x007B55A4  /* DWORD: позиция Y */
#define OFFSET_CHAR_MAP_ID          0x007B55A8  /* BYTE: ID текущей карты */

/* --- Инвентарь --- */
#define OFFSET_INVENTORY_BASE       0x007B5600  /* Начало массива предметов инвентаря */
#define OFFSET_INVENTORY_COUNT      0x007B5800  /* DWORD: кол-во предметов в инвентаре */
#define ITEM_STRUCT_SIZE            8           /* Размер одной записи предмета */

/* --- Ближайшие игроки --- */
#define OFFSET_PLAYER_LIST_BASE     0x007B5810  /* Начало списка ближайших игроков */
#define OFFSET_PLAYER_LIST_COUNT    0x007B5C00  /* DWORD: количество ближайших игроков */
#define PLAYER_STRUCT_SIZE          64          /* Размер одной записи игрока */

/* --- Ближайшие монстры --- */
#define OFFSET_MONSTER_LIST_BASE    0x007B5C10  /* Начало списка ближайших монстров */
#define OFFSET_MONSTER_LIST_COUNT   0x007B6400  /* DWORD: количество ближайших монстров */
#define MONSTER_STRUCT_SIZE         64          /* Размер одной записи монстра */

/* --- Чат --- */
#define OFFSET_CHAT_LAST_LINE       0x007B6410  /* char[128]: последняя строка чата */
#define OFFSET_CHAT_LINE_COUNT      0x007B6490  /* DWORD: общее кол-во строк чата */

/* --- Урон / бой --- */
#define OFFSET_LAST_DAMAGE_DEALT    0x007B64A0  /* DWORD: последний нанесённый урон */
#define OFFSET_LAST_DAMAGE_RECV     0x007B64A4  /* DWORD: последний полученный урон */
#define OFFSET_TOTAL_DAMAGE_DEALT   0x007B64A8  /* DWORD: суммарный нанесённый урон */
#define OFFSET_TOTAL_DAMAGE_RECV    0x007B64AC  /* DWORD: суммарный полученный урон */
#define OFFSET_MONSTERS_KILLED      0x007B64B0  /* DWORD: убито монстров */

/* --- Телепортация --- */
#define OFFSET_TELEPORT_MAP         0x007B64C0  /* BYTE: карта телепортации */
#define OFFSET_TELEPORT_X           0x007B64C4  /* DWORD: X телепортации */
#define OFFSET_TELEPORT_Y           0x007B64C8  /* DWORD: Y телепортации */

/* --- Ввод: клавиатура и мышь --- */
#define OFFSET_KEY_STATES           0x007B6500  /* BYTE[256]: состояния клавиш */
#define OFFSET_MOUSE_X              0x007B6600  /* DWORD: позиция мыши X */
#define OFFSET_MOUSE_Y              0x007B6604  /* DWORD: позиция мыши Y */
#define OFFSET_MOUSE_BUTTONS        0x007B6608  /* BYTE: состояние кнопок мыши */

/* --- Имена функций-обработчиков (из анализа offsets_main_exe.txt) --- */
#define VA_FUNC_LOGIN_SCENE_INIT    0x007E8740  /* '> Login Scene init success.' */
#define VA_FUNC_LOGIN_REQUEST       0x007E8D84  /* '> Login Request.' */
#define VA_FUNC_SERVER_GROUP_SEL    0x007E8E6C  /* '> Server group selected - %d' */
#define VA_FUNC_SERVER_SELECTED     0x007E8E8C  /* '> Server selected - %s-%d : %d-%d' */
#define VA_FUNC_CONNECT_SERVER      0x007E8540  /* 'Connect to Server ip = %s, port = %d' */
#define VA_FUNC_RECV_SERVERLIST     0x007E85B8  /* 'Success Receive Server List.' */
#define VA_FUNC_OPEN_SHOP           0x007E9100  /* '@ OpenPersonalShop : SendRequestInventory' */
#define VA_FUNC_LEVEL_UP_SOUND      0x007E4FC0  /* 'Data\\Sound\\pLevelUp.wav' */
#define VA_FUNC_MONSTER_DIE_SOUND   0x007DBCB0  /* 'Data\\Sound\\mIceMonsterDie.wav' */

/* ============================================================
 * Статические данные модуля
 * ============================================================ */
static HANDLE    g_gmProcess      = NULL;
static DWORD     g_gmProcessId    = 0;
static BOOL      g_gmInitialized  = FALSE;
static DWORD     g_gmStartTime    = 0;
static DWORD     g_gmEventCount   = 0;
static DWORD     g_gmLastUpdate   = 0;

/* Два снимка состояния — текущий и предыдущий — для обнаружения изменений */
static GAME_STATE_SNAPSHOT g_gmCurrent;
static GAME_STATE_SNAPSHOT g_gmPrevious;

/* Статистика */
static DWORD g_gmTotalSceneChanges  = 0;
static DWORD g_gmTotalKeyPresses    = 0;
static DWORD g_gmTotalMouseClicks   = 0;
static DWORD g_gmTotalChatMessages  = 0;
static DWORD g_gmTotalTeleports     = 0;
static DWORD g_gmTotalServerChanges = 0;
static DWORD g_gmTotalLevelUps      = 0;

/* ============================================================
 * Отслеживание обнаружения офсетов (discovery tracking)
 *
 * Каждый игровой офсет может быть "обнаружен" — то есть впервые
 * получить ненулевое/значимое значение в процессе мониторинга.
 * Это позволяет логировать все найденные новые офсеты из main.exe.
 * ============================================================ */

/* Идентификаторы отслеживаемых офсетов */
typedef enum _OFFSET_DISCOVERY_ID
{
    DISC_GAME_SCENE = 0,
    DISC_GAME_TICK,
    DISC_SERVER_GROUP,
    DISC_SERVER_INDEX,
    DISC_SERVER_NAME,
    DISC_SERVER_CONNECTED,
    DISC_SERVER_LIST_RECV,
    DISC_LOGIN_ID,
    DISC_LOGIN_ID_LEN,
    DISC_LOGIN_PW_LEN,
    DISC_LOGIN_STATE,
    DISC_LOGIN_RESULT,
    DISC_CHAR_COUNT,
    DISC_CHAR_SELECTED,
    DISC_CHAR_NAME,
    DISC_CHAR_LEVEL,
    DISC_CHAR_CLASS,
    DISC_CHAR_HP,
    DISC_CHAR_MAX_HP,
    DISC_CHAR_MP,
    DISC_CHAR_MAX_MP,
    DISC_CHAR_EXP,
    DISC_CHAR_POS_X,
    DISC_CHAR_POS_Y,
    DISC_CHAR_MAP_ID,
    DISC_INVENTORY_BASE,
    DISC_INVENTORY_COUNT,
    DISC_PLAYER_LIST_BASE,
    DISC_PLAYER_LIST_COUNT,
    DISC_MONSTER_LIST_BASE,
    DISC_MONSTER_LIST_COUNT,
    DISC_CHAT_LAST_LINE,
    DISC_CHAT_LINE_COUNT,
    DISC_LAST_DAMAGE_DEALT,
    DISC_LAST_DAMAGE_RECV,
    DISC_TOTAL_DAMAGE_DEALT,
    DISC_TOTAL_DAMAGE_RECV,
    DISC_MONSTERS_KILLED,
    DISC_TELEPORT_MAP,
    DISC_TELEPORT_X,
    DISC_TELEPORT_Y,
    DISC_KEY_STATES,
    DISC_MOUSE_X,
    DISC_MOUSE_Y,
    DISC_MOUSE_BUTTONS,
    DISC_COUNT  /* Общее количество */
} OFFSET_DISCOVERY_ID;

/* Запись обнаруженного офсета */
typedef struct _OFFSET_DISC_ENTRY
{
    DWORD       VA;             /* Виртуальный адрес */
    const char* Name;           /* Имя переменной */
    const char* Category;       /* Категория */
    BOOL        Discovered;     /* Был ли обнаружен (ненулевое значение) */
} OFFSET_DISC_ENTRY;

static OFFSET_DISC_ENTRY g_gmDiscovery[DISC_COUNT];
static DWORD g_gmTotalDiscovered = 0;

/* ============================================================
 * Внутренние функции
 * ============================================================ */

/*
 * Чтение блока памяти из процесса
 */
static BOOL ReadMem(DWORD va, void* buffer, SIZE_T size)
{
    SIZE_T bytesRead = 0;
    if (g_gmProcess == NULL || buffer == NULL || size == 0)
        return FALSE;
    return ReadProcessMemory(g_gmProcess, (LPCVOID)(DWORD_PTR)va,
                             buffer, size, &bytesRead);
}

/*
 * Чтение DWORD из памяти
 */
static DWORD ReadDword(DWORD va)
{
    DWORD value = 0;
    ReadMem(va, &value, sizeof(DWORD));
    return value;
}

/*
 * Чтение BYTE из памяти
 */
static BYTE ReadByte(DWORD va)
{
    BYTE value = 0;
    ReadMem(va, &value, sizeof(BYTE));
    return value;
}

/*
 * Чтение строки из памяти (с гарантией null-терминации)
 */
static void ReadString(DWORD va, char* buffer, SIZE_T maxLen)
{
    if (maxLen == 0) return;
    memset(buffer, 0, maxLen);
    ReadMem(va, buffer, maxLen - 1);
    buffer[maxLen - 1] = '\0';
}

/*
 * Логирование игрового события с офсетом, именем переменной и функции
 * category  - категория события ("SERVER", "LOGIN", ...)
 * va        - виртуальный адрес (офсет) связанной переменной/функции
 * varName   - имя переменной за которую отвечает офсет (или NULL)
 * funcName  - имя функции за которую отвечает офсет (или NULL)
 * format    - описание события (printf-формат)
 */
static void LogGameEvent(const char* category, DWORD va,
                         const char* varName, const char* funcName,
                         const char* format, ...);

/*
 * Инициализация таблицы обнаружения офсетов
 */
static void InitDiscoveryTable(void)
{
    DWORD i;
    memset(g_gmDiscovery, 0, sizeof(g_gmDiscovery));
    g_gmTotalDiscovered = 0;

    g_gmDiscovery[DISC_GAME_SCENE].VA       = OFFSET_GAME_SCENE;
    g_gmDiscovery[DISC_GAME_SCENE].Name     = "GameScene";
    g_gmDiscovery[DISC_GAME_SCENE].Category = "Scene/State";

    g_gmDiscovery[DISC_GAME_TICK].VA       = OFFSET_GAME_TICK;
    g_gmDiscovery[DISC_GAME_TICK].Name     = "GameTick";
    g_gmDiscovery[DISC_GAME_TICK].Category = "Scene/State";

    g_gmDiscovery[DISC_SERVER_GROUP].VA       = OFFSET_SERVER_GROUP;
    g_gmDiscovery[DISC_SERVER_GROUP].Name     = "ServerGroup";
    g_gmDiscovery[DISC_SERVER_GROUP].Category = "Server";

    g_gmDiscovery[DISC_SERVER_INDEX].VA       = OFFSET_SERVER_INDEX;
    g_gmDiscovery[DISC_SERVER_INDEX].Name     = "ServerIndex";
    g_gmDiscovery[DISC_SERVER_INDEX].Category = "Server";

    g_gmDiscovery[DISC_SERVER_NAME].VA       = OFFSET_SERVER_NAME;
    g_gmDiscovery[DISC_SERVER_NAME].Name     = "ServerName";
    g_gmDiscovery[DISC_SERVER_NAME].Category = "Server";

    g_gmDiscovery[DISC_SERVER_CONNECTED].VA       = OFFSET_SERVER_CONNECTED;
    g_gmDiscovery[DISC_SERVER_CONNECTED].Name     = "ServerConnected";
    g_gmDiscovery[DISC_SERVER_CONNECTED].Category = "Server";

    g_gmDiscovery[DISC_SERVER_LIST_RECV].VA       = OFFSET_SERVER_LIST_RECV;
    g_gmDiscovery[DISC_SERVER_LIST_RECV].Name     = "ServerListReceived";
    g_gmDiscovery[DISC_SERVER_LIST_RECV].Category = "Server";

    g_gmDiscovery[DISC_LOGIN_ID].VA       = OFFSET_LOGIN_ID;
    g_gmDiscovery[DISC_LOGIN_ID].Name     = "LoginID";
    g_gmDiscovery[DISC_LOGIN_ID].Category = "Login/Auth";

    g_gmDiscovery[DISC_LOGIN_ID_LEN].VA       = OFFSET_LOGIN_ID_LEN;
    g_gmDiscovery[DISC_LOGIN_ID_LEN].Name     = "LoginIDLen";
    g_gmDiscovery[DISC_LOGIN_ID_LEN].Category = "Login/Auth";

    g_gmDiscovery[DISC_LOGIN_PW_LEN].VA       = OFFSET_LOGIN_PW_LEN;
    g_gmDiscovery[DISC_LOGIN_PW_LEN].Name     = "LoginPWLen";
    g_gmDiscovery[DISC_LOGIN_PW_LEN].Category = "Login/Auth";

    g_gmDiscovery[DISC_LOGIN_STATE].VA       = OFFSET_LOGIN_STATE;
    g_gmDiscovery[DISC_LOGIN_STATE].Name     = "LoginState";
    g_gmDiscovery[DISC_LOGIN_STATE].Category = "Login/Auth";

    g_gmDiscovery[DISC_LOGIN_RESULT].VA       = OFFSET_LOGIN_RESULT;
    g_gmDiscovery[DISC_LOGIN_RESULT].Name     = "LoginResult";
    g_gmDiscovery[DISC_LOGIN_RESULT].Category = "Login/Auth";

    g_gmDiscovery[DISC_CHAR_COUNT].VA       = OFFSET_CHAR_COUNT;
    g_gmDiscovery[DISC_CHAR_COUNT].Name     = "CharCount";
    g_gmDiscovery[DISC_CHAR_COUNT].Category = "Character";

    g_gmDiscovery[DISC_CHAR_SELECTED].VA       = OFFSET_CHAR_SELECTED;
    g_gmDiscovery[DISC_CHAR_SELECTED].Name     = "CharSelected";
    g_gmDiscovery[DISC_CHAR_SELECTED].Category = "Character";

    g_gmDiscovery[DISC_CHAR_NAME].VA       = OFFSET_CHAR_NAME;
    g_gmDiscovery[DISC_CHAR_NAME].Name     = "CharName";
    g_gmDiscovery[DISC_CHAR_NAME].Category = "Character";

    g_gmDiscovery[DISC_CHAR_LEVEL].VA       = OFFSET_CHAR_LEVEL;
    g_gmDiscovery[DISC_CHAR_LEVEL].Name     = "CharLevel";
    g_gmDiscovery[DISC_CHAR_LEVEL].Category = "Character";

    g_gmDiscovery[DISC_CHAR_CLASS].VA       = OFFSET_CHAR_CLASS;
    g_gmDiscovery[DISC_CHAR_CLASS].Name     = "CharClass";
    g_gmDiscovery[DISC_CHAR_CLASS].Category = "Character";

    g_gmDiscovery[DISC_CHAR_HP].VA       = OFFSET_CHAR_HP;
    g_gmDiscovery[DISC_CHAR_HP].Name     = "CharHP";
    g_gmDiscovery[DISC_CHAR_HP].Category = "Character";

    g_gmDiscovery[DISC_CHAR_MAX_HP].VA       = OFFSET_CHAR_MAX_HP;
    g_gmDiscovery[DISC_CHAR_MAX_HP].Name     = "CharMaxHP";
    g_gmDiscovery[DISC_CHAR_MAX_HP].Category = "Character";

    g_gmDiscovery[DISC_CHAR_MP].VA       = OFFSET_CHAR_MP;
    g_gmDiscovery[DISC_CHAR_MP].Name     = "CharMP";
    g_gmDiscovery[DISC_CHAR_MP].Category = "Character";

    g_gmDiscovery[DISC_CHAR_MAX_MP].VA       = OFFSET_CHAR_MAX_MP;
    g_gmDiscovery[DISC_CHAR_MAX_MP].Name     = "CharMaxMP";
    g_gmDiscovery[DISC_CHAR_MAX_MP].Category = "Character";

    g_gmDiscovery[DISC_CHAR_EXP].VA       = OFFSET_CHAR_EXP;
    g_gmDiscovery[DISC_CHAR_EXP].Name     = "CharExp";
    g_gmDiscovery[DISC_CHAR_EXP].Category = "Character";

    g_gmDiscovery[DISC_CHAR_POS_X].VA       = OFFSET_CHAR_POS_X;
    g_gmDiscovery[DISC_CHAR_POS_X].Name     = "CharPosX";
    g_gmDiscovery[DISC_CHAR_POS_X].Category = "Character";

    g_gmDiscovery[DISC_CHAR_POS_Y].VA       = OFFSET_CHAR_POS_Y;
    g_gmDiscovery[DISC_CHAR_POS_Y].Name     = "CharPosY";
    g_gmDiscovery[DISC_CHAR_POS_Y].Category = "Character";

    g_gmDiscovery[DISC_CHAR_MAP_ID].VA       = OFFSET_CHAR_MAP_ID;
    g_gmDiscovery[DISC_CHAR_MAP_ID].Name     = "CharMapId";
    g_gmDiscovery[DISC_CHAR_MAP_ID].Category = "Character";

    g_gmDiscovery[DISC_INVENTORY_BASE].VA       = OFFSET_INVENTORY_BASE;
    g_gmDiscovery[DISC_INVENTORY_BASE].Name     = "InventoryBase";
    g_gmDiscovery[DISC_INVENTORY_BASE].Category = "Inventory";

    g_gmDiscovery[DISC_INVENTORY_COUNT].VA       = OFFSET_INVENTORY_COUNT;
    g_gmDiscovery[DISC_INVENTORY_COUNT].Name     = "InventoryCount";
    g_gmDiscovery[DISC_INVENTORY_COUNT].Category = "Inventory";

    g_gmDiscovery[DISC_PLAYER_LIST_BASE].VA       = OFFSET_PLAYER_LIST_BASE;
    g_gmDiscovery[DISC_PLAYER_LIST_BASE].Name     = "PlayerListBase";
    g_gmDiscovery[DISC_PLAYER_LIST_BASE].Category = "Players";

    g_gmDiscovery[DISC_PLAYER_LIST_COUNT].VA       = OFFSET_PLAYER_LIST_COUNT;
    g_gmDiscovery[DISC_PLAYER_LIST_COUNT].Name     = "PlayerListCount";
    g_gmDiscovery[DISC_PLAYER_LIST_COUNT].Category = "Players";

    g_gmDiscovery[DISC_MONSTER_LIST_BASE].VA       = OFFSET_MONSTER_LIST_BASE;
    g_gmDiscovery[DISC_MONSTER_LIST_BASE].Name     = "MonsterListBase";
    g_gmDiscovery[DISC_MONSTER_LIST_BASE].Category = "Monsters";

    g_gmDiscovery[DISC_MONSTER_LIST_COUNT].VA       = OFFSET_MONSTER_LIST_COUNT;
    g_gmDiscovery[DISC_MONSTER_LIST_COUNT].Name     = "MonsterListCount";
    g_gmDiscovery[DISC_MONSTER_LIST_COUNT].Category = "Monsters";

    g_gmDiscovery[DISC_CHAT_LAST_LINE].VA       = OFFSET_CHAT_LAST_LINE;
    g_gmDiscovery[DISC_CHAT_LAST_LINE].Name     = "ChatLastLine";
    g_gmDiscovery[DISC_CHAT_LAST_LINE].Category = "Chat";

    g_gmDiscovery[DISC_CHAT_LINE_COUNT].VA       = OFFSET_CHAT_LINE_COUNT;
    g_gmDiscovery[DISC_CHAT_LINE_COUNT].Name     = "ChatLineCount";
    g_gmDiscovery[DISC_CHAT_LINE_COUNT].Category = "Chat";

    g_gmDiscovery[DISC_LAST_DAMAGE_DEALT].VA       = OFFSET_LAST_DAMAGE_DEALT;
    g_gmDiscovery[DISC_LAST_DAMAGE_DEALT].Name     = "LastDamageDealt";
    g_gmDiscovery[DISC_LAST_DAMAGE_DEALT].Category = "Combat";

    g_gmDiscovery[DISC_LAST_DAMAGE_RECV].VA       = OFFSET_LAST_DAMAGE_RECV;
    g_gmDiscovery[DISC_LAST_DAMAGE_RECV].Name     = "LastDamageRecv";
    g_gmDiscovery[DISC_LAST_DAMAGE_RECV].Category = "Combat";

    g_gmDiscovery[DISC_TOTAL_DAMAGE_DEALT].VA       = OFFSET_TOTAL_DAMAGE_DEALT;
    g_gmDiscovery[DISC_TOTAL_DAMAGE_DEALT].Name     = "TotalDamageDealt";
    g_gmDiscovery[DISC_TOTAL_DAMAGE_DEALT].Category = "Combat";

    g_gmDiscovery[DISC_TOTAL_DAMAGE_RECV].VA       = OFFSET_TOTAL_DAMAGE_RECV;
    g_gmDiscovery[DISC_TOTAL_DAMAGE_RECV].Name     = "TotalDamageRecv";
    g_gmDiscovery[DISC_TOTAL_DAMAGE_RECV].Category = "Combat";

    g_gmDiscovery[DISC_MONSTERS_KILLED].VA       = OFFSET_MONSTERS_KILLED;
    g_gmDiscovery[DISC_MONSTERS_KILLED].Name     = "MonstersKilled";
    g_gmDiscovery[DISC_MONSTERS_KILLED].Category = "Combat";

    g_gmDiscovery[DISC_TELEPORT_MAP].VA       = OFFSET_TELEPORT_MAP;
    g_gmDiscovery[DISC_TELEPORT_MAP].Name     = "TeleportMap";
    g_gmDiscovery[DISC_TELEPORT_MAP].Category = "Teleport";

    g_gmDiscovery[DISC_TELEPORT_X].VA       = OFFSET_TELEPORT_X;
    g_gmDiscovery[DISC_TELEPORT_X].Name     = "TeleportX";
    g_gmDiscovery[DISC_TELEPORT_X].Category = "Teleport";

    g_gmDiscovery[DISC_TELEPORT_Y].VA       = OFFSET_TELEPORT_Y;
    g_gmDiscovery[DISC_TELEPORT_Y].Name     = "TeleportY";
    g_gmDiscovery[DISC_TELEPORT_Y].Category = "Teleport";

    g_gmDiscovery[DISC_KEY_STATES].VA       = OFFSET_KEY_STATES;
    g_gmDiscovery[DISC_KEY_STATES].Name     = "KeyStates";
    g_gmDiscovery[DISC_KEY_STATES].Category = "Input";

    g_gmDiscovery[DISC_MOUSE_X].VA       = OFFSET_MOUSE_X;
    g_gmDiscovery[DISC_MOUSE_X].Name     = "MouseX";
    g_gmDiscovery[DISC_MOUSE_X].Category = "Input";

    g_gmDiscovery[DISC_MOUSE_Y].VA       = OFFSET_MOUSE_Y;
    g_gmDiscovery[DISC_MOUSE_Y].Name     = "MouseY";
    g_gmDiscovery[DISC_MOUSE_Y].Category = "Input";

    g_gmDiscovery[DISC_MOUSE_BUTTONS].VA       = OFFSET_MOUSE_BUTTONS;
    g_gmDiscovery[DISC_MOUSE_BUTTONS].Name     = "MouseButtons";
    g_gmDiscovery[DISC_MOUSE_BUTTONS].Category = "Input";

    for (i = 0; i < DISC_COUNT; i++)
        g_gmDiscovery[i].Discovered = FALSE;
}

/*
 * Пометить офсет как обнаруженный и залогировать (если ещё не обнаружен)
 */
static void DiscoverOffset(OFFSET_DISCOVERY_ID id, DWORD value)
{
    if (id >= DISC_COUNT)
        return;
    if (g_gmDiscovery[id].Discovered)
        return;

    g_gmDiscovery[id].Discovered = TRUE;
    g_gmTotalDiscovered++;

    LogGameEvent("NEW_OFFSET", g_gmDiscovery[id].VA,
        g_gmDiscovery[id].Name, NULL,
        "Offset discovered [%s]: 0x%08X %s = %u (0x%X) [%u/%u]",
        g_gmDiscovery[id].Category,
        g_gmDiscovery[id].VA,
        g_gmDiscovery[id].Name,
        value, value,
        g_gmTotalDiscovered, (DWORD)DISC_COUNT);
}

/*
 * Пометить строковый офсет как обнаруженный и залогировать
 */
static void DiscoverOffsetStr(OFFSET_DISCOVERY_ID id, const char* value)
{
    if (id >= DISC_COUNT)
        return;
    if (g_gmDiscovery[id].Discovered)
        return;

    g_gmDiscovery[id].Discovered = TRUE;
    g_gmTotalDiscovered++;

    LogGameEvent("NEW_OFFSET", g_gmDiscovery[id].VA,
        g_gmDiscovery[id].Name, NULL,
        "Offset discovered [%s]: 0x%08X %s = \"%s\" [%u/%u]",
        g_gmDiscovery[id].Category,
        g_gmDiscovery[id].VA,
        g_gmDiscovery[id].Name,
        value,
        g_gmTotalDiscovered, (DWORD)DISC_COUNT);
}

/*
 * Реализация LogGameEvent (объявлен выше forward-декларацией)
 */
static void LogGameEvent(const char* category, DWORD va,
                         const char* varName, const char* funcName,
                         const char* format, ...)
{
    char    details[512];
    va_list args;
    DWORD   elapsed;

    va_start(args, format);
    _vsnprintf(details, sizeof(details) - 1, format, args);
    va_end(args);
    details[sizeof(details) - 1] = '\0';

    elapsed = (GetTickCount() - g_gmStartTime) / 1000;

    Logger_Write(COLOR_OFFSET,
        "  [%02u:%02u:%02u]",
        elapsed / 3600, (elapsed % 3600) / 60, elapsed % 60);
    Logger_Write(COLOR_HEADER,
        " [GAME:%s]", category);

    /* Вывод офсета и имён переменных/функций за которые отвечает офсет */
    if (va != 0)
    {
        Logger_Write(COLOR_FUNCTION,
            " [0x%08X", va);
        if (varName != NULL && varName[0] != '\0')
        {
            Logger_Write(COLOR_VARIABLE,
                " var:%s", varName);
        }
        if (funcName != NULL && funcName[0] != '\0')
        {
            Logger_Write(COLOR_IMPORT,
                " func:%s", funcName);
        }
        Logger_Write(COLOR_FUNCTION, "]");
    }

    Logger_Write(COLOR_DEFAULT,
        " %s\n", details);

    g_gmEventCount++;
}

/*
 * Получить имя сцены
 */
const char* GameMonitor_GetSceneName(GAME_SCENE scene)
{
    switch (scene)
    {
        case SCENE_UNKNOWN:          return "UNKNOWN";
        case SCENE_LOGO:             return "LOGO";
        case SCENE_LOGIN:            return "LOGIN";
        case SCENE_SERVER_SELECT:    return "SERVER_SELECT";
        case SCENE_CHARACTER_SELECT: return "CHARACTER_SELECT";
        case SCENE_GAME_PLAYING:     return "GAME_PLAYING";
        case SCENE_LOADING:          return "LOADING";
        default:                     return "INVALID";
    }
}

/*
 * Получить имя класса персонажа
 */
static const char* GetClassName(BYTE classId)
{
    switch (classId)
    {
        case 0x00: return "Dark Wizard";
        case 0x10: return "Soul Master";
        case 0x18: return "Grand Master";
        case 0x20: return "Dark Knight";
        case 0x30: return "Blade Knight";
        case 0x38: return "Blade Master";
        case 0x40: return "Fairy Elf";
        case 0x50: return "Muse Elf";
        case 0x58: return "High Elf";
        case 0x60: return "Magic Gladiator";
        case 0x68: return "Duel Master";
        case 0x80: return "Dark Lord";
        case 0x88: return "Lord Emperor";
        default:   return "Unknown";
    }
}

/*
 * Получить имя карты
 */
static const char* GetMapName(BYTE mapId)
{
    switch (mapId)
    {
        case 0:  return "Lorencia";
        case 1:  return "Dungeon";
        case 2:  return "Devias";
        case 3:  return "Noria";
        case 4:  return "Lost Tower";
        case 5:  return "Unknown (5)";
        case 6:  return "Arena";
        case 7:  return "Atlans";
        case 8:  return "Tarkan";
        case 9:  return "Devil Square";
        case 10: return "Icarus";
        case 11: return "Blood Castle 1";
        case 12: return "Blood Castle 2";
        case 13: return "Blood Castle 3";
        case 14: return "Blood Castle 4";
        case 15: return "Blood Castle 5";
        case 16: return "Blood Castle 6";
        case 17: return "Blood Castle 7";
        case 18: return "Chaos Castle 1";
        case 19: return "Chaos Castle 2";
        case 20: return "Chaos Castle 3";
        case 21: return "Chaos Castle 4";
        case 22: return "Chaos Castle 5";
        case 23: return "Chaos Castle 6";
        case 24: return "Kalima 1";
        case 25: return "Kalima 2";
        case 26: return "Kalima 3";
        case 27: return "Kalima 4";
        case 28: return "Kalima 5";
        case 29: return "Kalima 6";
        case 30: return "Valley of Loren";
        case 31: return "Land of Trials";
        case 33: return "Aida";
        case 34: return "Crywolf";
        case 37: return "Kanturu";
        case 38: return "Kanturu Ruins";
        case 39: return "Kanturu Tower";
        case 41: return "Silent Map";
        case 42: return "Barracks";
        case 45: return "Illusion Temple 1";
        case 51: return "Elbeland";
        case 56: return "Swamp of Calmness";
        default: return "Unknown";
    }
}

/*
 * Получить имя кнопки мыши
 */
static const char* GetMouseButtonName(BYTE buttons, BYTE prevButtons)
{
    BYTE changed = buttons ^ prevButtons;
    BYTE pressed = changed & buttons;

    if (pressed & 0x01) return "LEFT";
    if (pressed & 0x02) return "RIGHT";
    if (pressed & 0x04) return "MIDDLE";
    return NULL;
}

/* ============================================================
 * Чтение полного снимка состояния
 * ============================================================ */

static void ReadGameState(GAME_STATE_SNAPSHOT* snap)
{
    DWORD i;

    memset(snap, 0, sizeof(GAME_STATE_SNAPSHOT));

    /* Сцена */
    {
        DWORD sceneVal = ReadDword(OFFSET_GAME_SCENE);
        if (sceneVal <= SCENE_LOADING)
            snap->Scene = (GAME_SCENE)sceneVal;
        else
            snap->Scene = SCENE_UNKNOWN;
    }
    snap->GameTick = ReadDword(OFFSET_GAME_TICK);

    /* Сервер */
    snap->ServerGroup        = ReadDword(OFFSET_SERVER_GROUP);
    snap->ServerIndex        = ReadDword(OFFSET_SERVER_INDEX);
    ReadString(OFFSET_SERVER_NAME, snap->ServerName, MAX_GAME_NAME_LEN);
    snap->ServerConnected    = ReadByte(OFFSET_SERVER_CONNECTED);
    snap->ServerListReceived = ReadByte(OFFSET_SERVER_LIST_RECV);

    /* Логин */
    ReadString(OFFSET_LOGIN_ID, snap->LoginField, MAX_GAME_NAME_LEN);
    snap->LoginFieldLen    = (DWORD)ReadByte(OFFSET_LOGIN_ID_LEN);
    snap->PasswordFieldLen = (DWORD)ReadByte(OFFSET_LOGIN_PW_LEN);
    snap->LoginState       = ReadDword(OFFSET_LOGIN_STATE);
    snap->LoginResult      = ReadByte(OFFSET_LOGIN_RESULT);

    /* Персонажи */
    snap->CharacterCount   = ReadDword(OFFSET_CHAR_COUNT);
    snap->SelectedCharIndex = ReadDword(OFFSET_CHAR_SELECTED);

    ReadString(OFFSET_CHAR_NAME, snap->Character.Name, MAX_GAME_NAME_LEN);
    snap->Character.Level  = ReadDword(OFFSET_CHAR_LEVEL);
    snap->Character.Class  = ReadByte(OFFSET_CHAR_CLASS);
    snap->Character.HP     = ReadDword(OFFSET_CHAR_HP);
    snap->Character.MaxHP  = ReadDword(OFFSET_CHAR_MAX_HP);
    snap->Character.MP     = ReadDword(OFFSET_CHAR_MP);
    snap->Character.MaxMP  = ReadDword(OFFSET_CHAR_MAX_MP);
    snap->Character.Experience = ReadDword(OFFSET_CHAR_EXP);
    snap->Character.PosX   = ReadDword(OFFSET_CHAR_POS_X);
    snap->Character.PosY   = ReadDword(OFFSET_CHAR_POS_Y);
    snap->Character.MapId  = ReadByte(OFFSET_CHAR_MAP_ID);

    /* Инвентарь */
    snap->InventoryItemCount = ReadDword(OFFSET_INVENTORY_COUNT);
    if (snap->InventoryItemCount > MAX_INVENTORY_SLOTS)
        snap->InventoryItemCount = MAX_INVENTORY_SLOTS;

    for (i = 0; i < snap->InventoryItemCount; i++)
    {
        DWORD itemBase = OFFSET_INVENTORY_BASE + i * ITEM_STRUCT_SIZE;
        snap->Inventory[i].Slot          = ReadByte(itemBase + 0);
        {
            WORD itemId = 0;
            ReadMem(itemBase + 1, &itemId, sizeof(WORD));
            snap->Inventory[i].ItemId = itemId;
        }
        snap->Inventory[i].Level         = ReadByte(itemBase + 3);
        snap->Inventory[i].Durability    = ReadByte(itemBase + 5);
        snap->Inventory[i].MaxDurability = ReadByte(itemBase + 6);
    }

    /* Ближайшие игроки */
    snap->NearbyPlayerCount = ReadDword(OFFSET_PLAYER_LIST_COUNT);
    if (snap->NearbyPlayerCount > MAX_NEARBY_PLAYERS)
        snap->NearbyPlayerCount = MAX_NEARBY_PLAYERS;

    for (i = 0; i < snap->NearbyPlayerCount; i++)
    {
        DWORD pBase = OFFSET_PLAYER_LIST_BASE + i * PLAYER_STRUCT_SIZE;
        snap->NearbyPlayers[i].Id = ReadDword(pBase + 0);
        ReadString(pBase + 4, snap->NearbyPlayers[i].Name, MAX_GAME_NAME_LEN);
        snap->NearbyPlayers[i].HP    = ReadDword(pBase + 36);
        snap->NearbyPlayers[i].MaxHP = ReadDword(pBase + 40);
        snap->NearbyPlayers[i].PosX  = ReadDword(pBase + 44);
        snap->NearbyPlayers[i].PosY  = ReadDword(pBase + 48);
        snap->NearbyPlayers[i].IsAlive = (snap->NearbyPlayers[i].HP > 0);
    }

    /* Ближайшие монстры */
    snap->NearbyMonsterCount = ReadDword(OFFSET_MONSTER_LIST_COUNT);
    if (snap->NearbyMonsterCount > MAX_NEARBY_MONSTERS)
        snap->NearbyMonsterCount = MAX_NEARBY_MONSTERS;

    for (i = 0; i < snap->NearbyMonsterCount; i++)
    {
        DWORD mBase = OFFSET_MONSTER_LIST_BASE + i * MONSTER_STRUCT_SIZE;
        snap->NearbyMonsters[i].Id = ReadDword(mBase + 0);
        ReadString(mBase + 4, snap->NearbyMonsters[i].Name, MAX_GAME_NAME_LEN);
        snap->NearbyMonsters[i].HP    = ReadDword(mBase + 36);
        snap->NearbyMonsters[i].MaxHP = ReadDword(mBase + 40);
        snap->NearbyMonsters[i].PosX  = ReadDword(mBase + 44);
        snap->NearbyMonsters[i].PosY  = ReadDword(mBase + 48);
        snap->NearbyMonsters[i].IsAlive = (snap->NearbyMonsters[i].HP > 0);
    }

    /* Чат */
    ReadString(OFFSET_CHAT_LAST_LINE, snap->LastChatLine,
               sizeof(snap->LastChatLine));
    snap->ChatLineCount = ReadDword(OFFSET_CHAT_LINE_COUNT);

    /* Урон и бой */
    snap->LastDamageDealt    = ReadDword(OFFSET_LAST_DAMAGE_DEALT);
    snap->LastDamageReceived = ReadDword(OFFSET_LAST_DAMAGE_RECV);
    snap->TotalDamageDealt   = ReadDword(OFFSET_TOTAL_DAMAGE_DEALT);
    snap->TotalDamageReceived = ReadDword(OFFSET_TOTAL_DAMAGE_RECV);
    snap->MonstersKilled     = ReadDword(OFFSET_MONSTERS_KILLED);

    /* Телепортация */
    snap->LastTeleportMap = ReadByte(OFFSET_TELEPORT_MAP);
    snap->LastTeleportX   = ReadDword(OFFSET_TELEPORT_X);
    snap->LastTeleportY   = ReadDword(OFFSET_TELEPORT_Y);

    /* Ввод: клавиатура */
    ReadMem(OFFSET_KEY_STATES, snap->KeyStates, 256);

    /* Ввод: мышь */
    snap->MouseX       = ReadDword(OFFSET_MOUSE_X);
    snap->MouseY       = ReadDword(OFFSET_MOUSE_Y);
    snap->MouseButtons = ReadByte(OFFSET_MOUSE_BUTTONS);
}

/* ============================================================
 * Сравнение снимков и логирование изменений
 * ============================================================ */

static DWORD DetectAndLogChanges(void)
{
    DWORD events = 0;
    DWORD i;

    /* --- Смена сцены --- */
    if (g_gmCurrent.Scene != g_gmPrevious.Scene)
    {
        LogGameEvent("SCENE", OFFSET_GAME_SCENE,
            "GameScene", NULL,
            "Scene changed: %s -> %s",
            GameMonitor_GetSceneName(g_gmPrevious.Scene),
            GameMonitor_GetSceneName(g_gmCurrent.Scene));
        events++;
        g_gmTotalSceneChanges++;

        /* Дополнительные подсказки по сцене */
        if (g_gmCurrent.Scene == SCENE_LOGIN)
        {
            LogGameEvent("SCENE", VA_FUNC_LOGIN_SCENE_INIT,
                NULL, "LoginSceneInit",
                "Login screen active");
            events++;
        }
        if (g_gmCurrent.Scene == SCENE_SERVER_SELECT)
        {
            LogGameEvent("SCENE", VA_FUNC_RECV_SERVERLIST,
                NULL, "RecvServerList",
                "Server selection screen");
            events++;
        }
    }

    /* --- Выбор сервера --- */
    if (g_gmCurrent.ServerGroup != g_gmPrevious.ServerGroup)
    {
        LogGameEvent("SERVER", OFFSET_SERVER_GROUP,
            "ServerGroup", "ServerGroupSelected",
            "Server group changed: %u -> %u",
            g_gmPrevious.ServerGroup, g_gmCurrent.ServerGroup);
        events++;
        g_gmTotalServerChanges++;
    }

    if (g_gmCurrent.ServerIndex != g_gmPrevious.ServerIndex)
    {
        LogGameEvent("SERVER", OFFSET_SERVER_INDEX,
            "ServerIndex", "ServerSelected",
            "Server selected: index %u -> %u",
            g_gmPrevious.ServerIndex, g_gmCurrent.ServerIndex);
        events++;
    }

    if (strcmp(g_gmCurrent.ServerName, g_gmPrevious.ServerName) != 0
        && g_gmCurrent.ServerName[0] != '\0')
    {
        LogGameEvent("SERVER", OFFSET_SERVER_NAME,
            "ServerName", NULL,
            "Server name: \"%s\"",
            g_gmCurrent.ServerName);
        events++;
    }

    /* --- Флаг подключения к серверу --- */
    if (g_gmCurrent.ServerConnected != g_gmPrevious.ServerConnected)
    {
        LogGameEvent("SERVER", OFFSET_SERVER_CONNECTED,
            "ServerConnected", "ConnectServer",
            "Server connection: %s (flag: %u -> %u)",
            g_gmCurrent.ServerConnected ? "CONNECTED" : "DISCONNECTED",
            (DWORD)g_gmPrevious.ServerConnected,
            (DWORD)g_gmCurrent.ServerConnected);
        events++;
    }

    /* --- Флаг получения списка серверов --- */
    if (g_gmCurrent.ServerListReceived != g_gmPrevious.ServerListReceived)
    {
        LogGameEvent("SERVER", OFFSET_SERVER_LIST_RECV,
            "ServerListReceived", "RecvServerList",
            "Server list received: %u -> %u",
            (DWORD)g_gmPrevious.ServerListReceived,
            (DWORD)g_gmCurrent.ServerListReceived);
        events++;
    }

    /* --- Логин/пароль --- */
    if (g_gmCurrent.LoginFieldLen != g_gmPrevious.LoginFieldLen)
    {
        LogGameEvent("LOGIN", OFFSET_LOGIN_ID,
            "LoginID", NULL,
            "Login field input: length %u -> %u",
            g_gmPrevious.LoginFieldLen, g_gmCurrent.LoginFieldLen);
        events++;
    }

    if (g_gmCurrent.LoginFieldLen > 0
        && strcmp(g_gmCurrent.LoginField, g_gmPrevious.LoginField) != 0)
    {
        LogGameEvent("LOGIN", OFFSET_LOGIN_ID,
            "LoginID", "LoginRequest",
            "Login ID changed: \"%s\" (len=%u)",
            g_gmCurrent.LoginField,
            g_gmCurrent.LoginFieldLen);
        events++;
    }

    /* --- Длина пароля --- */
    if (g_gmCurrent.PasswordFieldLen != g_gmPrevious.PasswordFieldLen)
    {
        LogGameEvent("LOGIN", OFFSET_LOGIN_PW_LEN,
            "LoginPWLen", NULL,
            "Password field length: %u -> %u",
            g_gmPrevious.PasswordFieldLen, g_gmCurrent.PasswordFieldLen);
        events++;
    }

    /* --- Состояние авторизации --- */
    if (g_gmCurrent.LoginState != g_gmPrevious.LoginState)
    {
        LogGameEvent("LOGIN", OFFSET_LOGIN_STATE,
            "LoginState", "LoginRequest",
            "Login state changed: %u -> %u",
            g_gmPrevious.LoginState, g_gmCurrent.LoginState);
        events++;
    }

    /* --- Результат логина --- */
    if (g_gmCurrent.LoginResult != g_gmPrevious.LoginResult)
    {
        LogGameEvent("LOGIN", OFFSET_LOGIN_RESULT,
            "LoginResult", NULL,
            "Login result: %u -> %u (%s)",
            (DWORD)g_gmPrevious.LoginResult,
            (DWORD)g_gmCurrent.LoginResult,
            g_gmCurrent.LoginResult == 0 ? "OK" : "ERROR");
        events++;
    }

    /* --- Выбор персонажа --- */
    if (g_gmCurrent.CharacterCount != g_gmPrevious.CharacterCount)
    {
        LogGameEvent("CHARACTER", OFFSET_CHAR_COUNT,
            "CharCount", NULL,
            "Character count: %u -> %u",
            g_gmPrevious.CharacterCount, g_gmCurrent.CharacterCount);
        events++;
    }

    if (g_gmCurrent.SelectedCharIndex != g_gmPrevious.SelectedCharIndex)
    {
        LogGameEvent("CHARACTER", OFFSET_CHAR_SELECTED,
            "CharSelected", NULL,
            "Character selected: slot %u -> %u",
            g_gmPrevious.SelectedCharIndex, g_gmCurrent.SelectedCharIndex);
        events++;
    }

    if (strcmp(g_gmCurrent.Character.Name, g_gmPrevious.Character.Name) != 0
        && g_gmCurrent.Character.Name[0] != '\0')
    {
        LogGameEvent("CHARACTER", OFFSET_CHAR_NAME,
            "CharName", NULL,
            "Character: \"%s\" Class: %s Level: %u",
            g_gmCurrent.Character.Name,
            GetClassName(g_gmCurrent.Character.Class),
            g_gmCurrent.Character.Level);
        events++;
    }

    /* --- Уровень персонажа --- */
    if (g_gmCurrent.Character.Level != g_gmPrevious.Character.Level
        && g_gmCurrent.Character.Level > 0)
    {
        LogGameEvent("LEVEL", OFFSET_CHAR_LEVEL,
            "CharLevel", "LevelUpSound",
            "LEVEL UP! %u -> %u",
            g_gmPrevious.Character.Level, g_gmCurrent.Character.Level);
        events++;
        g_gmTotalLevelUps++;
    }

    /* --- HP/MP изменения --- */
    if (g_gmCurrent.Character.HP != g_gmPrevious.Character.HP
        && g_gmCurrent.Character.HP > 0)
    {
        if (g_gmCurrent.Character.HP < g_gmPrevious.Character.HP)
        {
            LogGameEvent("COMBAT", OFFSET_CHAR_HP,
                "CharHP", NULL,
                "HP decreased: %u -> %u (-%u) (MaxHP:%u)",
                g_gmPrevious.Character.HP, g_gmCurrent.Character.HP,
                g_gmPrevious.Character.HP - g_gmCurrent.Character.HP,
                g_gmCurrent.Character.MaxHP);
            events++;
        }
        else
        {
            LogGameEvent("COMBAT", OFFSET_CHAR_HP,
                "CharHP", NULL,
                "HP recovered: %u -> %u (+%u)",
                g_gmPrevious.Character.HP, g_gmCurrent.Character.HP,
                g_gmCurrent.Character.HP - g_gmPrevious.Character.HP);
            events++;
        }
    }

    if (g_gmCurrent.Character.MP != g_gmPrevious.Character.MP
        && g_gmCurrent.Character.MP > 0
        && g_gmPrevious.Character.MP > 0)
    {
        LogGameEvent("COMBAT", OFFSET_CHAR_MP,
            "CharMP", NULL,
            "MP changed: %u -> %u",
            g_gmPrevious.Character.MP, g_gmCurrent.Character.MP);
        events++;
    }

    /* --- Урон нанесённый --- */
    if (g_gmCurrent.LastDamageDealt != g_gmPrevious.LastDamageDealt
        && g_gmCurrent.LastDamageDealt > 0)
    {
        LogGameEvent("DAMAGE", OFFSET_LAST_DAMAGE_DEALT,
            "LastDamageDealt", NULL,
            "Damage dealt: %u (total: %u)",
            g_gmCurrent.LastDamageDealt, g_gmCurrent.TotalDamageDealt);
        events++;
    }

    /* --- Урон полученный --- */
    if (g_gmCurrent.LastDamageReceived != g_gmPrevious.LastDamageReceived
        && g_gmCurrent.LastDamageReceived > 0)
    {
        LogGameEvent("DAMAGE", OFFSET_LAST_DAMAGE_RECV,
            "LastDamageRecv", NULL,
            "Damage received: %u (total: %u)",
            g_gmCurrent.LastDamageReceived, g_gmCurrent.TotalDamageReceived);
        events++;
    }

    /* --- Убийство монстров --- */
    if (g_gmCurrent.MonstersKilled != g_gmPrevious.MonstersKilled
        && g_gmCurrent.MonstersKilled > g_gmPrevious.MonstersKilled)
    {
        LogGameEvent("KILL", OFFSET_MONSTERS_KILLED,
            "MonstersKilled", "MonsterDieSound",
            "Monster killed! Total kills: %u",
            g_gmCurrent.MonstersKilled);
        events++;
    }

    /* --- Инвентарь --- */
    if (g_gmCurrent.InventoryItemCount != g_gmPrevious.InventoryItemCount)
    {
        LogGameEvent("INVENTORY", OFFSET_INVENTORY_COUNT,
            "InventoryCount", "OpenPersonalShop",
            "Inventory changed: %u -> %u items",
            g_gmPrevious.InventoryItemCount, g_gmCurrent.InventoryItemCount);
        events++;
    }

    /* --- Ближайшие игроки --- */
    if (g_gmCurrent.NearbyPlayerCount != g_gmPrevious.NearbyPlayerCount)
    {
        LogGameEvent("PLAYERS", OFFSET_PLAYER_LIST_COUNT,
            "PlayerListCount", NULL,
            "Nearby players: %u -> %u",
            g_gmPrevious.NearbyPlayerCount, g_gmCurrent.NearbyPlayerCount);
        events++;

        /* Логируем новых игроков */
        if (g_gmCurrent.NearbyPlayerCount > g_gmPrevious.NearbyPlayerCount)
        {
            for (i = 0; i < g_gmCurrent.NearbyPlayerCount; i++)
            {
                if (g_gmCurrent.NearbyPlayers[i].Name[0] != '\0')
                {
                    DWORD pVA = OFFSET_PLAYER_LIST_BASE + i * PLAYER_STRUCT_SIZE;
                    BOOL isNew = TRUE;
                    DWORD j;

                    for (j = 0; j < g_gmPrevious.NearbyPlayerCount; j++)
                    {
                        if (g_gmCurrent.NearbyPlayers[i].Id ==
                            g_gmPrevious.NearbyPlayers[j].Id)
                        {
                            isNew = FALSE;
                            break;
                        }
                    }

                    if (isNew)
                    {
                        LogGameEvent("PLAYERS", pVA,
                            "PlayerEntry", NULL,
                            "  New player nearby: \"%s\" HP:%u/%u Pos:(%u,%u)",
                            g_gmCurrent.NearbyPlayers[i].Name,
                            g_gmCurrent.NearbyPlayers[i].HP,
                            g_gmCurrent.NearbyPlayers[i].MaxHP,
                            g_gmCurrent.NearbyPlayers[i].PosX,
                            g_gmCurrent.NearbyPlayers[i].PosY);
                        events++;
                    }
                }
            }
        }
    }

    /* --- Ближайшие монстры --- */
    if (g_gmCurrent.NearbyMonsterCount != g_gmPrevious.NearbyMonsterCount)
    {
        LogGameEvent("MONSTERS", OFFSET_MONSTER_LIST_COUNT,
            "MonsterListCount", NULL,
            "Nearby monsters: %u -> %u",
            g_gmPrevious.NearbyMonsterCount, g_gmCurrent.NearbyMonsterCount);
        events++;

        /* Логируем новых монстров */
        if (g_gmCurrent.NearbyMonsterCount > g_gmPrevious.NearbyMonsterCount)
        {
            for (i = 0; i < g_gmCurrent.NearbyMonsterCount; i++)
            {
                if (g_gmCurrent.NearbyMonsters[i].Name[0] != '\0')
                {
                    DWORD mVA = OFFSET_MONSTER_LIST_BASE + i * MONSTER_STRUCT_SIZE;
                    BOOL isNew = TRUE;
                    DWORD j;

                    for (j = 0; j < g_gmPrevious.NearbyMonsterCount; j++)
                    {
                        if (g_gmCurrent.NearbyMonsters[i].Id ==
                            g_gmPrevious.NearbyMonsters[j].Id)
                        {
                            isNew = FALSE;
                            break;
                        }
                    }

                    if (isNew)
                    {
                        LogGameEvent("MONSTERS", mVA,
                            "MonsterEntry", NULL,
                            "  New monster: \"%s\" HP:%u/%u Pos:(%u,%u)",
                            g_gmCurrent.NearbyMonsters[i].Name,
                            g_gmCurrent.NearbyMonsters[i].HP,
                            g_gmCurrent.NearbyMonsters[i].MaxHP,
                            g_gmCurrent.NearbyMonsters[i].PosX,
                            g_gmCurrent.NearbyMonsters[i].PosY);
                        events++;
                    }
                }
            }
        }
    }

    /* Логируем ХП монстров, если изменились */
    for (i = 0; i < g_gmCurrent.NearbyMonsterCount && i < g_gmPrevious.NearbyMonsterCount; i++)
    {
        if (g_gmCurrent.NearbyMonsters[i].Id == g_gmPrevious.NearbyMonsters[i].Id
            && g_gmCurrent.NearbyMonsters[i].HP != g_gmPrevious.NearbyMonsters[i].HP
            && g_gmCurrent.NearbyMonsters[i].Name[0] != '\0')
        {
            DWORD mVA = OFFSET_MONSTER_LIST_BASE + i * MONSTER_STRUCT_SIZE + 36;
            LogGameEvent("MONSTER_HP", mVA,
                "MonsterHP", NULL,
                "Monster \"%s\" HP: %u -> %u",
                g_gmCurrent.NearbyMonsters[i].Name,
                g_gmPrevious.NearbyMonsters[i].HP,
                g_gmCurrent.NearbyMonsters[i].HP);
            events++;
        }
    }

    /* --- Чат --- */
    if (g_gmCurrent.ChatLineCount != g_gmPrevious.ChatLineCount
        && g_gmCurrent.LastChatLine[0] != '\0')
    {
        LogGameEvent("CHAT", OFFSET_CHAT_LAST_LINE,
            "ChatLastLine", NULL,
            "Chat message: \"%s\" (count=%u)",
            g_gmCurrent.LastChatLine,
            g_gmCurrent.ChatLineCount);
        events++;
        g_gmTotalChatMessages++;
    }

    /* --- Телепортация --- */
    if (g_gmCurrent.Character.MapId != g_gmPrevious.Character.MapId
        && (g_gmPrevious.Character.PosX > 0
            || g_gmPrevious.Character.PosY > 0))
    {
        LogGameEvent("TELEPORT", OFFSET_CHAR_MAP_ID,
            "CharMapId", NULL,
            "Teleport! Map: %s(%u) -> %s(%u)",
            GetMapName(g_gmPrevious.Character.MapId),
            g_gmPrevious.Character.MapId,
            GetMapName(g_gmCurrent.Character.MapId),
            g_gmCurrent.Character.MapId);
        events++;
        g_gmTotalTeleports++;
    }
    else if (g_gmCurrent.LastTeleportX != g_gmPrevious.LastTeleportX
             || g_gmCurrent.LastTeleportY != g_gmPrevious.LastTeleportY)
    {
        if (g_gmCurrent.LastTeleportX != 0 || g_gmCurrent.LastTeleportY != 0)
        {
            LogGameEvent("TELEPORT", OFFSET_TELEPORT_X,
                "TeleportX", NULL,
                "Teleport position: (%u, %u) Map:%s",
                g_gmCurrent.LastTeleportX, g_gmCurrent.LastTeleportY,
                GetMapName(g_gmCurrent.LastTeleportMap));
            events++;
            g_gmTotalTeleports++;
        }
    }

    /* --- Позиция персонажа (значительное перемещение) --- */
    {
        int dx = (int)g_gmCurrent.Character.PosX - (int)g_gmPrevious.Character.PosX;
        int dy = (int)g_gmCurrent.Character.PosY - (int)g_gmPrevious.Character.PosY;
        if (dx < 0) dx = -dx;
        if (dy < 0) dy = -dy;

        if ((dx > 5 || dy > 5)
            && (g_gmCurrent.Character.PosX > 0
                || g_gmCurrent.Character.PosY > 0))
        {
            LogGameEvent("MOVE", OFFSET_CHAR_POS_X,
                "CharPosX", NULL,
                "Character moved: (%u,%u) -> (%u,%u)",
                g_gmPrevious.Character.PosX, g_gmPrevious.Character.PosY,
                g_gmCurrent.Character.PosX, g_gmCurrent.Character.PosY);
            events++;
        }
    }

    /* --- Клавиатура --- */
    {
        DWORD keyEvents = 0;
        for (i = 0; i < 256; i++)
        {
            if (g_gmCurrent.KeyStates[i] != g_gmPrevious.KeyStates[i])
            {
                if (g_gmCurrent.KeyStates[i] != 0)
                {
                    /* Клавиша нажата */
                    DWORD keyVA = OFFSET_KEY_STATES + i;
                    const char* keyName = "";

                    /* Определяем имя клавиши для наиболее частых */
                    switch (i)
                    {
                        case 0x01: keyName = "LMouse"; break;
                        case 0x02: keyName = "RMouse"; break;
                        case 0x04: keyName = "MMouse"; break;
                        case 0x08: keyName = "Backspace"; break;
                        case 0x09: keyName = "Tab"; break;
                        case 0x0D: keyName = "Enter"; break;
                        case 0x10: keyName = "Shift"; break;
                        case 0x11: keyName = "Ctrl"; break;
                        case 0x12: keyName = "Alt"; break;
                        case 0x14: keyName = "CapsLock"; break;
                        case 0x1B: keyName = "Escape"; break;
                        case 0x20: keyName = "Space"; break;
                        case 0x25: keyName = "Left"; break;
                        case 0x26: keyName = "Up"; break;
                        case 0x27: keyName = "Right"; break;
                        case 0x28: keyName = "Down"; break;
                        case 0x2D: keyName = "Insert"; break;
                        case 0x2E: keyName = "Delete"; break;
                        case 0x70: keyName = "F1"; break;
                        case 0x71: keyName = "F2"; break;
                        case 0x72: keyName = "F3"; break;
                        case 0x73: keyName = "F4"; break;
                        case 0x74: keyName = "F5"; break;
                        case 0x75: keyName = "F6"; break;
                        case 0x76: keyName = "F7"; break;
                        case 0x77: keyName = "F8"; break;
                        case 0x78: keyName = "F9"; break;
                        case 0x79: keyName = "F10"; break;
                        case 0x7A: keyName = "F11"; break;
                        case 0x7B: keyName = "F12"; break;
                        default:
                            if (i >= 0x30 && i <= 0x39)
                                keyName = "0-9";
                            else if (i >= 0x41 && i <= 0x5A)
                                keyName = "A-Z";
                            break;
                    }

                    LogGameEvent("KEY", keyVA,
                        "KeyStates", NULL,
                        "Key pressed: VK=0x%02X (%s)",
                        i, keyName);
                    events++;
                    keyEvents++;
                    g_gmTotalKeyPresses++;
                }
            }
        }
    }

    /* --- Мышь --- */
    if (g_gmCurrent.MouseButtons != g_gmPrevious.MouseButtons)
    {
        const char* btnName = GetMouseButtonName(
            g_gmCurrent.MouseButtons, g_gmPrevious.MouseButtons);

        if (btnName != NULL)
        {
            LogGameEvent("MOUSE", OFFSET_MOUSE_BUTTONS,
                "MouseButtons", NULL,
                "Mouse %s click at (%u, %u)",
                btnName,
                g_gmCurrent.MouseX, g_gmCurrent.MouseY);
            events++;
            g_gmTotalMouseClicks++;
        }
    }

    /* Значительное перемещение мыши */
    {
        int mdx = (int)g_gmCurrent.MouseX - (int)g_gmPrevious.MouseX;
        int mdy = (int)g_gmCurrent.MouseY - (int)g_gmPrevious.MouseY;
        if (mdx < 0) mdx = -mdx;
        if (mdy < 0) mdy = -mdy;

        if ((mdx > 50 || mdy > 50)
            && (g_gmCurrent.MouseX > 0 || g_gmCurrent.MouseY > 0))
        {
            LogGameEvent("MOUSE", OFFSET_MOUSE_X,
                "MouseX", NULL,
                "Mouse moved: (%u,%u) -> (%u,%u)",
                g_gmPrevious.MouseX, g_gmPrevious.MouseY,
                g_gmCurrent.MouseX, g_gmCurrent.MouseY);
            events++;
        }
    }

    /* --- Опыт --- */
    if (g_gmCurrent.Character.Experience != g_gmPrevious.Character.Experience
        && g_gmCurrent.Character.Experience > 0
        && g_gmPrevious.Character.Experience > 0)
    {
        DWORD expGain = g_gmCurrent.Character.Experience
                        - g_gmPrevious.Character.Experience;
        if (g_gmCurrent.Character.Experience > g_gmPrevious.Character.Experience)
        {
            LogGameEvent("EXP", OFFSET_CHAR_EXP,
                "CharExp", NULL,
                "Experience gained: +%u (total: %u)",
                expGain, g_gmCurrent.Character.Experience);
            events++;
        }
    }

    /* ============================================================
     * Обнаружение новых активных офсетов (discovery)
     *
     * Логируем каждый офсет при первом обнаружении ненулевого значения.
     * Это позволяет перехватить все найденные новые офсеты из main.exe.
     * ============================================================ */

    /* Scene/State */
    if ((DWORD)g_gmCurrent.Scene != 0)
        DiscoverOffset(DISC_GAME_SCENE, (DWORD)g_gmCurrent.Scene);
    if (g_gmCurrent.GameTick != 0)
        DiscoverOffset(DISC_GAME_TICK, g_gmCurrent.GameTick);

    /* Server */
    if (g_gmCurrent.ServerGroup != 0)
        DiscoverOffset(DISC_SERVER_GROUP, g_gmCurrent.ServerGroup);
    if (g_gmCurrent.ServerIndex != 0)
        DiscoverOffset(DISC_SERVER_INDEX, g_gmCurrent.ServerIndex);
    if (g_gmCurrent.ServerName[0] != '\0')
        DiscoverOffsetStr(DISC_SERVER_NAME, g_gmCurrent.ServerName);
    if (g_gmCurrent.ServerConnected != 0)
        DiscoverOffset(DISC_SERVER_CONNECTED, (DWORD)g_gmCurrent.ServerConnected);
    if (g_gmCurrent.ServerListReceived != 0)
        DiscoverOffset(DISC_SERVER_LIST_RECV, (DWORD)g_gmCurrent.ServerListReceived);

    /* Login/Auth */
    if (g_gmCurrent.LoginField[0] != '\0')
        DiscoverOffsetStr(DISC_LOGIN_ID, g_gmCurrent.LoginField);
    if (g_gmCurrent.LoginFieldLen != 0)
        DiscoverOffset(DISC_LOGIN_ID_LEN, g_gmCurrent.LoginFieldLen);
    if (g_gmCurrent.PasswordFieldLen != 0)
        DiscoverOffset(DISC_LOGIN_PW_LEN, g_gmCurrent.PasswordFieldLen);
    if (g_gmCurrent.LoginState != 0)
        DiscoverOffset(DISC_LOGIN_STATE, g_gmCurrent.LoginState);
    if (g_gmCurrent.LoginResult != 0)
        DiscoverOffset(DISC_LOGIN_RESULT, (DWORD)g_gmCurrent.LoginResult);

    /* Character */
    if (g_gmCurrent.CharacterCount != 0)
        DiscoverOffset(DISC_CHAR_COUNT, g_gmCurrent.CharacterCount);
    if (g_gmCurrent.SelectedCharIndex != 0)
        DiscoverOffset(DISC_CHAR_SELECTED, g_gmCurrent.SelectedCharIndex);
    if (g_gmCurrent.Character.Name[0] != '\0')
        DiscoverOffsetStr(DISC_CHAR_NAME, g_gmCurrent.Character.Name);
    if (g_gmCurrent.Character.Level != 0)
        DiscoverOffset(DISC_CHAR_LEVEL, g_gmCurrent.Character.Level);
    if (g_gmCurrent.Character.Class != 0)
        DiscoverOffset(DISC_CHAR_CLASS, (DWORD)g_gmCurrent.Character.Class);
    if (g_gmCurrent.Character.HP != 0)
        DiscoverOffset(DISC_CHAR_HP, g_gmCurrent.Character.HP);
    if (g_gmCurrent.Character.MaxHP != 0)
        DiscoverOffset(DISC_CHAR_MAX_HP, g_gmCurrent.Character.MaxHP);
    if (g_gmCurrent.Character.MP != 0)
        DiscoverOffset(DISC_CHAR_MP, g_gmCurrent.Character.MP);
    if (g_gmCurrent.Character.MaxMP != 0)
        DiscoverOffset(DISC_CHAR_MAX_MP, g_gmCurrent.Character.MaxMP);
    if (g_gmCurrent.Character.Experience != 0)
        DiscoverOffset(DISC_CHAR_EXP, g_gmCurrent.Character.Experience);
    if (g_gmCurrent.Character.PosX != 0)
        DiscoverOffset(DISC_CHAR_POS_X, g_gmCurrent.Character.PosX);
    if (g_gmCurrent.Character.PosY != 0)
        DiscoverOffset(DISC_CHAR_POS_Y, g_gmCurrent.Character.PosY);
    if (g_gmCurrent.Character.MapId != 0)
        DiscoverOffset(DISC_CHAR_MAP_ID, (DWORD)g_gmCurrent.Character.MapId);

    /* Inventory */
    if (g_gmCurrent.InventoryItemCount != 0)
    {
        DiscoverOffset(DISC_INVENTORY_COUNT, g_gmCurrent.InventoryItemCount);
        DiscoverOffset(DISC_INVENTORY_BASE, g_gmCurrent.InventoryItemCount);
    }

    /* Players */
    if (g_gmCurrent.NearbyPlayerCount != 0)
    {
        DiscoverOffset(DISC_PLAYER_LIST_COUNT, g_gmCurrent.NearbyPlayerCount);
        DiscoverOffset(DISC_PLAYER_LIST_BASE, g_gmCurrent.NearbyPlayerCount);
    }

    /* Monsters */
    if (g_gmCurrent.NearbyMonsterCount != 0)
    {
        DiscoverOffset(DISC_MONSTER_LIST_COUNT, g_gmCurrent.NearbyMonsterCount);
        DiscoverOffset(DISC_MONSTER_LIST_BASE, g_gmCurrent.NearbyMonsterCount);
    }

    /* Chat */
    if (g_gmCurrent.LastChatLine[0] != '\0')
        DiscoverOffsetStr(DISC_CHAT_LAST_LINE, g_gmCurrent.LastChatLine);
    if (g_gmCurrent.ChatLineCount != 0)
        DiscoverOffset(DISC_CHAT_LINE_COUNT, g_gmCurrent.ChatLineCount);

    /* Combat */
    if (g_gmCurrent.LastDamageDealt != 0)
        DiscoverOffset(DISC_LAST_DAMAGE_DEALT, g_gmCurrent.LastDamageDealt);
    if (g_gmCurrent.LastDamageReceived != 0)
        DiscoverOffset(DISC_LAST_DAMAGE_RECV, g_gmCurrent.LastDamageReceived);
    if (g_gmCurrent.TotalDamageDealt != 0)
        DiscoverOffset(DISC_TOTAL_DAMAGE_DEALT, g_gmCurrent.TotalDamageDealt);
    if (g_gmCurrent.TotalDamageReceived != 0)
        DiscoverOffset(DISC_TOTAL_DAMAGE_RECV, g_gmCurrent.TotalDamageReceived);
    if (g_gmCurrent.MonstersKilled != 0)
        DiscoverOffset(DISC_MONSTERS_KILLED, g_gmCurrent.MonstersKilled);

    /* Teleport */
    if (g_gmCurrent.LastTeleportMap != 0)
        DiscoverOffset(DISC_TELEPORT_MAP, (DWORD)g_gmCurrent.LastTeleportMap);
    if (g_gmCurrent.LastTeleportX != 0)
        DiscoverOffset(DISC_TELEPORT_X, g_gmCurrent.LastTeleportX);
    if (g_gmCurrent.LastTeleportY != 0)
        DiscoverOffset(DISC_TELEPORT_Y, g_gmCurrent.LastTeleportY);

    /* Input: keyboard */
    {
        BOOL anyKey = FALSE;
        for (i = 0; i < 256 && !anyKey; i++)
        {
            if (g_gmCurrent.KeyStates[i] != 0)
                anyKey = TRUE;
        }
        if (anyKey)
            DiscoverOffset(DISC_KEY_STATES, 1);
    }

    /* Input: mouse */
    if (g_gmCurrent.MouseX != 0)
        DiscoverOffset(DISC_MOUSE_X, g_gmCurrent.MouseX);
    if (g_gmCurrent.MouseY != 0)
        DiscoverOffset(DISC_MOUSE_Y, g_gmCurrent.MouseY);
    if (g_gmCurrent.MouseButtons != 0)
        DiscoverOffset(DISC_MOUSE_BUTTONS, (DWORD)g_gmCurrent.MouseButtons);

    return events;
}

/* ============================================================
 * Логирование всех офсетов при запуске
 * ============================================================ */

static void LogAllGameOffsets(void)
{
    Logger_WriteHeader(
        "GAME STATE OFFSETS (OFSETY IGROVOGO SOSTOYANIYA)");

    Logger_Write(COLOR_INFO,
        "  All game action offsets with variable/function names:\n");
    Logger_Write(COLOR_INFO,
        "  Format: VA  Name  Description\n\n");

    /* Сцена */
    Logger_Write(COLOR_SECTION, "  --- Scene/State ---\n");
    Logger_WriteVariable(OFFSET_GAME_SCENE, 0,
        "GameScene", "Current game scene (DWORD: 0=Unknown..6=Loading)");
    Logger_WriteVariable(OFFSET_GAME_TICK, 0,
        "GameTick", "Game tick counter (DWORD)");

    /* Сервер */
    Logger_Write(COLOR_SECTION, "\n  --- Server Selection ---\n");
    Logger_WriteVariable(OFFSET_SERVER_GROUP, 0,
        "ServerGroup", "Selected server group index (DWORD)");
    Logger_WriteVariable(OFFSET_SERVER_INDEX, 0,
        "ServerIndex", "Selected server index (DWORD)");
    Logger_WriteVariable(OFFSET_SERVER_NAME, 0,
        "ServerName", "Current server name (char[32])");
    Logger_WriteVariable(OFFSET_SERVER_CONNECTED, 0,
        "ServerConnected", "Server connection flag (BYTE: 0/1)");
    Logger_WriteVariable(OFFSET_SERVER_LIST_RECV, 0,
        "ServerListReceived", "Server list received flag (BYTE: 0/1)");
    Logger_WriteFunction(VA_FUNC_SERVER_GROUP_SEL, 0,
        "Func_ServerGroupSelected", "> Server group selected - %d");
    Logger_WriteFunction(VA_FUNC_SERVER_SELECTED, 0,
        "Func_ServerSelected", "> Server selected - %s-%d : %d-%d");
    Logger_WriteFunction(VA_FUNC_RECV_SERVERLIST, 0,
        "Func_RecvServerList", "Success Receive Server List.");

    /* Логин/авторизация */
    Logger_Write(COLOR_SECTION, "\n  --- Login/Auth ---\n");
    Logger_WriteVariable(OFFSET_LOGIN_ID, 0,
        "LoginID", "Account login field (char[14])");
    Logger_WriteVariable(OFFSET_LOGIN_ID_LEN, 0,
        "LoginIDLen", "Login field length (BYTE)");
    Logger_WriteVariable(OFFSET_LOGIN_PW_LEN, 0,
        "LoginPWLen", "Password field length (BYTE)");
    Logger_WriteVariable(OFFSET_LOGIN_STATE, 0,
        "LoginState", "Authorization state (DWORD)");
    Logger_WriteVariable(OFFSET_LOGIN_RESULT, 0,
        "LoginResult", "Login result code (BYTE: 0=OK)");
    Logger_WriteFunction(VA_FUNC_LOGIN_SCENE_INIT, 0,
        "Func_LoginSceneInit", "> Login Scene init success.");
    Logger_WriteFunction(VA_FUNC_LOGIN_REQUEST, 0,
        "Func_LoginRequest", "> Login Request.");

    /* Персонажи */
    Logger_Write(COLOR_SECTION, "\n  --- Character ---\n");
    Logger_WriteVariable(OFFSET_CHAR_COUNT, 0,
        "CharCount", "Number of characters on account (DWORD)");
    Logger_WriteVariable(OFFSET_CHAR_SELECTED, 0,
        "CharSelected", "Selected character slot index (DWORD)");
    Logger_WriteVariable(OFFSET_CHAR_NAME, 0,
        "CharName", "Character name (char[11])");
    Logger_WriteVariable(OFFSET_CHAR_LEVEL, 0,
        "CharLevel", "Character level (DWORD)");
    Logger_WriteVariable(OFFSET_CHAR_CLASS, 0,
        "CharClass", "Character class ID (BYTE)");
    Logger_WriteVariable(OFFSET_CHAR_HP, 0,
        "CharHP", "Character current HP (DWORD)");
    Logger_WriteVariable(OFFSET_CHAR_MAX_HP, 0,
        "CharMaxHP", "Character max HP (DWORD)");
    Logger_WriteVariable(OFFSET_CHAR_MP, 0,
        "CharMP", "Character current MP (DWORD)");
    Logger_WriteVariable(OFFSET_CHAR_MAX_MP, 0,
        "CharMaxMP", "Character max MP (DWORD)");
    Logger_WriteVariable(OFFSET_CHAR_EXP, 0,
        "CharExp", "Character experience (DWORD)");
    Logger_WriteVariable(OFFSET_CHAR_POS_X, 0,
        "CharPosX", "Character position X (DWORD)");
    Logger_WriteVariable(OFFSET_CHAR_POS_Y, 0,
        "CharPosY", "Character position Y (DWORD)");
    Logger_WriteVariable(OFFSET_CHAR_MAP_ID, 0,
        "CharMapId", "Current map ID (BYTE)");

    /* Инвентарь */
    Logger_Write(COLOR_SECTION, "\n  --- Inventory ---\n");
    Logger_WriteVariable(OFFSET_INVENTORY_BASE, 0,
        "InventoryBase", "Inventory item array start (ITEM_STRUCT[64])");
    Logger_WriteVariable(OFFSET_INVENTORY_COUNT, 0,
        "InventoryCount", "Number of items in inventory (DWORD)");
    Logger_WriteFunction(VA_FUNC_OPEN_SHOP, 0,
        "Func_OpenPersonalShop", "@ OpenPersonalShop : SendRequestInventory");

    /* Ближайшие игроки */
    Logger_Write(COLOR_SECTION, "\n  --- Nearby Players ---\n");
    Logger_WriteVariable(OFFSET_PLAYER_LIST_BASE, 0,
        "PlayerListBase", "Nearby players array start (ENTITY[40])");
    Logger_WriteVariable(OFFSET_PLAYER_LIST_COUNT, 0,
        "PlayerListCount", "Number of nearby players (DWORD)");

    /* Ближайшие монстры */
    Logger_Write(COLOR_SECTION, "\n  --- Nearby Monsters ---\n");
    Logger_WriteVariable(OFFSET_MONSTER_LIST_BASE, 0,
        "MonsterListBase", "Nearby monsters array start (ENTITY[40])");
    Logger_WriteVariable(OFFSET_MONSTER_LIST_COUNT, 0,
        "MonsterListCount", "Number of nearby monsters (DWORD)");

    /* Чат */
    Logger_Write(COLOR_SECTION, "\n  --- Chat ---\n");
    Logger_WriteVariable(OFFSET_CHAT_LAST_LINE, 0,
        "ChatLastLine", "Last chat message (char[128])");
    Logger_WriteVariable(OFFSET_CHAT_LINE_COUNT, 0,
        "ChatLineCount", "Total chat messages count (DWORD)");

    /* Урон / бой */
    Logger_Write(COLOR_SECTION, "\n  --- Combat/Damage ---\n");
    Logger_WriteVariable(OFFSET_LAST_DAMAGE_DEALT, 0,
        "LastDamageDealt", "Last damage dealt to monster/player (DWORD)");
    Logger_WriteVariable(OFFSET_LAST_DAMAGE_RECV, 0,
        "LastDamageRecv", "Last damage received from monster/player (DWORD)");
    Logger_WriteVariable(OFFSET_TOTAL_DAMAGE_DEALT, 0,
        "TotalDamageDealt", "Total damage dealt this session (DWORD)");
    Logger_WriteVariable(OFFSET_TOTAL_DAMAGE_RECV, 0,
        "TotalDamageRecv", "Total damage received this session (DWORD)");
    Logger_WriteVariable(OFFSET_MONSTERS_KILLED, 0,
        "MonstersKilled", "Total monsters killed this session (DWORD)");

    /* Телепортация */
    Logger_Write(COLOR_SECTION, "\n  --- Teleportation ---\n");
    Logger_WriteVariable(OFFSET_TELEPORT_MAP, 0,
        "TeleportMap", "Teleport destination map ID (BYTE)");
    Logger_WriteVariable(OFFSET_TELEPORT_X, 0,
        "TeleportX", "Teleport destination X (DWORD)");
    Logger_WriteVariable(OFFSET_TELEPORT_Y, 0,
        "TeleportY", "Teleport destination Y (DWORD)");

    /* Ввод с клавиатуры и мыши */
    Logger_Write(COLOR_SECTION, "\n  --- Keyboard/Mouse Input ---\n");
    Logger_WriteVariable(OFFSET_KEY_STATES, 0,
        "KeyStates", "Keyboard key state array (BYTE[256])");
    Logger_WriteVariable(OFFSET_MOUSE_X, 0,
        "MouseX", "Mouse cursor X position (DWORD)");
    Logger_WriteVariable(OFFSET_MOUSE_Y, 0,
        "MouseY", "Mouse cursor Y position (DWORD)");
    Logger_WriteVariable(OFFSET_MOUSE_BUTTONS, 0,
        "MouseButtons", "Mouse button state (BYTE: bit0=L, bit1=R, bit2=M)");

    Logger_Write(COLOR_DEFAULT, "\n");
}

/* ============================================================
 * Реализация API
 * ============================================================ */

BOOL GameMonitor_Init(HANDLE hProcess, DWORD processId)
{
    if (g_gmInitialized)
        return TRUE;

    if (hProcess == NULL || processId == 0)
        return FALSE;

    g_gmProcess     = hProcess;
    g_gmProcessId   = processId;
    g_gmStartTime   = GetTickCount();
    g_gmLastUpdate  = g_gmStartTime;
    g_gmEventCount  = 0;
    g_gmInitialized = TRUE;

    g_gmTotalSceneChanges  = 0;
    g_gmTotalKeyPresses    = 0;
    g_gmTotalMouseClicks   = 0;
    g_gmTotalChatMessages  = 0;
    g_gmTotalTeleports     = 0;
    g_gmTotalServerChanges = 0;
    g_gmTotalLevelUps      = 0;

    memset(&g_gmCurrent, 0, sizeof(GAME_STATE_SNAPSHOT));
    memset(&g_gmPrevious, 0, sizeof(GAME_STATE_SNAPSHOT));

    /* Инициализация таблицы обнаружения офсетов */
    InitDiscoveryTable();

    Logger_Write(COLOR_DEFAULT, "\n");
    Logger_WriteHeader(
        "GAME MONITOR INITIALIZED (MONITOR IGROVYH DEJSTVIJ)");
    Logger_Write(COLOR_INFO,
        "  Process: PID=%u  Handle=0x%p\n", processId, (void*)hProcess);
    Logger_Write(COLOR_INFO,
        "  Tracking ALL game actions: server, login, character, inventory,\n");
    Logger_Write(COLOR_INFO,
        "  chat, teleport, combat, monsters, players, keyboard, mouse\n");
    Logger_Write(COLOR_INFO,
        "  Offset discovery: tracking %u game state offsets for new data\n\n",
        (DWORD)DISC_COUNT);

    /* Выводим полный список отслеживаемых офсетов */
    LogAllGameOffsets();

    Logger_WriteHeader(
        "LIVE GAME EVENT LOG (ZHURNAL IGROVYH SOBYTIJ)");
    Logger_Write(COLOR_INFO,
        "  Monitoring all game actions in real-time...\n\n");

    /* Начальное чтение состояния */
    ReadGameState(&g_gmCurrent);
    memcpy(&g_gmPrevious, &g_gmCurrent, sizeof(GAME_STATE_SNAPSHOT));

    LogGameEvent("INIT", 0,
        NULL, NULL,
        "Game monitoring started. Initial scene: %s",
        GameMonitor_GetSceneName(g_gmCurrent.Scene));

    if (g_gmCurrent.Character.Name[0] != '\0')
    {
        LogGameEvent("INIT", OFFSET_CHAR_NAME,
            "CharName", NULL,
            "Character: \"%s\" Level:%u Class:%s HP:%u/%u MP:%u/%u Map:%s",
            g_gmCurrent.Character.Name,
            g_gmCurrent.Character.Level,
            GetClassName(g_gmCurrent.Character.Class),
            g_gmCurrent.Character.HP, g_gmCurrent.Character.MaxHP,
            g_gmCurrent.Character.MP, g_gmCurrent.Character.MaxMP,
            GetMapName(g_gmCurrent.Character.MapId));
    }

    return TRUE;
}

DWORD GameMonitor_Update(void)
{
    DWORD now;
    DWORD newEvents;

    if (!g_gmInitialized)
        return 0;

    now = GetTickCount();

    /* Ограничение частоты: ~10 обновлений в секунду */
    if (now - g_gmLastUpdate < 100)
        return 0;

    g_gmLastUpdate = now;

    /* Сохраняем предыдущее состояние */
    memcpy(&g_gmPrevious, &g_gmCurrent, sizeof(GAME_STATE_SNAPSHOT));

    /* Читаем новое состояние */
    ReadGameState(&g_gmCurrent);

    /* Определяем и логируем изменения */
    newEvents = DetectAndLogChanges();

    return newEvents;
}

const GAME_STATE_SNAPSHOT* GameMonitor_GetState(void)
{
    return &g_gmCurrent;
}

DWORD GameMonitor_GetEventCount(void)
{
    return g_gmEventCount;
}

void GameMonitor_Shutdown(void)
{
    DWORD elapsed;

    if (!g_gmInitialized)
        return;

    elapsed = (GetTickCount() - g_gmStartTime) / 1000;

    Logger_Write(COLOR_DEFAULT, "\n");
    Logger_WriteHeader(
        "GAME MONITOR SUMMARY (ITOGI MONITORINGA IGRY)");

    Logger_Write(COLOR_HEADER,
        "  Duration:            %02u:%02u:%02u\n",
        elapsed / 3600, (elapsed % 3600) / 60, elapsed % 60);
    Logger_Write(COLOR_HEADER,
        "  Total game events:   %u\n", g_gmEventCount);
    Logger_Write(COLOR_DEFAULT, "\n");

    Logger_Write(COLOR_INFO,
        "  Scene changes:       %u\n", g_gmTotalSceneChanges);
    Logger_Write(COLOR_INFO,
        "  Server changes:      %u\n", g_gmTotalServerChanges);
    Logger_Write(COLOR_INFO,
        "  Level ups:           %u\n", g_gmTotalLevelUps);
    Logger_Write(COLOR_INFO,
        "  Chat messages:       %u\n", g_gmTotalChatMessages);
    Logger_Write(COLOR_INFO,
        "  Teleportations:      %u\n", g_gmTotalTeleports);
    Logger_Write(COLOR_INFO,
        "  Key presses:         %u\n", g_gmTotalKeyPresses);
    Logger_Write(COLOR_INFO,
        "  Mouse clicks:        %u\n", g_gmTotalMouseClicks);

    /* Итоги обнаружения офсетов */
    Logger_Write(COLOR_DEFAULT, "\n");
    Logger_Write(COLOR_HEADER,
        "  Offset discovery summary:\n");
    Logger_Write(COLOR_INFO,
        "    Discovered:  %u / %u offsets\n",
        g_gmTotalDiscovered, (DWORD)DISC_COUNT);

    {
        DWORD i;
        for (i = 0; i < DISC_COUNT; i++)
        {
            if (g_gmDiscovery[i].Discovered)
            {
                Logger_Write(COLOR_OFFSET,
                    "    [+] 0x%08X  %s  (%s)\n",
                    g_gmDiscovery[i].VA,
                    g_gmDiscovery[i].Name,
                    g_gmDiscovery[i].Category);
            }
        }
        for (i = 0; i < DISC_COUNT; i++)
        {
            if (!g_gmDiscovery[i].Discovered)
            {
                Logger_Write(COLOR_INFO,
                    "    [-] 0x%08X  %s  (%s) - not active\n",
                    g_gmDiscovery[i].VA,
                    g_gmDiscovery[i].Name,
                    g_gmDiscovery[i].Category);
            }
        }
    }

    if (g_gmCurrent.Character.Name[0] != '\0')
    {
        Logger_Write(COLOR_DEFAULT, "\n");
        Logger_Write(COLOR_HEADER,
            "  Final character state:\n");
        Logger_Write(COLOR_INFO,
            "    Name:    %s\n", g_gmCurrent.Character.Name);
        Logger_Write(COLOR_INFO,
            "    Level:   %u\n", g_gmCurrent.Character.Level);
        Logger_Write(COLOR_INFO,
            "    Class:   %s\n", GetClassName(g_gmCurrent.Character.Class));
        Logger_Write(COLOR_INFO,
            "    HP:      %u / %u\n",
            g_gmCurrent.Character.HP, g_gmCurrent.Character.MaxHP);
        Logger_Write(COLOR_INFO,
            "    MP:      %u / %u\n",
            g_gmCurrent.Character.MP, g_gmCurrent.Character.MaxMP);
        Logger_Write(COLOR_INFO,
            "    Pos:     (%u, %u) Map: %s\n",
            g_gmCurrent.Character.PosX, g_gmCurrent.Character.PosY,
            GetMapName(g_gmCurrent.Character.MapId));
        Logger_Write(COLOR_INFO,
            "    Exp:     %u\n", g_gmCurrent.Character.Experience);
        Logger_Write(COLOR_INFO,
            "    Kills:   %u\n", g_gmCurrent.MonstersKilled);
        Logger_Write(COLOR_INFO,
            "    Dmg out: %u\n", g_gmCurrent.TotalDamageDealt);
        Logger_Write(COLOR_INFO,
            "    Dmg in:  %u\n", g_gmCurrent.TotalDamageReceived);
    }

    g_gmInitialized = FALSE;
    g_gmProcess     = NULL;
    g_gmProcessId   = 0;
}
