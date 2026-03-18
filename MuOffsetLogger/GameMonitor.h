/*
 * GameMonitor.h
 * MuOffsetLogger - Отслеживание всех игровых событий MU Online
 *
 * Модуль мониторинга игровых действий через чтение памяти процесса:
 * - Выбор сервера (server selection)
 * - Ввод логина/пароля (login/password input)
 * - Выбор персонажа, количество персонажей (character selection)
 * - Инвентарь (inventory)
 * - Нажатие кнопок клавиатуры и мыши (keyboard/mouse input)
 * - Чат (chat messages)
 * - Телепортация (teleportation)
 * - Убийство монстров (monster kills)
 * - Уровень персонажа (character level)
 * - Игроки рядом (nearby players)
 * - Имена монстров (monster names)
 * - ХП монстров (monster HP)
 * - Нанесённый урон (damage dealt)
 * Совместимость: Visual Studio 2010 (v100), Windows 10 x86/x64
 */

#ifndef GAME_MONITOR_H
#define GAME_MONITOR_H

#include <windows.h>

/* Максимальное количество отслеживаемых объектов */
#define MAX_NEARBY_PLAYERS   40
#define MAX_NEARBY_MONSTERS  40
#define MAX_INVENTORY_SLOTS  64
#define MAX_CHAT_LINES        8
#define MAX_GAME_NAME_LEN    32

/* Текущая сцена/экран игры */
typedef enum _GAME_SCENE
{
    SCENE_UNKNOWN = 0,
    SCENE_LOGO,             /* Заставка */
    SCENE_LOGIN,            /* Экран логина */
    SCENE_SERVER_SELECT,    /* Выбор сервера */
    SCENE_CHARACTER_SELECT, /* Выбор персонажа */
    SCENE_GAME_PLAYING,     /* Игровой процесс */
    SCENE_LOADING           /* Загрузка */
} GAME_SCENE;

/* Информация о персонаже */
typedef struct _CHAR_INFO_MON
{
    char   Name[MAX_GAME_NAME_LEN];
    DWORD  Level;
    DWORD  HP;
    DWORD  MaxHP;
    DWORD  MP;
    DWORD  MaxMP;
    DWORD  Experience;
    DWORD  PosX;
    DWORD  PosY;
    BYTE   MapId;
    BYTE   Class;
} CHAR_INFO_MON;

/* Информация о ближайшем игроке/монстре */
typedef struct _ENTITY_INFO
{
    DWORD  Id;
    char   Name[MAX_GAME_NAME_LEN];
    DWORD  HP;
    DWORD  MaxHP;
    DWORD  PosX;
    DWORD  PosY;
    BOOL   IsAlive;
} ENTITY_INFO;

/* Информация о предмете инвентаря */
typedef struct _ITEM_INFO
{
    BYTE   Slot;
    WORD   ItemId;
    BYTE   Level;
    BYTE   Durability;
    BYTE   MaxDurability;
} ITEM_INFO;

/* Полное игровое состояние (снимок) */
typedef struct _GAME_STATE_SNAPSHOT
{
    /* Сцена */
    GAME_SCENE Scene;

    /* Данные выбора сервера */
    DWORD  ServerGroup;
    DWORD  ServerIndex;
    char   ServerName[MAX_GAME_NAME_LEN];

    /* Данные логина */
    char   LoginField[MAX_GAME_NAME_LEN];
    DWORD  LoginFieldLen;

    /* Персонаж */
    DWORD  CharacterCount;
    DWORD  SelectedCharIndex;
    CHAR_INFO_MON Character;

    /* Инвентарь */
    DWORD  InventoryItemCount;
    ITEM_INFO Inventory[MAX_INVENTORY_SLOTS];

    /* Ближайшие игроки */
    DWORD  NearbyPlayerCount;
    ENTITY_INFO NearbyPlayers[MAX_NEARBY_PLAYERS];

    /* Ближайшие монстры */
    DWORD  NearbyMonsterCount;
    ENTITY_INFO NearbyMonsters[MAX_NEARBY_MONSTERS];

    /* Чат */
    char   LastChatLine[256];
    DWORD  ChatLineCount;

    /* Урон */
    DWORD  LastDamageDealt;
    DWORD  LastDamageReceived;
    DWORD  TotalDamageDealt;
    DWORD  TotalDamageReceived;
    DWORD  MonstersKilled;

    /* Телепортация */
    BYTE   LastTeleportMap;
    DWORD  LastTeleportX;
    DWORD  LastTeleportY;

    /* Ввод */
    BYTE   KeyStates[256];
    DWORD  MouseX;
    DWORD  MouseY;
    BYTE   MouseButtons;
} GAME_STATE_SNAPSHOT;

/* Событие игрового мониторинга */
typedef struct _GAME_EVENT
{
    DWORD       Timestamp;      /* Метка времени (мс от старта) */
    const char* Category;       /* Категория: "SERVER", "LOGIN", ... */
    const char* Description;    /* Описание события */
    DWORD       VA;             /* VA связанного офсета */
    DWORD       OldValue;       /* Предыдущее значение (или 0) */
    DWORD       NewValue;       /* Новое значение (или 0) */
} GAME_EVENT;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Инициализация GameMonitor
 * hProcess   - хэндл процесса main.exe (с правами PROCESS_VM_READ)
 * processId  - PID процесса
 * Возвращает TRUE при успехе
 */
BOOL GameMonitor_Init(HANDLE hProcess, DWORD processId);

/*
 * Обновление мониторинга (вызывать в цикле ~10 раз/сек)
 * Читает память процесса, определяет изменения, логирует события
 * Возвращает количество новых событий за этот вызов
 */
DWORD GameMonitor_Update(void);

/*
 * Получить текущий снимок игрового состояния
 */
const GAME_STATE_SNAPSHOT* GameMonitor_GetState(void);

/*
 * Получить общее количество обнаруженных игровых событий
 */
DWORD GameMonitor_GetEventCount(void);

/*
 * Получить текущую сцену как строку
 */
const char* GameMonitor_GetSceneName(GAME_SCENE scene);

/*
 * Завершение мониторинга: итоговая статистика
 */
void GameMonitor_Shutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* GAME_MONITOR_H */
