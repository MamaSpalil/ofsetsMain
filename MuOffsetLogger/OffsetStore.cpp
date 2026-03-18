/*
 * OffsetStore.cpp
 * MuOffsetLogger - Persistent database for storing discovered offsets
 *
 * Implementation: CSV-based file storage with in-memory deduplication.
 * Database format (CSV):
 *   Offset|FunctionName|ModuleName|VariableName
 *
 * On init, existing records are loaded from file.
 * New records are appended immediately to file and stored in memory.
 * Совместимость: Visual Studio 2010 (v100), Windows 10 x86/x64
 */

#include "OffsetStore.h"
#include "Logger.h"
#include <stdio.h>
#include <string.h>

/* ============================================================
 * Static data
 * ============================================================ */
static OFFSET_RECORD g_records[OSTORE_MAX_RECORDS];
static DWORD         g_recordCount    = 0;
static BOOL          g_initialized    = FALSE;
static char          g_dbFilePath[MAX_PATH];
static HANDLE        g_dbFile         = INVALID_HANDLE_VALUE;

/* ============================================================
 * Internal helpers
 * ============================================================ */

/*
 * Safe string copy with null termination
 */
static void SafeCopy(char* dst, const char* src, SIZE_T maxLen)
{
    if (src == NULL || src[0] == '\0')
    {
        dst[0] = '\0';
        return;
    }
    strncpy(dst, src, maxLen - 1);
    dst[maxLen - 1] = '\0';
}

/*
 * Check if a record already exists (exact match)
 */
static BOOL IsDuplicate(DWORD offset, const char* funcName,
                        const char* moduleName, const char* varName)
{
    DWORD i;
    const char* fn  = (funcName != NULL)   ? funcName   : "";
    const char* mn  = (moduleName != NULL) ? moduleName : "";
    const char* vn  = (varName != NULL)    ? varName    : "";

    for (i = 0; i < g_recordCount; i++)
    {
        if (g_records[i].Offset == offset
            && strcmp(g_records[i].FunctionName, fn) == 0
            && strcmp(g_records[i].ModuleName, mn) == 0
            && strcmp(g_records[i].VariableName, vn) == 0)
        {
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * Write a single record line to the open file handle
 */
static void WriteRecordToFile(const OFFSET_RECORD* rec)
{
    char   line[512];
    DWORD  bytesWritten;
    int    len;

    if (g_dbFile == INVALID_HANDLE_VALUE)
        return;

    len = _snprintf(line, sizeof(line) - 1,
                    "0x%08X|%s|%s|%s\r\n",
                    rec->Offset,
                    rec->FunctionName,
                    rec->ModuleName,
                    rec->VariableName);
    if (len <= 0)
        return;
    line[sizeof(line) - 1] = '\0';

    WriteFile(g_dbFile, line, (DWORD)len, &bytesWritten, NULL);
}

/*
 * Parse a CSV line into an OFFSET_RECORD
 * Format: 0xHHHHHHHH|FunctionName|ModuleName|VariableName
 * Returns TRUE if parsed successfully
 */
static BOOL ParseLine(const char* line, OFFSET_RECORD* rec)
{
    const char* p;
    const char* field;
    int fieldIdx;
    char token[256];
    SIZE_T tokenLen;

    if (line == NULL || line[0] == '\0')
        return FALSE;

    /* Skip header line */
    if (line[0] == 'O' && strncmp(line, "Offset|", 7) == 0)
        return FALSE;

    /* Skip comment lines */
    if (line[0] == '#' || line[0] == ';')
        return FALSE;

    memset(rec, 0, sizeof(OFFSET_RECORD));

    p = line;
    fieldIdx = 0;

    while (fieldIdx < 4 && *p != '\0')
    {
        field = p;
        /* Find next delimiter or end of line */
        while (*p != '|' && *p != '\r' && *p != '\n' && *p != '\0')
            p++;

        tokenLen = (SIZE_T)(p - field);
        if (tokenLen >= sizeof(token))
            tokenLen = sizeof(token) - 1;

        memcpy(token, field, tokenLen);
        token[tokenLen] = '\0';

        switch (fieldIdx)
        {
        case 0: /* Offset */
            if (token[0] == '0' && (token[1] == 'x' || token[1] == 'X'))
                rec->Offset = (DWORD)strtoul(token, NULL, 16);
            else
                rec->Offset = (DWORD)strtoul(token, NULL, 10);
            break;
        case 1: /* FunctionName */
            SafeCopy(rec->FunctionName, token, OSTORE_MAX_FUNC_NAME);
            break;
        case 2: /* ModuleName */
            SafeCopy(rec->ModuleName, token, OSTORE_MAX_MOD_NAME);
            break;
        case 3: /* VariableName */
            SafeCopy(rec->VariableName, token, OSTORE_MAX_VAR_NAME);
            break;
        }

        fieldIdx++;
        if (*p == '|')
            p++;
    }

    /* Must have at least an offset */
    return (fieldIdx >= 1 && rec->Offset != 0) ? TRUE : FALSE;
}

/*
 * Load existing records from database file
 */
static DWORD LoadExistingRecords(void)
{
    HANDLE hRead;
    DWORD  fileSize, bytesRead;
    char*  content;
    char*  line;
    char*  next;
    DWORD  loaded = 0;

    hRead = CreateFileA(g_dbFilePath, GENERIC_READ, FILE_SHARE_READ,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hRead == INVALID_HANDLE_VALUE)
        return 0;

    fileSize = GetFileSize(hRead, NULL);
    if (fileSize == 0 || fileSize == INVALID_FILE_SIZE)
    {
        CloseHandle(hRead);
        return 0;
    }

    content = (char*)VirtualAlloc(NULL, fileSize + 1,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (content == NULL)
    {
        CloseHandle(hRead);
        return 0;
    }

    if (!ReadFile(hRead, content, fileSize, &bytesRead, NULL))
    {
        VirtualFree(content, 0, MEM_RELEASE);
        CloseHandle(hRead);
        return 0;
    }
    content[bytesRead] = '\0';
    CloseHandle(hRead);

    /* Parse line by line */
    line = content;
    while (line != NULL && *line != '\0' && g_recordCount < OSTORE_MAX_RECORDS)
    {
        OFFSET_RECORD rec;

        /* Find end of line */
        next = strstr(line, "\r\n");
        if (next != NULL)
        {
            *next = '\0';
            next += 2;
        }
        else
        {
            next = strchr(line, '\n');
            if (next != NULL)
            {
                *next = '\0';
                next++;
            }
        }

        if (ParseLine(line, &rec))
        {
            /* Add without duplicate check for loading (file is authoritative) */
            memcpy(&g_records[g_recordCount], &rec, sizeof(OFFSET_RECORD));
            g_recordCount++;
            loaded++;
        }

        line = next;
    }

    VirtualFree(content, 0, MEM_RELEASE);
    return loaded;
}

/* ============================================================
 * Public API
 * ============================================================ */

BOOL OffsetStore_Init(const char* dbPath)
{
    DWORD loaded;
    DWORD bytesWritten;
    const char* header = "Offset|FunctionName|ModuleName|VariableName\r\n";
    BOOL  isNewFile;

    if (g_initialized)
        return TRUE;

    g_recordCount = 0;
    memset(g_records, 0, sizeof(g_records));

    if (dbPath != NULL && dbPath[0] != '\0')
    {
        strncpy(g_dbFilePath, dbPath, MAX_PATH - 1);
        g_dbFilePath[MAX_PATH - 1] = '\0';
    }
    else
    {
        /* Default: same directory as exe */
        char modulePath[MAX_PATH];
        char* lastSlash;

        GetModuleFileNameA(NULL, modulePath, MAX_PATH);
        lastSlash = strrchr(modulePath, '\\');
        if (lastSlash != NULL)
        {
            *(lastSlash + 1) = '\0';
            _snprintf(g_dbFilePath, MAX_PATH - 1, "%s%s",
                      modulePath, OSTORE_DB_FILENAME);
        }
        else
        {
            _snprintf(g_dbFilePath, MAX_PATH - 1, "%s", OSTORE_DB_FILENAME);
        }
        g_dbFilePath[MAX_PATH - 1] = '\0';
    }

    /* Check if file already exists */
    isNewFile = (GetFileAttributesA(g_dbFilePath) == INVALID_FILE_ATTRIBUTES);

    /* Load existing records */
    if (!isNewFile)
    {
        loaded = LoadExistingRecords();
        Logger_Write(COLOR_INFO,
            "  [OffsetStore] Loaded %u existing records from %s\n",
            loaded, g_dbFilePath);
    }

    /* Open file for appending new records */
    g_dbFile = CreateFileA(g_dbFilePath,
                           FILE_APPEND_DATA,
                           FILE_SHARE_READ,
                           NULL,
                           OPEN_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);

    if (g_dbFile == INVALID_HANDLE_VALUE)
    {
        Logger_Write(COLOR_WARN,
            "  [OffsetStore] WARNING: Cannot open database file: %s\n",
            g_dbFilePath);
        /* Continue without file - memory-only mode */
    }
    else if (isNewFile)
    {
        /* Write CSV header for new files */
        WriteFile(g_dbFile, header, (DWORD)strlen(header),
                  &bytesWritten, NULL);
    }

    g_initialized = TRUE;

    Logger_Write(COLOR_OFFSET,
        "  [OffsetStore] Database initialized: %s (%u records)\n",
        g_dbFilePath, g_recordCount);

    return TRUE;
}

BOOL OffsetStore_Add(DWORD offset, const char* funcName,
                     const char* moduleName, const char* varName)
{
    OFFSET_RECORD* rec;

    if (!g_initialized)
        return FALSE;
    if (g_recordCount >= OSTORE_MAX_RECORDS)
        return FALSE;
    if (offset == 0)
        return FALSE;

    /* Deduplicate */
    if (IsDuplicate(offset, funcName, moduleName, varName))
        return FALSE;

    rec = &g_records[g_recordCount];
    rec->Offset = offset;
    SafeCopy(rec->FunctionName, funcName, OSTORE_MAX_FUNC_NAME);
    SafeCopy(rec->ModuleName, moduleName, OSTORE_MAX_MOD_NAME);
    SafeCopy(rec->VariableName, varName, OSTORE_MAX_VAR_NAME);

    /* Write immediately to file */
    WriteRecordToFile(rec);

    g_recordCount++;
    return TRUE;
}

DWORD OffsetStore_GetCount(void)
{
    return g_recordCount;
}

const OFFSET_RECORD* OffsetStore_GetRecord(DWORD index)
{
    if (index >= g_recordCount)
        return NULL;
    return &g_records[index];
}

void OffsetStore_Flush(void)
{
    if (g_dbFile != INVALID_HANDLE_VALUE)
        FlushFileBuffers(g_dbFile);
}

void OffsetStore_Shutdown(void)
{
    if (!g_initialized)
        return;

    OffsetStore_Flush();

    if (g_dbFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g_dbFile);
        g_dbFile = INVALID_HANDLE_VALUE;
    }

    Logger_Write(COLOR_OFFSET,
        "  [OffsetStore] Database closed. Total records: %u\n",
        g_recordCount);

    g_initialized = FALSE;
    g_recordCount = 0;
}
