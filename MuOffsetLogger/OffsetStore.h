/*
 * OffsetStore.h
 * MuOffsetLogger - Persistent database for storing discovered offsets
 *
 * Stores all found offsets in format:
 *   Offset | FunctionName | ModuleName | VariableName
 *
 * Uses a CSV file (MuOffsetDB.csv) for persistent storage.
 * Supports writing, reading, and deduplication of offset records.
 * Совместимость: Visual Studio 2010 (v100), Windows 10 x86/x64
 */

#ifndef OFFSET_STORE_H
#define OFFSET_STORE_H

#include <windows.h>

/* Maximum field lengths */
#define OSTORE_MAX_FUNC_NAME   128
#define OSTORE_MAX_MOD_NAME    64
#define OSTORE_MAX_VAR_NAME    128

/* Maximum records in memory */
#define OSTORE_MAX_RECORDS     8192

/* Database file name */
#define OSTORE_DB_FILENAME     "MuOffsetDB.csv"

/* Single offset record */
typedef struct _OFFSET_RECORD
{
    DWORD  Offset;                              /* Virtual Address */
    char   FunctionName[OSTORE_MAX_FUNC_NAME];  /* Function name */
    char   ModuleName[OSTORE_MAX_MOD_NAME];     /* Module/category name */
    char   VariableName[OSTORE_MAX_VAR_NAME];   /* Variable name */
} OFFSET_RECORD;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialize the offset store: open/create database file,
 * load existing records into memory for deduplication.
 * dbPath - full path to database file (or NULL for default)
 * Returns TRUE on success
 */
BOOL OffsetStore_Init(const char* dbPath);

/*
 * Add offset record to the database.
 * Deduplicates: if exact (Offset, FunctionName, ModuleName, VariableName)
 * already exists, the record is not added again.
 * offset       - virtual address of the offset
 * funcName     - function name (may be NULL or empty)
 * moduleName   - module/category name (may be NULL or empty)
 * varName      - variable name (may be NULL or empty)
 * Returns TRUE if the record was added (new), FALSE if duplicate or error
 */
BOOL OffsetStore_Add(DWORD offset, const char* funcName,
                     const char* moduleName, const char* varName);

/*
 * Get the total number of records in the store
 */
DWORD OffsetStore_GetCount(void);

/*
 * Get a record by index (0-based)
 * Returns pointer to OFFSET_RECORD or NULL if index is out of range
 */
const OFFSET_RECORD* OffsetStore_GetRecord(DWORD index);

/*
 * Flush all pending records to disk
 */
void OffsetStore_Flush(void);

/*
 * Shutdown the offset store: flush and close
 */
void OffsetStore_Shutdown(void);

/*
 * Reset the offset store to zero state.
 * Clears all records in memory and truncates the database file.
 * Call before starting a new analysis session.
 * Returns TRUE on success.
 */
BOOL OffsetStore_Reset(void);

#ifdef __cplusplus
}
#endif

#endif /* OFFSET_STORE_H */
