/*
 * PEAnalyzer.cpp
 * MuOffsetLogger - Система логирования офсетов main.exe MU Online
 *
 * Реализация модуля анализа PE-структуры
 * Совместимость: Visual Studio 2010 (v100), Windows 10 x86/x64
 */

#include "PEAnalyzer.h"
#include "Logger.h"
#include <string.h>

/*
 * Безопасное чтение памяти
 */
static BOOL SafeReadMemory(LPCVOID address, LPVOID buffer, SIZE_T size)
{
    BOOL result;
    __try
    {
        memcpy(buffer, address, size);
        result = TRUE;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        result = FALSE;
    }
    return result;
}

BOOL PEAnalyzer_Parse(HMODULE hModule, PE_FILE_INFO* pInfo)
{
    BYTE* pBase;
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS ntHeaders;
    IMAGE_SECTION_HEADER sectionHeader;
    DWORD i;

    if (hModule == NULL || pInfo == NULL)
        return FALSE;

    memset(pInfo, 0, sizeof(PE_FILE_INFO));
    pBase = (BYTE*)hModule;

    /* Чтение DOS Header */
    if (!SafeReadMemory(pBase, &dosHeader, sizeof(dosHeader)))
        return FALSE;

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) /* 'MZ' */
        return FALSE;

    /* Чтение NT Headers */
    if (!SafeReadMemory(pBase + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders)))
        return FALSE;

    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) /* 'PE\0\0' */
        return FALSE;

    /* Заполнение основной информации */
    pInfo->ImageBase          = ntHeaders.OptionalHeader.ImageBase;
    pInfo->EntryPointRVA      = ntHeaders.OptionalHeader.AddressOfEntryPoint;
    pInfo->EntryPointVA       = pInfo->ImageBase + pInfo->EntryPointRVA;
    pInfo->SizeOfImage        = ntHeaders.OptionalHeader.SizeOfImage;
    pInfo->SizeOfHeaders      = ntHeaders.OptionalHeader.SizeOfHeaders;
    pInfo->Subsystem          = ntHeaders.OptionalHeader.Subsystem;
    pInfo->Machine            = ntHeaders.FileHeader.Machine;
    pInfo->NumberOfSections   = ntHeaders.FileHeader.NumberOfSections;
    pInfo->FileAlignment      = ntHeaders.OptionalHeader.FileAlignment;
    pInfo->SectionAlignment   = ntHeaders.OptionalHeader.SectionAlignment;
    pInfo->SizeOfStackReserve = ntHeaders.OptionalHeader.SizeOfStackReserve;
    pInfo->SizeOfHeapReserve  = ntHeaders.OptionalHeader.SizeOfHeapReserve;

    /* Чтение секций */
    {
        BYTE* pSections = pBase + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS);
        DWORD count = ntHeaders.FileHeader.NumberOfSections;

        if (count > MAX_SECTIONS)
            count = MAX_SECTIONS;

        pInfo->SectionCount = count;

        for (i = 0; i < count; i++)
        {
            if (!SafeReadMemory(pSections + i * sizeof(IMAGE_SECTION_HEADER),
                                &sectionHeader, sizeof(sectionHeader)))
                continue;

            memcpy(pInfo->Sections[i].Name, sectionHeader.Name, 8);
            pInfo->Sections[i].Name[8]           = '\0';
            pInfo->Sections[i].VirtualAddress     = pInfo->ImageBase +
                                                    sectionHeader.VirtualAddress;
            pInfo->Sections[i].VirtualSize        = sectionHeader.Misc.VirtualSize;
            pInfo->Sections[i].RawOffset          = sectionHeader.PointerToRawData;
            pInfo->Sections[i].RawSize            = sectionHeader.SizeOfRawData;
            pInfo->Sections[i].Characteristics    = sectionHeader.Characteristics;
        }
    }

    /* Разбор таблицы импорта */
    {
        DWORD importRVA  = ntHeaders.OptionalHeader.DataDirectory
                           [IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        DWORD importSize = ntHeaders.OptionalHeader.DataDirectory
                           [IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

        if (importRVA != 0 && importSize != 0)
        {
            IMAGE_IMPORT_DESCRIPTOR* pImport;
            DWORD dllIndex = 0;

            pImport = (IMAGE_IMPORT_DESCRIPTOR*)(pBase + importRVA);

            while (pImport->Name != 0 && dllIndex < MAX_IMPORT_DLL)
            {
                char* dllName;
                IMAGE_THUNK_DATA* pOrigThunk;
                IMAGE_THUNK_DATA* pThunk;
                DWORD funcIndex = 0;

                /* Имя DLL */
                dllName = (char*)(pBase + pImport->Name);
                if (!SafeReadMemory(dllName, pInfo->Imports[dllIndex].DllName, 127))
                {
                    pImport++;
                    continue;
                }
                pInfo->Imports[dllIndex].DllName[127] = '\0';

                /* Обход функций */
                if (pImport->OriginalFirstThunk != 0)
                    pOrigThunk = (IMAGE_THUNK_DATA*)(pBase + pImport->OriginalFirstThunk);
                else
                    pOrigThunk = (IMAGE_THUNK_DATA*)(pBase + pImport->FirstThunk);

                pThunk = (IMAGE_THUNK_DATA*)(pBase + pImport->FirstThunk);

                while (pOrigThunk->u1.AddressOfData != 0 &&
                       funcIndex < MAX_IMPORT_FUNC_PER_DLL)
                {
                    PE_IMPORT_FUNC* pFunc = &pInfo->Imports[dllIndex].Functions[funcIndex];

                    /* IAT VA: адрес записи в таблице адресов */
                    pFunc->IatVA = pInfo->ImageBase + pImport->FirstThunk +
                                   funcIndex * sizeof(IMAGE_THUNK_DATA);

                    if (pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
                    {
                        /* Импорт по ординалу */
                        pFunc->ByOrdinal = TRUE;
                        pFunc->Ordinal   = IMAGE_ORDINAL32(pOrigThunk->u1.Ordinal);
                        sprintf(pFunc->FunctionName, "Ordinal_%u", pFunc->Ordinal);
                    }
                    else
                    {
                        /* Импорт по имени */
                        IMAGE_IMPORT_BY_NAME* pByName;
                        pByName = (IMAGE_IMPORT_BY_NAME*)(pBase +
                                   pOrigThunk->u1.AddressOfData);

                        pFunc->ByOrdinal = FALSE;
                        if (!SafeReadMemory(pByName->Name, pFunc->FunctionName, 127))
                            pFunc->FunctionName[0] = '\0';
                        pFunc->FunctionName[127] = '\0';
                    }

                    funcIndex++;
                    pOrigThunk++;
                    pThunk++;
                }

                pInfo->Imports[dllIndex].FunctionCount = funcIndex;
                dllIndex++;
                pImport++;
            }

            pInfo->ImportDllCount = dllIndex;
        }
    }

    return TRUE;
}

void PEAnalyzer_LogHeaders(const PE_FILE_INFO* pInfo)
{
    const char* subsystemStr;
    const char* machineStr;

    if (pInfo == NULL) return;

    Logger_WriteHeader("1. PE HEADERS (ZAGOLOVKI PE-FAJLA)");

    /* Machine type */
    switch (pInfo->Machine)
    {
        case 0x014C: machineStr = "Intel 386 (x86)"; break;
        case 0x8664: machineStr = "AMD64 (x64)";     break;
        default:     machineStr = "Unknown";          break;
    }

    /* Subsystem */
    switch (pInfo->Subsystem)
    {
        case 1:  subsystemStr = "Native";          break;
        case 2:  subsystemStr = "Windows GUI";      break;
        case 3:  subsystemStr = "Windows Console";  break;
        default: subsystemStr = "Unknown";          break;
    }

    Logger_Write(COLOR_DEFAULT,
        "  ImageBase:            0x%08X\n", pInfo->ImageBase);
    Logger_Write(COLOR_DEFAULT,
        "  EntryPoint (VA):      0x%08X (RVA: 0x%08X)\n",
        pInfo->EntryPointVA, pInfo->EntryPointRVA);
    Logger_Write(COLOR_DEFAULT,
        "  Machine:              0x%04X (%s)\n", pInfo->Machine, machineStr);
    Logger_Write(COLOR_DEFAULT,
        "  Subsystem:            %u (%s)\n", pInfo->Subsystem, subsystemStr);
    Logger_Write(COLOR_DEFAULT,
        "  SizeOfImage:          0x%08X (%u bytes)\n",
        pInfo->SizeOfImage, pInfo->SizeOfImage);
    Logger_Write(COLOR_DEFAULT,
        "  NumberOfSections:     %u\n", pInfo->NumberOfSections);
    Logger_Write(COLOR_DEFAULT,
        "  SectionAlignment:     0x%08X\n", pInfo->SectionAlignment);
    Logger_Write(COLOR_DEFAULT,
        "  FileAlignment:        0x%08X\n", pInfo->FileAlignment);
    Logger_Write(COLOR_DEFAULT,
        "  SizeOfStackReserve:   0x%08X\n", pInfo->SizeOfStackReserve);
    Logger_Write(COLOR_DEFAULT,
        "  SizeOfHeapReserve:    0x%08X\n", pInfo->SizeOfHeapReserve);
}

void PEAnalyzer_LogSections(const PE_FILE_INFO* pInfo)
{
    DWORD i;

    if (pInfo == NULL) return;

    Logger_WriteHeader("2. SECTIONS (SEKTSII)");

    for (i = 0; i < pInfo->SectionCount; i++)
    {
        const PE_SECTION_INFO* sec = &pInfo->Sections[i];
        const char* desc = "";

        /* Описание секций по имени */
        if (strcmp(sec->Name, ".text") == 0)
            desc = "Main code section (executable)";
        else if (strcmp(sec->Name, ".data") == 0)
            desc = "Global variables and data (read/write)";
        else if (strcmp(sec->Name, ".rdata") == 0)
            desc = "Read-only data and constants";
        else if (strcmp(sec->Name, ".rsrc") == 0)
            desc = "Resources (icons, dialogs, version)";
        else if (strcmp(sec->Name, ".idata") == 0)
            desc = "Import Address Table";
        else if (strcmp(sec->Name, ".reloc") == 0)
            desc = "Relocation table";
        else if (sec->Name[0] == '\0')
            desc = "Unnamed section (possible packer data)";
        else if (strstr(sec->Name, ".as_") != NULL)
            desc = "ASProtect section (packer/protector)";
        else if (strcmp(sec->Name, ".LibHook") == 0)
            desc = "LibHook section (DLL hook entry point)";
        else if (strcmp(sec->Name, ".zero") == 0)
            desc = "Empty placeholder section (ASProtect)";

        Logger_Write(COLOR_SECTION,
            "\n  Section: %s\n", sec->Name[0] ? sec->Name : "(unnamed)");
        Logger_Write(COLOR_DEFAULT,
            "    VA:              0x%08X\n", sec->VirtualAddress);
        Logger_Write(COLOR_DEFAULT,
            "    Virtual Size:    0x%08X\n", sec->VirtualSize);
        Logger_Write(COLOR_DEFAULT,
            "    File Offset:     0x%08X\n", sec->RawOffset);
        Logger_Write(COLOR_DEFAULT,
            "    Raw Size:        0x%08X\n", sec->RawSize);
        Logger_Write(COLOR_DEFAULT,
            "    Characteristics: 0x%08X\n", sec->Characteristics);
        if (desc[0] != '\0')
        {
            Logger_Write(COLOR_INFO,
                "    Description:     %s\n", desc);
        }
    }
}

void PEAnalyzer_LogImports(const PE_FILE_INFO* pInfo)
{
    DWORD d, f;
    DWORD totalFuncs = 0;

    if (pInfo == NULL) return;

    Logger_WriteHeader("3. IMPORT TABLE (TABLITSA IMPORTA) - IAT OFFSETS");
    Logger_Write(COLOR_INFO,
        "  Format: IAT_VA  [IAT]  FunctionName  (DLL, calls: N)\n\n");

    for (d = 0; d < pInfo->ImportDllCount; d++)
    {
        const PE_IMPORT_DLL* pDll = &pInfo->Imports[d];

        Logger_Write(COLOR_SECTION,
            "  --- %s ---\n", pDll->DllName);

        for (f = 0; f < pDll->FunctionCount; f++)
        {
            const PE_IMPORT_FUNC* pFunc = &pDll->Functions[f];

            Logger_WriteImport(pFunc->IatVA, pDll->DllName,
                               pFunc->FunctionName, 0);
            totalFuncs++;
        }

        Logger_Write(COLOR_DEFAULT, "\n");
    }

    Logger_Write(COLOR_INFO,
        "  Total imported DLLs: %u, Total imported functions: %u\n",
        pInfo->ImportDllCount, totalFuncs);
}

DWORD PEAnalyzer_RvaToFileOffset(const PE_FILE_INFO* pInfo, DWORD rva)
{
    DWORD i;

    if (pInfo == NULL)
        return 0;

    for (i = 0; i < pInfo->SectionCount; i++)
    {
        DWORD sectionRVA  = pInfo->Sections[i].VirtualAddress - pInfo->ImageBase;
        DWORD sectionSize = pInfo->Sections[i].VirtualSize;

        if (rva >= sectionRVA && rva < sectionRVA + sectionSize)
        {
            return pInfo->Sections[i].RawOffset + (rva - sectionRVA);
        }
    }

    return 0;
}
