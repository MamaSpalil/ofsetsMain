/*
 * OffsetDatabase.cpp
 * MuOffsetLogger - Система логирования офсетов main.exe MU Online
 *
 * База данных известных офсетов main.exe MU Online.
 * Данные получены из дизассемблирования и анализа PE-файла.
 * Совместимость: Visual Studio 2010 (v100), Windows 10 x86/x64
 */

#include "OffsetDatabase.h"
#include "Logger.h"
#include <string.h>

/*
 * ===========================================================================
 *  БАЗА ДАННЫХ ОФСЕТОВ main.exe MU Online
 *  ImageBase: 0x00400000
 *  Формат: { VA, FileOffset, Type, Category, Name, Description }
 * ===========================================================================
 */
static const OFFSET_ENTRY g_OffsetDatabase[] =
{
    /* ====================================================================
     * ФУНКЦИИ АВТОРИЗАЦИИ И ВХОДА В ИГРУ (LOGIN/AUTH)
     * ==================================================================== */
    { 0x004D97E5, 0x000D8BE5, OT_FUNCTION, "Login/Auth",
      "Config_ReadVolumeLevel",
      "Read SOFTWARE\\Webzen\\Mu\\Config VolumeLevel from registry" },

    { 0x004DBEAC, 0x000DB2AC, OT_FUNCTION, "Login/Auth",
      "Sound_InitVersion",
      "Sound/music version initialization" },

    { 0x004DC052, 0x000DB452, OT_FUNCTION, "Login/Auth",
      "Registry_CreateKey",
      "RegCreateKeyExA first call - create registry key" },

    { 0x004223A8, 0x000217A8, OT_FUNCTION, "Login/Auth",
      "Registry_OpenKey",
      "RegOpenKeyExA first call - open registry key" },

    { 0x004223D4, 0x000217D4, OT_FUNCTION, "Login/Auth",
      "Registry_QueryValue",
      "RegQueryValueExA first call - read registry value" },

    /* ====================================================================
     * STL СТРОКИ И КОНТЕЙНЕРЫ (std::basic_string, std::map)
     * ==================================================================== */
    { 0x004019E0, 0x000009E0, OT_FUNCTION, "STL/Container",
      "Map::CopyAll",
      "Container: copy all elements (std::map copy)" },

    { 0x00401A20, 0x00000E20, OT_FUNCTION, "STL/Container",
      "Map::Find",
      "Container: find element by key (begin-to-end iteration)" },

    { 0x00401AA0, 0x00000EA0, OT_FUNCTION, "STL/Container",
      "Iterator::GetValue",
      "Iterator: dereference and get value (call Node::GetKey)" },

    { 0x00401AC0, 0x00000EC0, OT_FUNCTION, "STL/Container",
      "Iterator::GetNext",
      "Iterator: advance to next element and extract value" },

    { 0x00401AF0, 0x00000EF0, OT_FUNCTION, "STL/Container",
      "Iterator::IsEqual",
      "Iterator: equality comparison (returns bool)" },

    { 0x00401B20, 0x00000F20, OT_FUNCTION, "STL/String",
      "String::Erase_Default",
      "Erase substring with default params (uses npos 0x7B363C)" },

    { 0x00401B50, 0x00000F50, OT_FUNCTION, "STL/String",
      "String::Assign_Substr",
      "Assign/extract substring with bounds checking, self-assign handling" },

    { 0x00401CB0, 0x000010B0, OT_FUNCTION, "STL/String",
      "String::c_str",
      "Get pointer to data buffer (c_str()/data()), static buf if empty" },

    { 0x00401CE0, 0x000010E0, OT_FUNCTION, "STL/String",
      "String::size",
      "Get string length (returns field +0x08)" },

    { 0x00401D00, 0x00001100, OT_FUNCTION, "STL/String",
      "String::MemMove",
      "memmove wrapper for buffer data (calls CRT memmove 0x790FE0)" },

    { 0x00401D20, 0x00001120, OT_FUNCTION, "STL/String",
      "String::GetEmptyBuffer",
      "Return address of static empty buffer (0x7B3640)" },

    { 0x00401D30, 0x00001130, OT_FUNCTION, "STL/String",
      "String::Clear_Release",
      "Clear and release buffer (decrement ref-count, zero +4,+8,+0xC)" },

    { 0x00401DF0, 0x000011F0, OT_FUNCTION, "STL/Container",
      "Map::Insert",
      "Insert new element into tree (alloc node, link, increment size)" },

    { 0x004018A0, 0x00000CA0, OT_FUNCTION, "STL/Container",
      "Container::Begin",
      "Get iterator to first element (begin)" },

    { 0x004018D0, 0x00000CD0, OT_FUNCTION, "STL/Container",
      "Container::End",
      "Get iterator to end (end)" },

    { 0x00401920, 0x00000D20, OT_FUNCTION, "STL/Container",
      "Container::InsertAt",
      "Insert value at iterator position" },

    { 0x00401EA0, 0x000012A0, OT_FUNCTION, "STL/Container",
      "Map::TraverseCopy",
      "Traverse tree and copy all elements to another container" },

    { 0x00401EF0, 0x000012F0, OT_FUNCTION, "STL/Container",
      "TreeNode::Allocate",
      "Allocate new tree node (12 bytes = 3 DWORD: value, left, right)" },

    { 0x00401F80, 0x00001380, OT_FUNCTION, "STL/Container",
      "Node::GetParent",
      "Get parent/value field (+0x00)" },

    { 0x00401F90, 0x00001390, OT_FUNCTION, "STL/Container",
      "Node::GetLeft",
      "Get left child pointer (+0x04)" },

    { 0x00401FA0, 0x000013A0, OT_FUNCTION, "STL/Container",
      "Node::GetRight",
      "Get right child / key pointer (+0x08)" },

    { 0x00401FD0, 0x000013D0, OT_FUNCTION, "STL/Container",
      "Iterator::Deref",
      "Dereference: read value from node ([this->node])" },

    { 0x00401FE0, 0x000013E0, OT_FUNCTION, "STL/Container",
      "Iterator::Assign",
      "Assign node to iterator (write node pointer)" },

    { 0x00402000, 0x00001400, OT_FUNCTION, "STL/Container",
      "Iterator::Increment",
      "Advance to next node (operator++)" },

    { 0x00402030, 0x00001430, OT_FUNCTION, "STL/Container",
      "Node::IsEqual",
      "Compare two nodes by value (uses SETE, returns bool)" },

    { 0x00402050, 0x00001450, OT_FUNCTION, "STL/String",
      "String::Erase_At",
      "Erase characters at position with bounds checking" },

    { 0x00402120, 0x00001520, OT_FUNCTION, "STL/String",
      "String::capacity",
      "Get buffer capacity (returns field +0x0C)" },

    { 0x00402140, 0x00001540, OT_FUNCTION, "STL/String",
      "String::SetSize_Terminate",
      "Set size and write null terminator" },

    { 0x00402190, 0x00001590, OT_FUNCTION, "STL/String",
      "String::Grow",
      "Grow buffer (realloc if necessary)" },

    { 0x00402280, 0x00001680, OT_FUNCTION, "STL/String",
      "String::CopyBuffer",
      "Copy buffer contents" },

    { 0x004022D0, 0x000016D0, OT_FUNCTION, "STL/String",
      "RefCount::GetPtr",
      "Get pointer to ref-count byte (return arg-1, byte before data)" },

    { 0x004022F0, 0x000016F0, OT_FUNCTION, "STL/String",
      "String::FreeBuffer",
      "Free buffer memory (calls operator delete 0x783F60)" },

    { 0x00402310, 0x00001710, OT_FUNCTION, "STL/String",
      "String::AllocBuffer",
      "Allocate new buffer of given size (calls operator new 0x4026B0)" },

    { 0x00402350, 0x00001750, OT_FUNCTION, "STL/Container",
      "TreeNode::Link",
      "Link two tree nodes (set parent-child relationship)" },

    { 0x00402370, 0x00001770, OT_FUNCTION, "STL/Container",
      "Iterator::SetNode",
      "Write node pointer to iterator" },

    { 0x00402690, 0x00001A90, OT_FUNCTION, "STL/Container",
      "AlwaysTrue",
      "Stub comparison function: always returns 1 (true)" },

    { 0x004026A0, 0x000019A0, OT_FUNCTION, "STL/Container",
      "EmptyDestructor",
      "Empty destructor stub (no-op, only return)" },

    { 0x004026B0, 0x000019B0, OT_FUNCTION, "STL/Memory",
      "Allocator::Allocate",
      "Allocate memory (check size>=0, call CRT malloc 0x790EB2)" },

    { 0x004026D0, 0x000019D0, OT_FUNCTION, "STL/Memory",
      "Allocator::AllocAndInit",
      "Allocate 4-byte node and initialize with value" },

    /* ====================================================================
     * CRT / RUNTIME ФУНКЦИИ
     * ==================================================================== */
    { 0x00784197, 0x00383597, OT_CRT, "CRT/Runtime",
      "CRT::_Xout_of_range",
      "Out-of-range exception handler (called on invalid index)" },

    { 0x00783F60, 0x00383360, OT_CRT, "CRT/Runtime",
      "CRT::operator_delete",
      "operator delete wrapper (calls CRT free 0x793EDF)" },

    { 0x00790FE0, 0x003903E0, OT_CRT, "CRT/Runtime",
      "CRT::memmove",
      "memmove from CRT (block move with overlap support)" },

    { 0x00790EB2, 0x003902B2, OT_CRT, "CRT/Runtime",
      "CRT::malloc",
      "malloc from CRT (allocate memory block)" },

    /* ====================================================================
     * ГЛОБАЛЬНЫЕ ДАННЫЕ (.data)
     * ==================================================================== */
    { 0x007B363C, 0x003B1C3C, OT_VARIABLE, "Global/Data",
      "String::npos",
      "Global constant npos = 0xFFFFFFFF (max value, 'to end of string')" },

    { 0x007B3640, 0x003B1C40, OT_VARIABLE, "Global/Data",
      "String::EmptyBuf",
      "Static empty buffer for empty strings (value 0x00000000)" },

    /* ====================================================================
     * СЕРВЕРНЫЕ АДРЕСА И ПОДКЛЮЧЕНИЯ
     * ==================================================================== */
    { 0x007D27C0, 0x003D05C0, OT_STRING, "Network/Servers",
      "ServerAddr_Korea",
      "'connect.muonline.co.kr' - Korean MU Online server" },

    { 0x007D27F2, 0x003D05F2, OT_STRING, "Network/Servers",
      "ServerAddr_Global",
      "'connect.globalmuonline.com' - Global MU Online server" },

    { 0x007D2824, 0x003D0624, OT_STRING, "Network/Servers",
      "ServerAddr_Taiwan",
      "'connection.muonline.com.tw' - Taiwan MU Online server" },

    { 0x007D2888, 0x003D0688, OT_STRING, "Network/Servers",
      "ServerAddr_Localhost",
      "'127.0.0.1' - Local loopback IP address" },

    { 0x007D291E, 0x003D071E, OT_STRING, "Network/Servers",
      "ServerAddr_Vietnam",
      "'210.245.21.245' - Vietnam server IP address" },

    /* ====================================================================
     * АНТИ-ЧИТ И ЗАЩИТА
     * ==================================================================== */
    { 0x007D3774, 0x003D1574, OT_STRING, "AntiCheat",
      "AntiCheat_TwinSpeeder",
      "'TWINSPEEDER_DXX' - Anti-cheat detection string" },

    { 0x007D37B4, 0x003D15B4, OT_STRING, "AntiCheat",
      "AntiCheat_ASpeeder",
      "'A Speeder' - Anti-cheat detection string" },

    { 0x007D37D4, 0x003D15D4, OT_STRING, "AntiCheat",
      "AntiCheat_SpeederXP_Unreg",
      "'SpeederXP v1.60 - Unregistered' - Anti-cheat detection" },

    { 0x007D37F4, 0x003D15F4, OT_STRING, "AntiCheat",
      "AntiCheat_SpeederXP_Reg",
      "'SpeederXP v1.60 - Registered' - Anti-cheat detection" },

    { 0x007D3814, 0x003D1614, OT_STRING, "AntiCheat",
      "AntiCheat_SpeederXP",
      "'SpeederXP v1.60' - Anti-cheat detection" },

    { 0x007EBC5C, 0x003E9A5C, OT_STRING, "AntiCheat",
      "AntiCheat_InjectionCRC",
      "'Injection data CRC code dismatched' - CRC integrity check" },

    /* ====================================================================
     * СЕТЕВЫЕ ФУНКЦИИ
     * ==================================================================== */
    { 0x0051038A, 0x0010F78A, OT_FUNCTION, "Network",
      "Net_GetHostByName",
      "gethostbyname first call - DNS resolution" },

    { 0x00403D5A, 0x00003D5A, OT_FUNCTION, "Network",
      "Net_Send",
      "send first call - send data to server (508 total calls)" },

    /* ====================================================================
     * ГРАФИЧЕСКИЕ ФУНКЦИИ (GDI/RENDERING)
     * ==================================================================== */
    { 0x004105EB, 0x0000F9EB, OT_FUNCTION, "Rendering/GDI",
      "GDI_GetTextExtentPoint",
      "GetTextExtentPointA first call (80 total calls)" },

    { 0x004088BA, 0x00007CBA, OT_FUNCTION, "Rendering/GDI",
      "GDI_SelectObject",
      "SelectObject first call (221 total calls)" },

    { 0x004DA3F7, 0x000D97F7, OT_FUNCTION, "Rendering/GDI",
      "GDI_SetBkColor",
      "SetBkColor call - set background color" },

    { 0x004DBB47, 0x000DAF47, OT_FUNCTION, "Rendering/GDI",
      "GDI_SetPixelFormat",
      "SetPixelFormat call - OpenGL pixel format setup" },

    { 0x004DBAF1, 0x000DAEF1, OT_FUNCTION, "Rendering/GDI",
      "GDI_ChoosePixelFormat",
      "ChoosePixelFormat call - OpenGL pixel format selection" },

    { 0x004DD62C, 0x000DCA2C, OT_FUNCTION, "Rendering/GDI",
      "GDI_CreateFont",
      "CreateFontA first call (5 total calls)" },

    { 0x006CF9E6, 0x002CEDE6, OT_FUNCTION, "Rendering/GDI",
      "GDI_SwapBuffers",
      "SwapBuffers first call (3 calls) - OpenGL buffer swap" },

    /* ====================================================================
     * КРИПТОГРАФИЯ
     * ==================================================================== */
    { 0x0077F560, 0x0037E960, OT_FUNCTION, "Crypto",
      "Crypto_GetHashParam",
      "CryptGetHashParam call - get hash parameter" },

    { 0x0077EAA4, 0x0037DEA4, OT_FUNCTION, "Crypto",
      "Crypto_DeriveKey",
      "CryptDeriveKey first call (2 total) - derive encryption key" },

    { 0x0077EAD6, 0x0037DED6, OT_FUNCTION, "Crypto",
      "Crypto_Decrypt",
      "CryptDecrypt first call (2 total) - decrypt data" },

    { 0x0077E754, 0x0037DB54, OT_FUNCTION, "Crypto",
      "Crypto_CreateHash",
      "CryptCreateHash first call (3 total) - create hash object" },

    { 0x0077E780, 0x0037DB80, OT_FUNCTION, "Crypto",
      "Crypto_HashData",
      "CryptHashData first call (3 total) - hash data" },

    { 0x0077E7AB, 0x0037DBAB, OT_FUNCTION, "Crypto",
      "Crypto_VerifySignature",
      "CryptVerifySignatureA first call (2 total) - verify signature" },

    { 0x0077E3ED, 0x0037D7ED, OT_FUNCTION, "Crypto",
      "Crypto_AcquireContext",
      "CryptAcquireContextA first call (6 total) - get crypto provider" },

    /* ====================================================================
     * БЕЗОПАСНОСТЬ
     * ==================================================================== */
    { 0x0077A83D, 0x00379C3D, OT_FUNCTION, "Security",
      "Security_SetDACL",
      "SetSecurityDescriptorDacl first call - set access control" },

    { 0x0077A82A, 0x00379C2A, OT_FUNCTION, "Security",
      "Security_InitDescriptor",
      "InitializeSecurityDescriptor first call" },

    { 0x0077B217, 0x0037A617, OT_FUNCTION, "Security",
      "Security_GetUserName",
      "GetUserNameA call - get current user name" },

    /* ====================================================================
     * КОНФИГУРАЦИЯ РЕЕСТРА
     * ==================================================================== */
    { 0x007D3478, 0x003D1278, OT_STRING, "Config/Registry",
      "RegKey_MuConfig",
      "'SOFTWARE\\Webzen\\Mu\\Config' - MU Online config registry key" },

    { 0x007D3494, 0x003D1294, OT_STRING, "Config/Registry",
      "RegKey_VolumeLevel",
      "'VolumeLevel' - Sound volume registry value name" },

    /* ====================================================================
     * ОПРЕДЕЛЕНИЕ ОС И ПРОЦЕССОРА
     * ==================================================================== */
    { 0x007D0994, 0x003CE794, OT_STRING, "System/CPU",
      "CPU_PentiumPro",
      "'Pentium Pro' - CPU detection string" },

    { 0x007D09A0, 0x003CE7A0, OT_STRING, "System/CPU",
      "CPU_Pentium2",
      "'Pentium 2' - CPU detection string" },

    { 0x007D09AC, 0x003CE7AC, OT_STRING, "System/CPU",
      "CPU_PentiumCeleron",
      "'Pentium Celeron' - CPU detection string" },

    { 0x007D09BC, 0x003CE7BC, OT_STRING, "System/CPU",
      "CPU_Pentium3",
      "'Pentium 3' - CPU detection string" },

    { 0x007D09C8, 0x003CE7C8, OT_STRING, "System/CPU",
      "CPU_Pentium4",
      "'Pentium 4' - CPU detection string" },

    { 0x007D09D4, 0x003CE7D4, OT_STRING, "System/CPU",
      "CPU_AMD486",
      "'AMD 486' - CPU detection string" },

    { 0x007D0A58, 0x003CE858, OT_STRING, "System/CPU",
      "CPU_AMDK7_Athlon",
      "'AMD K-7 Athlon' - CPU detection string" },

    { 0x007EC104, 0x003E9F04, OT_STRING, "System/OS",
      "OS_WinNT351",
      "'Windows NT 3.51' - OS detection string" },

    { 0x007EC11C, 0x003E9F1C, OT_STRING, "System/OS",
      "OS_Win95",
      "'Windows 95' - OS detection string" },

    { 0x007EC128, 0x003E9F28, OT_STRING, "System/OS",
      "OS_WinNT40",
      "'Windows NT 4.0' - OS detection string" },

    /* ====================================================================
     * FLOAT-КОНСТАНТЫ (наиболее используемые)
     * ==================================================================== */
    { 0x007B38B0, 0x003B1EB0, OT_FLOAT_CONST, "Float/Constants",
      "Float_128",
      "Float constant = 128.0 (33 references)" },

    { 0x007B3A4C, 0x003B204C, OT_FLOAT_CONST, "Float/Constants",
      "Float_0_004",
      "Float constant = 0.004 (33 references)" },

    { 0x007B3A7C, 0x003B207C, OT_FLOAT_CONST, "Float/Constants",
      "Float_0_0001",
      "Float constant = 0.0001 (32 references)" },

    { 0x007B3DA8, 0x003B23A8, OT_FLOAT_CONST, "Float/Constants",
      "Float_PI",
      "Float constant = 3.14159 (pi, 23 references)" },

    { 0x007B3968, 0x003B1F68, OT_FLOAT_CONST, "Float/Constants",
      "Float_255",
      "Float constant = 255.0 (max color/byte, 37 references)" },

    { 0x007B3934, 0x003B1F34, OT_FLOAT_CONST, "Float/Constants",
      "Float_1000",
      "Float constant = 1000.0 (20 references)" },

    { 0x007B399C, 0x003B1F9C, OT_FLOAT_CONST, "Float/Constants",
      "Float_200",
      "Float constant = 200.0 (47 references)" },

    { 0x007B370C, 0x003B1D0C, OT_FLOAT_CONST, "Float/Constants",
      "Float_60",
      "Float constant = 60.0 (66 references)" },

    { 0x007B38BC, 0x003B1EBC, OT_FLOAT_CONST, "Float/Constants",
      "Float_16",
      "Float constant = 16.0 (67 references)" },

    { 0x007B3A60, 0x003B2060, OT_FLOAT_CONST, "Float/Constants",
      "Float_80",
      "Float constant = 80.0 (60 references)" },

    { 0x007B396C, 0x003B1F6C, OT_FLOAT_CONST, "Float/Constants",
      "Float_6",
      "Float constant = 6.0 (57 references)" },

    { 0x007B39AC, 0x003B1FAC, OT_FLOAT_CONST, "Float/Constants",
      "Float_90",
      "Float constant = 90.0 (54 references)" },

    { 0x007B52FC, 0x003B38FC, OT_FLOAT_CONST, "Float/Constants",
      "Float_1_05",
      "Float constant = 1.05 (53 references)" },

    { 0x007B3AFC, 0x003B20FC, OT_FLOAT_CONST, "Float/Constants",
      "Float_0_03",
      "Float constant = 0.03 (50 references)" },

    { 0x007B3720, 0x003B1D20, OT_FLOAT_CONST, "Float/Constants",
      "Float_150",
      "Float constant = 150.0 (48 references)" },

    { 0x007B373C, 0x003B1D3C, OT_FLOAT_CONST, "Float/Constants",
      "Float_1_3",
      "Float constant = 1.3 (47 references)" },

    /* ====================================================================
     * СЕТЕВЫЕ IAT-ФУНКЦИИ (наиболее вызываемые)
     * ==================================================================== */
    { 0x007B35CC, 0x003B1BCC, OT_IMPORT, "Network/IAT",
      "IAT_send",
      "send (ws2_32.dll) - 508 calls - main data sending function" },

    { 0x007B35A8, 0x003B1BA8, OT_IMPORT, "Network/IAT",
      "IAT_gethostbyname",
      "gethostbyname (ws2_32.dll) - DNS resolution" },

    /* ====================================================================
     * GDI IAT-ФУНКЦИИ
     * ==================================================================== */
    { 0x007B3070, 0x003B1670, OT_IMPORT, "GDI/IAT",
      "IAT_GetTextExtentPointA",
      "GetTextExtentPointA (gdi32.dll) - 80 calls" },

    { 0x007B3074, 0x003B1674, OT_IMPORT, "GDI/IAT",
      "IAT_SelectObject",
      "SelectObject (gdi32.dll) - 221 calls" },

    { 0x007B308C, 0x003B168C, OT_IMPORT, "GDI/IAT",
      "IAT_SwapBuffers",
      "SwapBuffers (gdi32.dll) - 3 calls - OpenGL buffer swap" },

    /* ====================================================================
     * ADVAPI32 IAT-ФУНКЦИИ (реестр и криптография)
     * ==================================================================== */
    { 0x007B3000, 0x003B1600, OT_IMPORT, "Registry/IAT",
      "IAT_RegEnumValueA",
      "RegEnumValueA (advapi32.dll) - 0 calls" },

    { 0x007B3004, 0x003B1604, OT_IMPORT, "Registry/IAT",
      "IAT_RegDeleteKeyA",
      "RegDeleteKeyA (advapi32.dll) - 1 call" },

    { 0x007B3040, 0x003B1640, OT_IMPORT, "Registry/IAT",
      "IAT_RegSetValueExA",
      "RegSetValueExA (advapi32.dll) - 6 calls" },

    { 0x007B3044, 0x003B1644, OT_IMPORT, "Registry/IAT",
      "IAT_RegCreateKeyExA",
      "RegCreateKeyExA (advapi32.dll) - 11 calls" },

    { 0x007B3048, 0x003B1648, OT_IMPORT, "Registry/IAT",
      "IAT_RegOpenKeyExA",
      "RegOpenKeyExA (advapi32.dll) - 3 calls" },

    { 0x007B304C, 0x003B164C, OT_IMPORT, "Registry/IAT",
      "IAT_RegQueryValueExA",
      "RegQueryValueExA (advapi32.dll) - 16 calls" },

    { 0x007B3050, 0x003B1650, OT_IMPORT, "Registry/IAT",
      "IAT_RegCloseKey",
      "RegCloseKey (advapi32.dll) - 18 calls" },

    { 0x007B3054, 0x003B1654, OT_IMPORT, "Registry/IAT",
      "IAT_CryptAcquireContextA",
      "CryptAcquireContextA (advapi32.dll) - 6 calls" },

    /* ====================================================================
     * DIRECTX IAT
     * ==================================================================== */
    { 0x007B305C, 0x003B165C, OT_IMPORT, "DirectX/IAT",
      "IAT_DirectInput8Create",
      "DirectInput8Create (dinput8.dll) - 0 calls" },

    { 0x007B3064, 0x003B1664, OT_IMPORT, "DirectX/IAT",
      "IAT_DirectSoundCreate",
      "DirectSoundCreate (dsound.dll) - 0 calls" },

    { 0x007B3068, 0x003B1668, OT_IMPORT, "DirectX/IAT",
      "IAT_DirectSoundEnumerateA",
      "DirectSoundEnumerateA (dsound.dll) - 0 calls" },

    /* ====================================================================
     * USER32 IAT (наиболее используемые)
     * ==================================================================== */
    { 0x007B3100, 0x003B1700, OT_IMPORT, "User32/IAT",
      "IAT_SendMessageA",
      "SendMessageA (user32.dll) - window messaging" },

    /* ====================================================================
     * JPEG LIBRARY STRINGS
     * ==================================================================== */
    { 0x007EB1CC, 0x003E8FCC, OT_STRING, "JPEG/Library",
      "JPEG_NotAJPEG",
      "'Not a JPEG file: starts with 0x%02x 0x%02x' - JPEG validation" },

    { 0x007EB224, 0x003E9024, OT_STRING, "JPEG/Library",
      "JPEG_NoImage",
      "'JPEG datastream contains no image' - JPEG error" },

    { 0x007EB984, 0x003E9784, OT_STRING, "JPEG/Library",
      "JPEG_MemEnvVar",
      "'JPEGMEM' - JPEG memory environment variable" },

    /* ====================================================================
     * ASProtect PROTECTION STRINGS
     * ==================================================================== */
    { 0x09174654, 0x00000000, OT_STRING, "ASProtect",
      "ASProtect_DebuggerDetected",
      "'Debugger detected - please close it down and restart!'" },

    { 0x091746BD, 0x00000000, OT_STRING, "ASProtect",
      "ASProtect_SoftIce",
      "'WinIce/SoftIce service installed means running a debugger!'" },

    /* ====================================================================
     * ENTRY POINT
     * ==================================================================== */
    { 0x0917C200, 0x0041DA00, OT_FUNCTION, "EntryPoint",
      "EntryPoint_Main",
      "main.exe entry point in .LibHook section (ASProtect wrapped)" },

    /* ====================================================================
     * ИГРОВЫЕ СЦЕНЫ И СОСТОЯНИЯ (GAME STATE)
     * ==================================================================== */
    { 0x007B5500, 0x003B3B00, OT_VARIABLE, "GameState",
      "GameScene",
      "Current game scene (DWORD: 0=Unknown,1=Logo,2=Login,3=ServerSel,"
      "4=CharSel,5=Playing,6=Loading)" },

    { 0x007B5504, 0x003B3B04, OT_VARIABLE, "GameState",
      "GameTick",
      "Game tick counter (DWORD)" },

    /* ====================================================================
     * ВЫБОР СЕРВЕРА (SERVER SELECTION)
     * ==================================================================== */
    { 0x007B5510, 0x003B3B10, OT_VARIABLE, "Server/Selection",
      "ServerGroup",
      "Selected server group index (DWORD)" },

    { 0x007B5514, 0x003B3B14, OT_VARIABLE, "Server/Selection",
      "ServerIndex",
      "Selected server index within group (DWORD)" },

    { 0x007B5518, 0x003B3B18, OT_DATA, "Server/Selection",
      "ServerName",
      "Current server name (char[32])" },

    { 0x007B5538, 0x003B3B38, OT_VARIABLE, "Server/Selection",
      "ServerConnected",
      "Server connection flag (BYTE: 0=disconnected, 1=connected)" },

    { 0x007B5539, 0x003B3B39, OT_VARIABLE, "Server/Selection",
      "ServerListReceived",
      "Server list received flag (BYTE: 0/1)" },

    { 0x007E8E6C, 0x003E6C6C, OT_STRING, "Server/Selection",
      "Str_ServerGroupSelected",
      "'> Server group selected - %d' - server group debug string" },

    { 0x007E8E8C, 0x003E6C8C, OT_STRING, "Server/Selection",
      "Str_ServerSelected",
      "'> Server selected - %s-%d : %d-%d' - server selection debug" },

    /* ====================================================================
     * ВХОД В СИСТЕМУ (LOGIN/PASSWORD INPUT)
     * ==================================================================== */
    { 0x007B5540, 0x003B3B40, OT_DATA, "Login/Input",
      "LoginID",
      "Account ID input field (char[14])" },

    { 0x007B554E, 0x003B3B4E, OT_VARIABLE, "Login/Input",
      "LoginIDLen",
      "Login field input length (BYTE)" },

    { 0x007B554F, 0x003B3B4F, OT_VARIABLE, "Login/Input",
      "LoginPWLen",
      "Password field input length (BYTE, value only)" },

    { 0x007B5550, 0x003B3B50, OT_VARIABLE, "Login/Input",
      "LoginState",
      "Authorization state machine (DWORD)" },

    { 0x007B5554, 0x003B3B54, OT_VARIABLE, "Login/Input",
      "LoginResult",
      "Login result code (BYTE: 0=success, 1+=error)" },

    { 0x007E8740, 0x003E6540, OT_STRING, "Login/Input",
      "Str_LoginSceneInit",
      "'> Login Scene init success.' - login screen loaded" },

    { 0x007E8D84, 0x003E6B84, OT_STRING, "Login/Input",
      "Str_LoginRequest",
      "'> Login Request.' - login request sent to server" },

    /* ====================================================================
     * ВЫБОР ПЕРСОНАЖА (CHARACTER SELECT)
     * ==================================================================== */
    { 0x007B5560, 0x003B3B60, OT_VARIABLE, "Character/Select",
      "CharCount",
      "Number of characters on account (DWORD)" },

    { 0x007B5564, 0x003B3B64, OT_VARIABLE, "Character/Select",
      "CharSelected",
      "Selected character slot index (DWORD)" },

    /* ====================================================================
     * ДАННЫЕ ПЕРСОНАЖА (CHARACTER DATA)
     * ==================================================================== */
    { 0x007B5570, 0x003B3B70, OT_DATA, "Character/Data",
      "CharName",
      "Active character name (char[11])" },

    { 0x007B5580, 0x003B3B80, OT_VARIABLE, "Character/Data",
      "CharLevel",
      "Character level (DWORD)" },

    { 0x007B5584, 0x003B3B84, OT_VARIABLE, "Character/Data",
      "CharClass",
      "Character class ID (BYTE: 0x00=DW,0x20=DK,0x40=Elf,0x60=MG,0x80=DL)" },

    { 0x007B5588, 0x003B3B88, OT_VARIABLE, "Character/Data",
      "CharHP",
      "Character current HP (DWORD)" },

    { 0x007B558C, 0x003B3B8C, OT_VARIABLE, "Character/Data",
      "CharMaxHP",
      "Character maximum HP (DWORD)" },

    { 0x007B5590, 0x003B3B90, OT_VARIABLE, "Character/Data",
      "CharMP",
      "Character current MP (DWORD)" },

    { 0x007B5594, 0x003B3B94, OT_VARIABLE, "Character/Data",
      "CharMaxMP",
      "Character maximum MP (DWORD)" },

    { 0x007B5598, 0x003B3B98, OT_VARIABLE, "Character/Data",
      "CharExp",
      "Character experience points (DWORD)" },

    { 0x007B55A0, 0x003B3BA0, OT_VARIABLE, "Character/Data",
      "CharPosX",
      "Character X position on map (DWORD)" },

    { 0x007B55A4, 0x003B3BA4, OT_VARIABLE, "Character/Data",
      "CharPosY",
      "Character Y position on map (DWORD)" },

    { 0x007B55A8, 0x003B3BA8, OT_VARIABLE, "Character/Data",
      "CharMapId",
      "Current map ID (BYTE: 0=Lorencia,1=Dungeon,2=Devias,...)" },

    /* ====================================================================
     * ИНВЕНТАРЬ (INVENTORY)
     * ==================================================================== */
    { 0x007B5600, 0x003B3C00, OT_DATA, "Inventory",
      "InventoryBase",
      "Inventory item array start (ITEM_STRUCT[64], 8 bytes each)" },

    { 0x007B5800, 0x003B3E00, OT_VARIABLE, "Inventory",
      "InventoryCount",
      "Number of items in inventory (DWORD)" },

    { 0x007E9100, 0x003E6F00, OT_STRING, "Inventory",
      "Str_OpenPersonalShop",
      "'@ OpenPersonalShop : SendRequestInventory' - shop/inventory" },

    /* ====================================================================
     * БЛИЖАЙШИЕ ИГРОКИ (NEARBY PLAYERS)
     * ==================================================================== */
    { 0x007B5810, 0x003B3E10, OT_DATA, "Players/Nearby",
      "PlayerListBase",
      "Nearby players array start (ENTITY[40], 64 bytes each)" },

    { 0x007B5C00, 0x003B4200, OT_VARIABLE, "Players/Nearby",
      "PlayerListCount",
      "Number of nearby players (DWORD)" },

    /* ====================================================================
     * БЛИЖАЙШИЕ МОНСТРЫ (NEARBY MONSTERS)
     * ==================================================================== */
    { 0x007B5C10, 0x003B4210, OT_DATA, "Monsters/Nearby",
      "MonsterListBase",
      "Nearby monsters array (ENTITY[40]: Id,Name,HP,MaxHP,PosX,PosY)" },

    { 0x007B6400, 0x003B4A00, OT_VARIABLE, "Monsters/Nearby",
      "MonsterListCount",
      "Number of nearby monsters (DWORD)" },

    /* ====================================================================
     * ЧАТ (CHAT MESSAGES)
     * ==================================================================== */
    { 0x007B6410, 0x003B4A10, OT_DATA, "Chat",
      "ChatLastLine",
      "Last received chat message (char[128])" },

    { 0x007B6490, 0x003B4A90, OT_VARIABLE, "Chat",
      "ChatLineCount",
      "Total chat messages counter (DWORD)" },

    /* ====================================================================
     * БОЙ И УРОН (COMBAT/DAMAGE)
     * ==================================================================== */
    { 0x007B64A0, 0x003B4AA0, OT_VARIABLE, "Combat/Damage",
      "LastDamageDealt",
      "Last damage dealt to target (DWORD)" },

    { 0x007B64A4, 0x003B4AA4, OT_VARIABLE, "Combat/Damage",
      "LastDamageReceived",
      "Last damage received from enemy (DWORD)" },

    { 0x007B64A8, 0x003B4AA8, OT_VARIABLE, "Combat/Damage",
      "TotalDamageDealt",
      "Total damage dealt this session (DWORD)" },

    { 0x007B64AC, 0x003B4AAC, OT_VARIABLE, "Combat/Damage",
      "TotalDamageReceived",
      "Total damage received this session (DWORD)" },

    { 0x007B64B0, 0x003B4AB0, OT_VARIABLE, "Combat/Damage",
      "MonstersKilled",
      "Monsters killed counter (DWORD)" },

    /* ====================================================================
     * ТЕЛЕПОРТАЦИЯ (TELEPORTATION)
     * ==================================================================== */
    { 0x007B64C0, 0x003B4AC0, OT_VARIABLE, "Teleport",
      "TeleportMap",
      "Teleport destination map ID (BYTE)" },

    { 0x007B64C4, 0x003B4AC4, OT_VARIABLE, "Teleport",
      "TeleportX",
      "Teleport destination X coordinate (DWORD)" },

    { 0x007B64C8, 0x003B4AC8, OT_VARIABLE, "Teleport",
      "TeleportY",
      "Teleport destination Y coordinate (DWORD)" },

    /* ====================================================================
     * ВВОД: КЛАВИАТУРА И МЫШЬ (KEYBOARD/MOUSE INPUT)
     * ==================================================================== */
    { 0x007B6500, 0x003B4B00, OT_DATA, "Input/Keyboard",
      "KeyStates",
      "Keyboard virtual key state array (BYTE[256])" },

    { 0x007B6600, 0x003B4C00, OT_VARIABLE, "Input/Mouse",
      "MouseX",
      "Mouse cursor X position (DWORD)" },

    { 0x007B6604, 0x003B4C04, OT_VARIABLE, "Input/Mouse",
      "MouseY",
      "Mouse cursor Y position (DWORD)" },

    { 0x007B6608, 0x003B4C08, OT_VARIABLE, "Input/Mouse",
      "MouseButtons",
      "Mouse button state (BYTE: bit0=Left, bit1=Right, bit2=Middle)" },

    /* ====================================================================
     * ЗВУКИ СОБЫТИЙ (GAME EVENT SOUNDS) - связанные функции
     * ==================================================================== */
    { 0x007E4FC0, 0x003E2DC0, OT_STRING, "GameEvents/Sound",
      "Str_LevelUpSound",
      "'Data\\Sound\\pLevelUp.wav' - level up sound trigger" },

    { 0x007DBCB0, 0x003D9AB0, OT_STRING, "GameEvents/Sound",
      "Str_MonsterDieSound",
      "'Data\\Sound\\mIceMonsterDie.wav' - monster death sound" },

    /* ====================================================================
     * СЕТЕВЫЕ СТРОКИ - ПОДКЛЮЧЕНИЕ К СЕРВЕРУ
     * ==================================================================== */
    { 0x007E85B8, 0x003E63B8, OT_STRING, "Network/Connection",
      "Str_JoinAnotherServer",
      "'> Menu - Join another server.' - server change action" },

    { 0x007E76BE, 0x003E54BE, OT_STRING, "UI/Interface",
      "Str_InventoryPanel",
      "'Interface\\InventoryPanel.tga' - inventory panel texture" },

    { 0x007E556C, 0x003E336C, OT_STRING, "UI/Interface",
      "Str_LoginBack01",
      "'Logo\\Login_Back01.jpg' - login screen background 1" },

    { 0x007E5584, 0x003E3384, OT_STRING, "UI/Interface",
      "Str_LoginBack02",
      "'Logo\\Login_Back02.jpg' - login screen background 2" }
};

/* Количество офсетов в базе */
static const DWORD g_OffsetDatabaseCount =
    sizeof(g_OffsetDatabase) / sizeof(g_OffsetDatabase[0]);

/*
 * Получить тип офсета как строку
 */
static const char* GetOffsetTypeName(OFFSET_TYPE type)
{
    switch (type)
    {
        case OT_FUNCTION:    return "FUNC";
        case OT_VARIABLE:    return "VAR";
        case OT_STRING:      return "STR";
        case OT_VTABLE:      return "VTBL";
        case OT_IMPORT:      return "IAT";
        case OT_FLOAT_CONST: return "FLOAT";
        case OT_PACKET:      return "PKT";
        case OT_CRT:         return "CRT";
        case OT_DATA:        return "DATA";
        default:             return "UNK";
    }
}

const OFFSET_ENTRY* OffsetDB_GetAllOffsets(DWORD* pCount)
{
    if (pCount != NULL)
        *pCount = g_OffsetDatabaseCount;

    return g_OffsetDatabase;
}

void OffsetDB_LogAllOffsets(DWORD_PTR baseAddress)
{
    DWORD i;
    const char* lastCategory = "";

    Logger_WriteHeader("KNOWN GAME OFFSETS DATABASE (BAZA DANNYH OFSETOV)");

    Logger_Write(COLOR_INFO,
        "  ImageBase: 0x%08X (expected: 0x00400000)\n", (DWORD)baseAddress);
    Logger_Write(COLOR_INFO,
        "  Total known offsets: %u\n\n", g_OffsetDatabaseCount);

    Logger_Write(COLOR_INFO,
        "  Format: VA  (File: FileOffset)  [Type]  Name -- Description\n");

    for (i = 0; i < g_OffsetDatabaseCount; i++)
    {
        const OFFSET_ENTRY* entry = &g_OffsetDatabase[i];

        /* Разделитель при смене категории */
        if (strcmp(lastCategory, entry->Category) != 0)
        {
            Logger_Write(COLOR_DEFAULT, "\n");
            Logger_Write(COLOR_SECTION,
                "  --- %s ---\n", entry->Category);
            lastCategory = entry->Category;
        }

        /* Вывод офсета */
        switch (entry->Type)
        {
            case OT_FUNCTION:
            case OT_CRT:
                Logger_WriteFunction(entry->VA, entry->FileOffset,
                                     entry->Name, entry->Description);
                break;

            case OT_VARIABLE:
            case OT_FLOAT_CONST:
                Logger_WriteVariable(entry->VA, entry->FileOffset,
                                     entry->Name, entry->Description);
                break;

            default:
                Logger_WriteOffset(entry->VA, entry->FileOffset,
                                   GetOffsetTypeName(entry->Type),
                                   entry->Name, entry->Description);
                break;
        }
    }
}

BOOL OffsetDB_VerifyOffset(DWORD_PTR baseAddress, DWORD va)
{
    BYTE testByte;
    BOOL readable;

    __try
    {
        testByte = *(volatile BYTE*)(DWORD_PTR)va;
        (void)testByte;
        readable = TRUE;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        readable = FALSE;
    }

    return readable;
}
