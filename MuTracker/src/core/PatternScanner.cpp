/*
 * PatternScanner.cpp - Memory Pattern Scanner Implementation
 *
 * Scans process memory for byte patterns with wildcard support.
 * Works in both local (injected DLL) and remote (ReadProcessMemory) modes.
 */

#include "PatternScanner.h"
#include "MemoryUtils.h"
#include <cstring>
#include <cctype>
#include <cstdio>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <functional>

namespace MuTracker {

PatternScanner::PatternScanner()
    : m_memory(nullptr)
    , m_cacheHits(0)
    , m_cacheMisses(0)
    , m_totalScans(0)
    , m_totalMatches(0)
{
}

PatternScanner::~PatternScanner()
{
}

void PatternScanner::Init(MemoryUtils* memory)
{
    m_memory = memory;
}

/* ------------------------------------------------------------------ */
/*  Pattern Matching Core                                              */
/* ------------------------------------------------------------------ */

bool PatternScanner::MatchPattern(const uint8_t* data,
                                   const uint8_t* pattern,
                                   const char* mask,
                                   size_t patternLen)
{
    for (size_t i = 0; i < patternLen; ++i) {
        if (mask[i] == 'x' && data[i] != pattern[i]) {
            return false;
        }
        /* mask[i] == '?' means wildcard - skip comparison */
    }
    return true;
}

/* ------------------------------------------------------------------ */
/*  IDA Pattern Parsing                                                */
/* ------------------------------------------------------------------ */

bool PatternScanner::ParseIDAPattern(const std::string& idaPattern,
                                      std::vector<uint8_t>& outBytes,
                                      std::string& outMask)
{
    outBytes.clear();
    outMask.clear();

    std::istringstream ss(idaPattern);
    std::string token;

    while (ss >> token) {
        if (token == "?" || token == "??") {
            outBytes.push_back(0x00);
            outMask += '?';
        } else {
            /* Parse hex byte */
            unsigned int value = 0;
            bool valid = true;
            for (char c : token) {
                if (!std::isxdigit(static_cast<unsigned char>(c))) {
                    valid = false;
                    break;
                }
            }
            if (!valid || token.empty()) return false;

            char* end = nullptr;
            value = static_cast<unsigned int>(strtoul(token.c_str(), &end, 16));
            if (end == token.c_str() || value > 0xFF) return false;

            outBytes.push_back(static_cast<uint8_t>(value));
            outMask += 'x';
        }
    }

    return !outBytes.empty();
}

/* ------------------------------------------------------------------ */
/*  Cache Management                                                   */
/* ------------------------------------------------------------------ */

std::string PatternScanner::MakeCacheKey(const char* moduleName,
                                          const uint8_t* pattern,
                                          const char* mask)
{
    /* Simple hash: combine module name with pattern bytes and mask */
    std::string key;
    key += moduleName;
    key += "|";

    size_t maskLen = strlen(mask);
    for (size_t i = 0; i < maskLen; ++i) {
        char buf[4];
        snprintf(buf, sizeof(buf), "%02X", pattern[i]);
        key += buf;
    }
    key += "|";
    key += mask;

    return key;
}

bool PatternScanner::SaveCache(const char* cacheFile)
{
    std::ofstream file(cacheFile, std::ios::binary);
    if (!file.is_open()) return false;

    /* Format: one line per cache entry
     * KEY|COUNT|ADDR1,OFFSET1,MOD1|ADDR2,OFFSET2,MOD2|...
     */
    for (const auto& pair : m_cache) {
        file << pair.first << "|" << pair.second.size();
        for (const auto& result : pair.second) {
            char buf[64];
            snprintf(buf, sizeof(buf), "|%08X,%08X,%s",
                     static_cast<uint32_t>(result.address),
                     static_cast<uint32_t>(result.offset),
                     result.moduleName.c_str());
            file << buf;
        }
        file << "\n";
    }

    return true;
}

bool PatternScanner::LoadCache(const char* cacheFile)
{
    std::ifstream file(cacheFile);
    if (!file.is_open()) return false;

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;

        /* Parse cache line */
        size_t pos1 = line.find('|');
        if (pos1 == std::string::npos) continue;

        std::string key = line.substr(0, pos1);
        size_t pos2 = line.find('|', pos1 + 1);
        if (pos2 == std::string::npos) continue;

        std::vector<ScanResult> results;
        std::string rest = line.substr(pos2 + 1);

        /* Parse each result entry */
        std::istringstream ss(rest);
        std::string entry;
        while (std::getline(ss, entry, '|')) {
            if (entry.empty()) continue;
            ScanResult r;
            char modName[256] = {};
            uint32_t addr = 0, offset = 0;
            if (sscanf(entry.c_str(), "%X,%X,%255s", &addr, &offset, modName) >= 2) {
                r.address = addr;
                r.offset = offset;
                r.moduleName = modName;
                results.push_back(r);
            }
        }

        m_cache[key] = results;
    }

    return true;
}

void PatternScanner::ClearCache()
{
    m_cache.clear();
    m_cacheHits = 0;
    m_cacheMisses = 0;
}

/* ------------------------------------------------------------------ */
/*  Pattern Scanning                                                   */
/* ------------------------------------------------------------------ */

uintptr_t PatternScanner::FindPattern(const char* moduleName,
                                       const uint8_t* pattern,
                                       const char* mask)
{
    auto results = FindAllPatterns(moduleName, pattern, mask);
    return results.empty() ? 0 : results[0].address;
}

uintptr_t PatternScanner::FindPatternIDA(const char* moduleName,
                                          const std::string& idaPattern)
{
    std::vector<uint8_t> bytes;
    std::string mask;

    if (!ParseIDAPattern(idaPattern, bytes, mask)) {
        return 0;
    }

    return FindPattern(moduleName, bytes.data(), mask.c_str());
}

std::vector<ScanResult> PatternScanner::FindAllPatterns(
    const char* moduleName,
    const uint8_t* pattern,
    const char* mask)
{
    m_totalScans++;

    if (!m_memory || !m_memory->IsInitialized()) {
        return {};
    }

    /* Check cache first */
    std::string cacheKey = MakeCacheKey(moduleName, pattern, mask);
    auto it = m_cache.find(cacheKey);
    if (it != m_cache.end()) {
        m_cacheHits++;
        return it->second;
    }
    m_cacheMisses++;

    std::vector<ScanResult> results;
    size_t maskLen = strlen(mask);

    if (maskLen == 0) return results;

    /* Get module base and size */
    uintptr_t moduleBase = m_memory->GetModuleBase(moduleName);
    size_t moduleSize = m_memory->GetModuleSize(moduleName);

    if (moduleBase == 0 || moduleSize == 0) {
        return results;
    }

    /* Read module memory in chunks for efficiency */
    const size_t CHUNK_SIZE = 64 * 1024; /* 64 KB chunks */
    std::vector<uint8_t> buffer(CHUNK_SIZE + maskLen);

    for (size_t offset = 0; offset < moduleSize; offset += CHUNK_SIZE) {
        size_t readSize = std::min(CHUNK_SIZE + maskLen - 1,
                                    moduleSize - offset);
        if (readSize < maskLen) break;

        if (!m_memory->Read(moduleBase + offset, buffer.data(), readSize)) {
            continue;
        }

        /* Scan this chunk */
        size_t scanEnd = readSize - maskLen + 1;
        for (size_t i = 0; i < scanEnd; ++i) {
            if (MatchPattern(buffer.data() + i, pattern, mask, maskLen)) {
                ScanResult result;
                result.address = moduleBase + offset + i;
                result.offset = offset + i;
                result.moduleName = moduleName;
                results.push_back(result);
                m_totalMatches++;
            }
        }
    }

    /* Store in cache */
    m_cache[cacheKey] = results;

    return results;
}

std::vector<ScanResult> PatternScanner::FindAllPatternsIDA(
    const char* moduleName,
    const std::string& idaPattern)
{
    std::vector<uint8_t> bytes;
    std::string mask;

    if (!ParseIDAPattern(idaPattern, bytes, mask)) {
        return {};
    }

    return FindAllPatterns(moduleName, bytes.data(), mask.c_str());
}

uintptr_t PatternScanner::FindPatternInRange(uintptr_t startAddr,
                                              size_t size,
                                              const uint8_t* pattern,
                                              const char* mask)
{
    if (!m_memory || !m_memory->IsInitialized()) return 0;

    size_t maskLen = strlen(mask);
    if (maskLen == 0 || size < maskLen) return 0;

    m_totalScans++;

    /* Read memory */
    std::vector<uint8_t> buffer(size);
    if (!m_memory->Read(startAddr, buffer.data(), size)) {
        return 0;
    }

    /* Scan */
    size_t scanEnd = size - maskLen + 1;
    for (size_t i = 0; i < scanEnd; ++i) {
        if (MatchPattern(buffer.data() + i, pattern, mask, maskLen)) {
            m_totalMatches++;
            return startAddr + i;
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Relative Offset Resolution                                         */
/* ------------------------------------------------------------------ */

uintptr_t PatternScanner::ResolveRelativeOffset(uintptr_t instrAddr,
                                                  int offsetPos,
                                                  int instrSize)
{
    if (!m_memory || !m_memory->IsInitialized()) return 0;

    int32_t relOffset = 0;
    if (!m_memory->ReadValue<int32_t>(instrAddr + offsetPos, relOffset)) {
        return 0;
    }

    return instrAddr + instrSize + relOffset;
}

/* ------------------------------------------------------------------ */
/*  Module Export Enumeration                                           */
/* ------------------------------------------------------------------ */

std::vector<ExportEntry> PatternScanner::DumpExports(const char* moduleName)
{
    std::vector<ExportEntry> exports;

    if (!m_memory || !m_memory->IsInitialized()) return exports;

    uintptr_t moduleBase = m_memory->GetModuleBase(moduleName);
    if (moduleBase == 0) return exports;

#ifdef _WIN32
    /* Read DOS header */
    IMAGE_DOS_HEADER dosHeader;
    if (!m_memory->Read(moduleBase, &dosHeader, sizeof(dosHeader))) return exports;
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) return exports;

    /* Read NT headers */
    IMAGE_NT_HEADERS32 ntHeaders;
    if (!m_memory->Read(moduleBase + dosHeader.e_lfanew,
                        &ntHeaders, sizeof(ntHeaders))) return exports;
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) return exports;

    /* Get export directory */
    IMAGE_DATA_DIRECTORY& exportDir =
        ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (exportDir.VirtualAddress == 0 || exportDir.Size == 0) return exports;

    uintptr_t exportBase = moduleBase + exportDir.VirtualAddress;

    IMAGE_EXPORT_DIRECTORY exportDirectory;
    if (!m_memory->Read(exportBase, &exportDirectory, sizeof(exportDirectory))) {
        return exports;
    }

    /* Read function addresses, names, and ordinals */
    std::vector<uint32_t> funcAddrs(exportDirectory.NumberOfFunctions);
    std::vector<uint32_t> nameAddrs(exportDirectory.NumberOfNames);
    std::vector<uint16_t> ordinals(exportDirectory.NumberOfNames);

    if (exportDirectory.NumberOfFunctions > 0) {
        m_memory->Read(moduleBase + exportDirectory.AddressOfFunctions,
                       funcAddrs.data(),
                       funcAddrs.size() * sizeof(uint32_t));
    }

    if (exportDirectory.NumberOfNames > 0) {
        m_memory->Read(moduleBase + exportDirectory.AddressOfNames,
                       nameAddrs.data(),
                       nameAddrs.size() * sizeof(uint32_t));
        m_memory->Read(moduleBase + exportDirectory.AddressOfNameOrdinals,
                       ordinals.data(),
                       ordinals.size() * sizeof(uint16_t));
    }

    /* Build export list with names */
    for (uint32_t i = 0; i < exportDirectory.NumberOfNames; ++i) {
        ExportEntry entry;
        entry.ordinal = ordinals[i] + static_cast<uint16_t>(exportDirectory.Base);

        /* Read function name */
        entry.name = m_memory->ReadString(moduleBase + nameAddrs[i], 256);

        /* Get function address */
        if (ordinals[i] < funcAddrs.size()) {
            uint32_t funcRVA = funcAddrs[ordinals[i]];

            /* Check if forwarded (RVA points inside export directory) */
            if (funcRVA >= exportDir.VirtualAddress &&
                funcRVA < exportDir.VirtualAddress + exportDir.Size) {
                entry.isForwarded = true;
                entry.forwardName = m_memory->ReadString(moduleBase + funcRVA, 256);
                entry.address = 0;
            } else {
                entry.isForwarded = false;
                entry.address = moduleBase + funcRVA;
            }
        }

        exports.push_back(entry);
    }
#endif

    return exports;
}

} /* namespace MuTracker */
