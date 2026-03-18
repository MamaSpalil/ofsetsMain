/*
 * PatternScanner.h - Memory Pattern Scanner
 *
 * Provides fast pattern matching in process memory with support for
 * wildcard bytes, IDA-style signatures, and result caching.
 *
 * Features:
 *   - Byte pattern + mask scanning ("\\x55\\x8B\\xEC\\x83\\xEC\\x00", "xxxxx?")
 *   - IDA-style signature scanning ("55 8B EC 83 EC ??")
 *   - Module exports enumeration
 *   - Result caching between sessions
 *   - Multi-region scanning via VirtualQueryEx
 */

#ifndef MUTRACKER_PATTERN_SCANNER_H
#define MUTRACKER_PATTERN_SCANNER_H

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

namespace MuTracker {

/* Forward declarations */
class MemoryUtils;

/* Export entry from module's export table */
struct ExportEntry {
    std::string     name;
    uintptr_t       address;
    uint16_t        ordinal;
    bool            isForwarded;
    std::string     forwardName;    /* e.g., "NTDLL.RtlAllocateHeap" */
};

/* Scan result */
struct ScanResult {
    uintptr_t   address;        /* Absolute address of match */
    uintptr_t   offset;         /* Offset relative to module base */
    std::string moduleName;     /* Module where match was found */
};

/* Cached scan entry */
struct CachedScan {
    std::string     patternHash;
    std::string     moduleHash;
    std::vector<ScanResult> results;
};

class PatternScanner {
public:
    PatternScanner();
    ~PatternScanner();

    /*
     * Initialize the scanner with memory utilities.
     *
     * @param memory    Pointer to initialized MemoryUtils
     */
    void Init(MemoryUtils* memory);

    /*
     * Find a pattern in a specific module.
     * Uses byte pattern + mask format.
     *
     * @param moduleName    Module to scan (e.g., "main.exe")
     * @param pattern       Pattern bytes (including wildcard bytes)
     * @param mask          Mask string: 'x' = match, '?' = wildcard
     * @return              Address of first match, or 0 if not found
     */
    uintptr_t FindPattern(const char* moduleName,
                           const uint8_t* pattern,
                           const char* mask);

    /*
     * Find a pattern using IDA-style signature.
     * Format: "55 8B EC 83 EC ?? 56 57"
     *   - XX = exact byte match
     *   - ?? = wildcard (any byte)
     *   - ?  = single-char wildcard (same as ??)
     *
     * @param moduleName    Module to scan
     * @param idaPattern    IDA-style pattern string
     * @return              Address of first match, or 0 if not found
     */
    uintptr_t FindPatternIDA(const char* moduleName,
                              const std::string& idaPattern);

    /*
     * Find ALL occurrences of a pattern in a module.
     *
     * @param moduleName    Module to scan
     * @param pattern       Pattern bytes
     * @param mask          Mask string
     * @return              Vector of all matching addresses
     */
    std::vector<ScanResult> FindAllPatterns(const char* moduleName,
                                             const uint8_t* pattern,
                                             const char* mask);

    /*
     * Find ALL occurrences using IDA-style signature.
     */
    std::vector<ScanResult> FindAllPatternsIDA(const char* moduleName,
                                                const std::string& idaPattern);

    /*
     * Find a pattern in a specific memory range.
     *
     * @param startAddr     Start of scan range
     * @param size          Size of scan range
     * @param pattern       Pattern bytes
     * @param mask          Mask string
     * @return              Address of first match, or 0
     */
    uintptr_t FindPatternInRange(uintptr_t startAddr, size_t size,
                                  const uint8_t* pattern, const char* mask);

    /*
     * Resolve a relative offset from an instruction.
     * Used for CALL/JMP targets: target = instrAddr + instrSize + offset
     *
     * @param instrAddr     Address of the instruction
     * @param offsetPos     Position of the relative offset within instruction
     * @param instrSize     Total size of the instruction
     * @return              Resolved absolute address
     */
    uintptr_t ResolveRelativeOffset(uintptr_t instrAddr,
                                     int offsetPos,
                                     int instrSize);

    /*
     * Dump all exported functions from a module.
     *
     * @param moduleName    Module name
     * @return              Vector of export entries
     */
    std::vector<ExportEntry> DumpExports(const char* moduleName);

    /*
     * Parse IDA-style pattern into bytes + mask.
     *
     * @param idaPattern    IDA pattern string (e.g., "55 8B EC ?? 56")
     * @param outBytes      Output: pattern bytes
     * @param outMask       Output: mask string
     * @return              true if parsing succeeded
     */
    static bool ParseIDAPattern(const std::string& idaPattern,
                                 std::vector<uint8_t>& outBytes,
                                 std::string& outMask);

    /*
     * Save scan results to cache file.
     *
     * @param cacheFile     Path to cache file
     * @return              true if saved
     */
    bool SaveCache(const char* cacheFile);

    /*
     * Load scan results from cache file.
     *
     * @param cacheFile     Path to cache file
     * @return              true if loaded
     */
    bool LoadCache(const char* cacheFile);

    /* Clear the result cache */
    void ClearCache();

    /* Get statistics */
    size_t GetCacheHits() const { return m_cacheHits; }
    size_t GetCacheMisses() const { return m_cacheMisses; }
    size_t GetTotalScans() const { return m_totalScans; }
    size_t GetTotalMatches() const { return m_totalMatches; }

private:
    MemoryUtils*    m_memory;

    /* Result cache: hash(pattern+module) -> results */
    std::unordered_map<std::string, std::vector<ScanResult>> m_cache;

    /* Statistics */
    size_t          m_cacheHits;
    size_t          m_cacheMisses;
    size_t          m_totalScans;
    size_t          m_totalMatches;

    /* Internal: compare pattern bytes against memory */
    bool MatchPattern(const uint8_t* data, const uint8_t* pattern,
                       const char* mask, size_t patternLen);

    /* Internal: generate cache key from pattern + module */
    std::string MakeCacheKey(const char* moduleName,
                              const uint8_t* pattern,
                              const char* mask);
};

} /* namespace MuTracker */

#endif /* MUTRACKER_PATTERN_SCANNER_H */
