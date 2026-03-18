/*
 * DisasmEngine.h - C++ wrapper around x86 instruction length decoder
 *
 * Provides instruction decoding, CALL/JMP/RET detection, and formatted
 * disassembly output for the MuTracker hook engine.
 */

#ifndef MUTRACKER_DISASM_ENGINE_H
#define MUTRACKER_DISASM_ENGINE_H

#include <cstdint>
#include <string>
#include <vector>

namespace MuTracker {

/* Instruction type classification */
enum class InstrType {
    Unknown,
    Call,           /* CALL rel32 / CALL r/m32 */
    JmpShort,       /* JMP rel8 */
    JmpNear,        /* JMP rel32 */
    JmpIndirect,    /* JMP r/m32 */
    Jcc,            /* Conditional jump (Jcc rel8/rel32) */
    Ret,            /* RET / RETF / RET imm16 */
    Push,           /* PUSH reg/imm/r/m */
    Pop,            /* POP reg/r/m */
    Nop,            /* NOP / multi-byte NOP */
    Int3,           /* INT 3 (breakpoint) */
    Other           /* All other instructions */
};

/* Decoded instruction info */
struct Instruction {
    uintptr_t   address;        /* Address of this instruction */
    uint8_t     length;         /* Length in bytes */
    uint8_t     bytes[15];      /* Raw instruction bytes */
    InstrType   type;           /* Instruction classification */
    bool        isRelative;     /* Has relative offset (needs fixup in trampoline) */
    uintptr_t   targetAddress;  /* Target of CALL/JMP if relative */
    uint32_t    flags;          /* Raw HDE32 flags */
};

class DisasmEngine {
public:
    DisasmEngine() = default;
    ~DisasmEngine() = default;

    /*
     * Decode a single instruction at the given address.
     *
     * @param address   Address of the instruction
     * @param code      Pointer to instruction bytes
     * @return          Decoded instruction info
     */
    Instruction Decode(uintptr_t address, const void* code);

    /*
     * Decode instructions until we have at least `minBytes` worth.
     * Used to determine the trampoline size for inline hooks.
     *
     * @param address   Starting address
     * @param code      Pointer to code bytes
     * @param minBytes  Minimum number of bytes needed
     * @return          Vector of decoded instructions
     */
    std::vector<Instruction> DecodeUntil(uintptr_t address, const void* code,
                                          size_t minBytes);

    /*
     * Get just the instruction length at a given address.
     *
     * @param code  Pointer to instruction bytes
     * @return      Length in bytes (0 on error)
     */
    uint32_t GetInstructionLength(const void* code);

    /*
     * Format an instruction as a human-readable string (Intel syntax).
     *
     * @param instr     Decoded instruction
     * @return          Formatted string (e.g., "CALL 0x004012AB")
     */
    std::string Format(const Instruction& instr);

    /*
     * Check if an instruction at `address` is a relative branch/call
     * that would need fixup when relocated to a trampoline.
     *
     * @param code  Pointer to instruction bytes
     * @return      true if instruction contains a relative offset
     */
    bool NeedsRelocationFixup(const void* code);
};

} /* namespace MuTracker */

#endif /* MUTRACKER_DISASM_ENGINE_H */
