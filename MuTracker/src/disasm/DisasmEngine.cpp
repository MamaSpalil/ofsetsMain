/*
 * DisasmEngine.cpp - x86 Disassembler Engine Implementation
 */

#include "DisasmEngine.h"
#include "hde32.h"
#include <cstring>
#include <cstdio>

namespace MuTracker {

Instruction DisasmEngine::Decode(uintptr_t address, const void* code)
{
    Instruction instr = {};
    hde32s hs;

    instr.address = address;
    instr.length = static_cast<uint8_t>(hde32_disasm(code, &hs));
    instr.flags = hs.flags;
    instr.isRelative = (hs.flags & F_RELATIVE) != 0;
    instr.type = InstrType::Other;
    instr.targetAddress = 0;

    /* Copy raw bytes */
    if (instr.length > 0 && instr.length <= 15) {
        memcpy(instr.bytes, code, instr.length);
    }

    /* Classify the instruction */
    uint8_t op = hs.opcode;

    /* Skip prefixes for classification */
    if (hs.opcode == 0x0F) {
        /* Two-byte opcode */
        uint8_t op2 = hs.opcode2;

        /* 0x0F 0x80-0x8F: Jcc near (rel32) */
        if (op2 >= 0x80 && op2 <= 0x8F) {
            instr.type = InstrType::Jcc;
            if (instr.isRelative) {
                int32_t rel = static_cast<int32_t>(hs.imm.imm32);
                instr.targetAddress = address + instr.length + rel;
            }
        }
    } else {
        switch (op) {
        /* CALL rel32 */
        case 0xE8:
            instr.type = InstrType::Call;
            if (instr.isRelative) {
                int32_t rel = static_cast<int32_t>(hs.imm.imm32);
                instr.targetAddress = address + instr.length + rel;
            }
            break;

        /* CALL r/m32 (opcode FF /2) */
        case 0xFF:
            if ((hs.flags & F_MODRM) && hs.modrm_reg == 2) {
                instr.type = InstrType::Call;
            } else if ((hs.flags & F_MODRM) && hs.modrm_reg == 4) {
                instr.type = InstrType::JmpIndirect;
            } else if ((hs.flags & F_MODRM) && hs.modrm_reg == 6) {
                instr.type = InstrType::Push;
            }
            break;

        /* JMP rel32 */
        case 0xE9:
            instr.type = InstrType::JmpNear;
            if (instr.isRelative) {
                int32_t rel = static_cast<int32_t>(hs.imm.imm32);
                instr.targetAddress = address + instr.length + rel;
            }
            break;

        /* JMP rel8 */
        case 0xEB:
            instr.type = InstrType::JmpShort;
            if (instr.isRelative) {
                int8_t rel = static_cast<int8_t>(hs.imm.imm8);
                instr.targetAddress = address + instr.length + rel;
            }
            break;

        /* Jcc short (0x70-0x7F) */
        case 0x70: case 0x71: case 0x72: case 0x73:
        case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F:
            instr.type = InstrType::Jcc;
            if (instr.isRelative) {
                int8_t rel = static_cast<int8_t>(hs.imm.imm8);
                instr.targetAddress = address + instr.length + rel;
            }
            break;

        /* RET / RET imm16 */
        case 0xC3: case 0xC2:
        /* RETF / RETF imm16 */
        case 0xCB: case 0xCA:
            instr.type = InstrType::Ret;
            break;

        /* PUSH reg (0x50-0x57) */
        case 0x50: case 0x51: case 0x52: case 0x53:
        case 0x54: case 0x55: case 0x56: case 0x57:
        /* PUSH imm32 / PUSH imm8 */
        case 0x68: case 0x6A:
            instr.type = InstrType::Push;
            break;

        /* POP reg (0x58-0x5F) */
        case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            instr.type = InstrType::Pop;
            break;

        /* NOP */
        case 0x90:
            instr.type = InstrType::Nop;
            break;

        /* INT 3 */
        case 0xCC:
            instr.type = InstrType::Int3;
            break;

        default:
            instr.type = InstrType::Other;
            break;
        }
    }

    return instr;
}

std::vector<Instruction> DisasmEngine::DecodeUntil(uintptr_t address,
                                                    const void* code,
                                                    size_t minBytes)
{
    std::vector<Instruction> result;
    const uint8_t* p = static_cast<const uint8_t*>(code);
    size_t totalBytes = 0;

    while (totalBytes < minBytes) {
        Instruction instr = Decode(address + totalBytes, p + totalBytes);
        if (instr.length == 0) {
            /* Failed to decode - bail out to avoid infinite loop */
            break;
        }
        totalBytes += instr.length;
        result.push_back(instr);

        /* Safety: don't decode more than 64 bytes to prevent runaway */
        if (totalBytes > 64) {
            break;
        }
    }

    return result;
}

uint32_t DisasmEngine::GetInstructionLength(const void* code)
{
    hde32s hs;
    return hde32_disasm(code, &hs);
}

std::string DisasmEngine::Format(const Instruction& instr)
{
    char buf[256];
    char hexBuf[48] = {0};
    size_t hexPos = 0;

    /* Format raw bytes */
    for (uint8_t i = 0; i < instr.length && i < 15; ++i) {
        int written = snprintf(hexBuf + hexPos, sizeof(hexBuf) - hexPos,
                               "%02X ", instr.bytes[i]);
        if (written > 0 && hexPos + written < sizeof(hexBuf)) {
            hexPos += written;
        } else {
            break;
        }
    }

    /* Pad hex to 30 chars for alignment */
    while (hexPos < 30) {
        hexBuf[hexPos++] = ' ';
    }
    hexBuf[hexPos] = '\0';

    /* Format mnemonic */
    const char* mnemonic = "???";
    switch (instr.type) {
    case InstrType::Call:
        if (instr.isRelative)
            snprintf(buf, sizeof(buf), "%08X  %s CALL    0x%08X",
                     (uint32_t)instr.address, hexBuf, (uint32_t)instr.targetAddress);
        else
            snprintf(buf, sizeof(buf), "%08X  %s CALL    [indirect]",
                     (uint32_t)instr.address, hexBuf);
        return buf;
    case InstrType::JmpNear:
        snprintf(buf, sizeof(buf), "%08X  %s JMP     0x%08X",
                 (uint32_t)instr.address, hexBuf, (uint32_t)instr.targetAddress);
        return buf;
    case InstrType::JmpShort:
        snprintf(buf, sizeof(buf), "%08X  %s JMP     SHORT 0x%08X",
                 (uint32_t)instr.address, hexBuf, (uint32_t)instr.targetAddress);
        return buf;
    case InstrType::Jcc:
        snprintf(buf, sizeof(buf), "%08X  %s Jcc     0x%08X",
                 (uint32_t)instr.address, hexBuf, (uint32_t)instr.targetAddress);
        return buf;
    case InstrType::Ret:
        mnemonic = "RET"; break;
    case InstrType::Push:
        mnemonic = "PUSH"; break;
    case InstrType::Pop:
        mnemonic = "POP"; break;
    case InstrType::Nop:
        mnemonic = "NOP"; break;
    case InstrType::Int3:
        mnemonic = "INT3"; break;
    default:
        mnemonic = "..."; break;
    }

    snprintf(buf, sizeof(buf), "%08X  %s %s",
             (uint32_t)instr.address, hexBuf, mnemonic);
    return buf;
}

bool DisasmEngine::NeedsRelocationFixup(const void* code)
{
    hde32s hs;
    hde32_disasm(code, &hs);
    return (hs.flags & F_RELATIVE) != 0;
}

} /* namespace MuTracker */
