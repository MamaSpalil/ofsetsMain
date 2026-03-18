/*
 * hde32.c - x86 (32-bit) Instruction Length Decoder Implementation
 *
 * Decodes x86 instructions to determine their length, including all
 * prefixes, opcodes, ModR/M, SIB, displacement, and immediate bytes.
 */

#include "hde32.h"
#include "table32.h"
#include <string.h>

unsigned int hde32_disasm(const void *code, hde32s *hs)
{
    const uint8_t *p = (const uint8_t *)code;
    uint8_t opcode;
    uint8_t cflags;
    uint8_t modrm;
    uint8_t mod, reg, rm;
    int has_prefix_66 = 0;
    int has_prefix_67 = 0;
    int is_two_byte = 0;

    memset(hs, 0, sizeof(hde32s));

    /* Phase 1: Parse instruction prefixes */
    for (;;) {
        uint8_t b = *p;
        switch (b) {
            case PREFIX_LOCK:
                hs->p_lock = b;
                hs->flags |= F_PREFIX_LOCK;
                p++;
                continue;
            case PREFIX_REPNZ:
                hs->p_rep = b;
                hs->flags |= F_PREFIX_REPNZ;
                p++;
                continue;
            case PREFIX_REPX:
                hs->p_rep = b;
                hs->flags |= F_PREFIX_REPX;
                p++;
                continue;
            case PREFIX_OPERAND_SIZE:
                hs->p_66 = b;
                has_prefix_66 = 1;
                hs->flags |= F_PREFIX_66;
                p++;
                continue;
            case PREFIX_ADDRESS_SIZE:
                hs->p_67 = b;
                has_prefix_67 = 1;
                hs->flags |= F_PREFIX_67;
                p++;
                continue;
            case PREFIX_SEGMENT_CS:
            case PREFIX_SEGMENT_SS:
            case PREFIX_SEGMENT_DS:
            case PREFIX_SEGMENT_ES:
            case PREFIX_SEGMENT_FS:
            case PREFIX_SEGMENT_GS:
                hs->p_seg = b;
                hs->flags |= F_PREFIX_SEG;
                p++;
                continue;
            default:
                break;
        }
        break;
    }

    /* Phase 2: Read opcode */
    opcode = *p++;
    hs->opcode = opcode;

    if (opcode == 0x0F) {
        /* Two-byte opcode */
        is_two_byte = 1;
        opcode = *p++;
        hs->opcode2 = opcode;
        cflags = hde32_table_0F[opcode];
    } else {
        cflags = hde32_table[opcode];
    }

    /* Check for error */
    if (cflags & C_ERROR) {
        hs->flags |= F_ERROR | F_ERROR_OPCODE;
        /* Still compute length as best we can */
    }

    /* Phase 3: Parse ModR/M byte if present */
    if (cflags & C_MODRM) {
        modrm = *p++;
        hs->modrm = modrm;
        hs->flags |= F_MODRM;
        mod = (modrm >> 6) & 0x03;
        reg = (modrm >> 3) & 0x07;
        rm  = modrm & 0x07;
        hs->modrm_mod = mod;
        hs->modrm_reg = reg;
        hs->modrm_rm  = rm;

        /* Check for SIB byte: present when mod != 3 and rm == 4 */
        if (mod != 3 && rm == 4) {
            uint8_t sib = *p++;
            hs->sib = sib;
            hs->flags |= F_SIB;
            hs->sib_scale = (sib >> 6) & 0x03;
            hs->sib_index = (sib >> 3) & 0x07;
            hs->sib_base  = sib & 0x07;

            /* Special case: SIB base=5 with mod=0 means disp32 (no base) */
            if (hs->sib_base == 5 && mod == 0) {
                hs->flags |= F_DISP32;
            }
        }

        /* Displacement based on mod field */
        if (has_prefix_67) {
            /* 16-bit addressing mode */
            if (mod == 0 && rm == 6) {
                hs->flags |= F_DISP16;
            } else if (mod == 1) {
                hs->flags |= F_DISP8;
            } else if (mod == 2) {
                hs->flags |= F_DISP16;
            }
        } else {
            /* 32-bit addressing mode */
            if (mod == 0 && rm == 5) {
                hs->flags |= F_DISP32;
            } else if (mod == 1) {
                hs->flags |= F_DISP8;
            } else if (mod == 2) {
                hs->flags |= F_DISP32;
            }
        }

        /* Group 3 special case: TEST has immediate but NOT/NEG/MUL/DIV don't */
        if (!is_two_byte && (opcode == 0xF6 || opcode == 0xF7)) {
            if (GROUP3_HAS_IMM(reg)) {
                if (opcode == 0xF6) {
                    cflags |= C_IMM8;
                } else {
                    cflags |= C_IMM_P66;
                }
            }
        }
    }

    /* Phase 4: Read displacement bytes */
    if (hs->flags & F_DISP8) {
        hs->disp.disp8 = *p;
        p += 1;
    } else if (hs->flags & F_DISP16) {
        hs->disp.disp16 = *(const uint16_t *)p;
        p += 2;
    } else if (hs->flags & F_DISP32) {
        hs->disp.disp32 = *(const uint32_t *)p;
        p += 4;
    }

    /* Phase 5: Read immediate/relative bytes */
    if (cflags & C_IMM8) {
        hs->imm.imm8 = *p;
        hs->flags |= F_IMM8;
        p += 1;
    }
    if (cflags & C_IMM16) {
        hs->imm.imm16 = *(const uint16_t *)p;
        hs->flags |= F_IMM16;
        p += 2;
    }
    if (cflags & C_IMM_P66) {
        if (has_prefix_66) {
            hs->imm.imm16 = *(const uint16_t *)p;
            hs->flags |= F_IMM16;
            p += 2;
        } else {
            hs->imm.imm32 = *(const uint32_t *)p;
            hs->flags |= F_IMM32;
            p += 4;
        }
    }
    if (cflags & C_REL8) {
        hs->imm.imm8 = *p;
        hs->flags |= F_IMM8 | F_RELATIVE;
        p += 1;
    }
    if (cflags & C_REL32) {
        hs->imm.imm32 = *(const uint32_t *)p;
        hs->flags |= F_IMM32 | F_RELATIVE;
        p += 4;
    }

    /* Special handling for 0x9A (CALL far ptr16:32) and 0xEA (JMP far) */
    if (!is_two_byte && (opcode == 0x9A || opcode == 0xEA)) {
        /* These use ptr16:32 encoding: 4-byte offset + 2-byte segment */
        /* Already handled by IMM16|IMM_P66 in table, which gives 6 bytes total */
    }

    /* Special handling for moffs addressing (0xA0-0xA3) in non-ModR/M mode */
    /* The table encodes these as C_IMM_P66 which is correct for 32-bit mode */

    hs->len = (uint8_t)(p - (const uint8_t *)code);

    /* Sanity check: x86 instructions shouldn't exceed 15 bytes */
    if (hs->len > 15) {
        hs->flags |= F_ERROR | F_ERROR_LENGTH;
    }

    return hs->len;
}
