/*
 * hde32 - x86 (32-bit) Instruction Length Decoder
 *
 * Lightweight instruction length decoder for x86 (IA-32) instructions.
 * Used for inline hook trampoline creation - determines how many bytes
 * to copy from the beginning of a function to create a valid trampoline.
 *
 * Supports:
 *   - All standard x86 instruction prefixes
 *   - 1-byte and 2-byte (0x0F) opcodes
 *   - ModR/M and SIB byte decoding
 *   - Displacement and immediate operand sizing
 *   - FPU (x87), MMX, SSE instruction lengths
 *
 * This is a clean-room implementation based on the Intel x86 ISA reference.
 */

#ifndef HDE32_H
#define HDE32_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Instruction flags */
#define F_MODRM         0x00000001
#define F_SIB           0x00000002
#define F_IMM8          0x00000004
#define F_IMM16         0x00000008
#define F_IMM32         0x00000010
#define F_DISP8         0x00000020
#define F_DISP16        0x00000040
#define F_DISP32        0x00000080
#define F_RELATIVE      0x00000100
#define F_ERROR         0x00001000
#define F_ERROR_OPCODE  0x00002000
#define F_ERROR_LENGTH  0x00004000
#define F_ERROR_LOCK    0x00008000
#define F_ERROR_OPERAND 0x00010000
#define F_PREFIX_REPNZ  0x01000000
#define F_PREFIX_REPX   0x02000000
#define F_PREFIX_REP    0x03000000
#define F_PREFIX_66     0x04000000
#define F_PREFIX_67     0x08000000
#define F_PREFIX_LOCK   0x10000000
#define F_PREFIX_SEG    0x20000000
#define F_PREFIX_ANY    0x3F000000

/* Prefix values */
#define PREFIX_SEGMENT_CS   0x2E
#define PREFIX_SEGMENT_SS   0x36
#define PREFIX_SEGMENT_DS   0x3E
#define PREFIX_SEGMENT_ES   0x26
#define PREFIX_SEGMENT_FS   0x64
#define PREFIX_SEGMENT_GS   0x65
#define PREFIX_LOCK         0xF0
#define PREFIX_REPNZ        0xF2
#define PREFIX_REPX         0xF3
#define PREFIX_OPERAND_SIZE 0x66
#define PREFIX_ADDRESS_SIZE 0x67

/* Decoded instruction structure */
typedef struct {
    uint8_t  len;           /* Total instruction length in bytes */
    uint8_t  p_rep;         /* REP/REPNZ prefix (0xF2 or 0xF3) */
    uint8_t  p_lock;        /* LOCK prefix (0xF0) */
    uint8_t  p_seg;         /* Segment override prefix */
    uint8_t  p_66;          /* Operand-size override (0x66) */
    uint8_t  p_67;          /* Address-size override (0x67) */
    uint8_t  opcode;        /* Primary opcode byte */
    uint8_t  opcode2;       /* Secondary opcode (if 2-byte: 0x0F xx) */
    uint8_t  modrm;         /* ModR/M byte */
    uint8_t  modrm_mod;     /* ModR/M: mod field (bits 7-6) */
    uint8_t  modrm_reg;     /* ModR/M: reg field (bits 5-3) */
    uint8_t  modrm_rm;      /* ModR/M: r/m field (bits 2-0) */
    uint8_t  sib;           /* SIB byte */
    uint8_t  sib_scale;     /* SIB: scale field */
    uint8_t  sib_index;     /* SIB: index field */
    uint8_t  sib_base;      /* SIB: base field */
    union {
        uint8_t  imm8;
        uint16_t imm16;
        uint32_t imm32;
    } imm;                  /* Immediate operand */
    union {
        uint8_t  disp8;
        uint16_t disp16;
        uint32_t disp32;
    } disp;                 /* Displacement */
    uint32_t flags;         /* Instruction flags (F_xxx) */
} hde32s;

/*
 * Decode a single x86 instruction.
 *
 * @param code  Pointer to the instruction bytes
 * @param hs    Output: decoded instruction structure
 * @return      Length of the instruction in bytes (0 on error)
 */
unsigned int hde32_disasm(const void *code, hde32s *hs);

#ifdef __cplusplus
}
#endif

#endif /* HDE32_H */
