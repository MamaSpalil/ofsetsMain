/*
 * table32.h - x86 (32-bit) Opcode Tables for Instruction Length Decoding
 *
 * These tables encode the operand types for each opcode, allowing the
 * decoder to determine instruction length without full disassembly.
 *
 * Encoding:
 *   C_MODRM   - Instruction has ModR/M byte
 *   C_IMM8    - 8-bit immediate
 *   C_IMM16   - 16-bit immediate
 *   C_IMM_P66 - Immediate is 16-bit with 0x66 prefix, else 32-bit
 *   C_REL8    - 8-bit relative offset
 *   C_REL32   - 32-bit relative offset
 *   C_GROUP   - Opcode uses reg field of ModR/M for opcode extension
 *   C_ERROR   - Invalid/undefined opcode
 */

#ifndef TABLE32_H
#define TABLE32_H

#define C_NONE     0x00
#define C_MODRM    0x01
#define C_IMM8     0x02
#define C_IMM16    0x04
#define C_IMM_P66  0x08  /* 32-bit immediate, or 16-bit with 0x66 prefix */
#define C_REL8     0x10
#define C_REL32    0x20
#define C_GROUP    0x40
#define C_ERROR    0x80

/*
 * Primary opcode table (1-byte opcodes: 0x00 - 0xFF)
 *
 * Each entry describes the operand encoding for the corresponding opcode.
 */
static const unsigned char hde32_table[] = {
    /* 0x00-0x07: ADD r/m,r  ADD r,r/m  ADD AL,imm8  ADD eAX,imm32  PUSH ES  POP ES */
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_IMM8, C_IMM_P66, C_NONE, C_NONE,
    /* 0x08-0x0F: OR variants, PUSH CS, 2-byte escape */
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_IMM8, C_IMM_P66, C_NONE, C_NONE,
    /* 0x10-0x17: ADC */
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_IMM8, C_IMM_P66, C_NONE, C_NONE,
    /* 0x18-0x1F: SBB */
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_IMM8, C_IMM_P66, C_NONE, C_NONE,
    /* 0x20-0x27: AND */
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_IMM8, C_IMM_P66, C_NONE, C_NONE,
    /* 0x28-0x2F: SUB */
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_IMM8, C_IMM_P66, C_NONE, C_NONE,
    /* 0x30-0x37: XOR */
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_IMM8, C_IMM_P66, C_NONE, C_NONE,
    /* 0x38-0x3F: CMP */
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_IMM8, C_IMM_P66, C_NONE, C_NONE,
    /* 0x40-0x47: INC reg (eAX-eDI) */
    C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE,
    /* 0x48-0x4F: DEC reg (eAX-eDI) */
    C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE,
    /* 0x50-0x57: PUSH reg */
    C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE,
    /* 0x58-0x5F: POP reg */
    C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE,
    /* 0x60-0x67: PUSHA, POPA, BOUND, ARPL, FS:, GS:, OpSize, AddrSize */
    C_NONE, C_NONE, C_MODRM, C_MODRM, C_NONE, C_NONE, C_NONE, C_NONE,
    /* 0x68-0x6F: PUSH imm32, IMUL r,r/m,imm32, PUSH imm8, IMUL r,r/m,imm8, INS, OUTS */
    C_IMM_P66, C_MODRM | C_IMM_P66, C_IMM8, C_MODRM | C_IMM8, C_NONE, C_NONE, C_NONE, C_NONE,
    /* 0x70-0x77: Jcc short (JO, JNO, JB, JNB, JZ, JNZ, JBE, JNBE) */
    C_REL8, C_REL8, C_REL8, C_REL8, C_REL8, C_REL8, C_REL8, C_REL8,
    /* 0x78-0x7F: Jcc short (JS, JNS, JP, JNP, JL, JNL, JLE, JNLE) */
    C_REL8, C_REL8, C_REL8, C_REL8, C_REL8, C_REL8, C_REL8, C_REL8,
    /* 0x80-0x83: Group 1 (ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r/m, imm) */
    C_MODRM | C_IMM8, C_MODRM | C_IMM_P66, C_MODRM | C_IMM8, C_MODRM | C_IMM8,
    /* 0x84-0x87: TEST r/m,r   XCHG r/m,r */
    C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    /* 0x88-0x8F: MOV r/m,r  MOV r,r/m  MOV r/m,Sreg  LEA  MOV Sreg,r/m  POP r/m */
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    /* 0x90-0x97: NOP/XCHG eAX,reg */
    C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE,
    /* 0x98-0x9F: CBW, CWD, CALL ptr16:32, FWAIT, PUSHFD, POPFD, SAHF, LAHF */
    C_NONE, C_NONE, C_IMM16 | C_IMM_P66, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE,
    /* 0xA0-0xA3: MOV AL,moffs  MOV eAX,moffs  MOV moffs,AL  MOV moffs,eAX */
    C_IMM_P66, C_IMM_P66, C_IMM_P66, C_IMM_P66,
    /* 0xA4-0xA7: MOVS, CMPS */
    C_NONE, C_NONE, C_NONE, C_NONE,
    /* 0xA8-0xAF: TEST AL,imm8  TEST eAX,imm32  STOS  LODS  SCAS */
    C_IMM8, C_IMM_P66, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE,
    /* 0xB0-0xB7: MOV reg8, imm8 */
    C_IMM8, C_IMM8, C_IMM8, C_IMM8, C_IMM8, C_IMM8, C_IMM8, C_IMM8,
    /* 0xB8-0xBF: MOV reg32, imm32 */
    C_IMM_P66, C_IMM_P66, C_IMM_P66, C_IMM_P66, C_IMM_P66, C_IMM_P66, C_IMM_P66, C_IMM_P66,
    /* 0xC0-0xC7: Shift r/m,imm8  RET imm16  RET  LES  LDS  MOV r/m,imm8  MOV r/m,imm32 */
    C_MODRM | C_IMM8, C_MODRM | C_IMM8, C_IMM16, C_NONE, C_MODRM, C_MODRM,
    C_MODRM | C_IMM8, C_MODRM | C_IMM_P66,
    /* 0xC8-0xCF: ENTER imm16,imm8  LEAVE  RETF imm16  RETF  INT3  INT imm8  INTO  IRET */
    C_IMM16 | C_IMM8, C_NONE, C_IMM16, C_NONE, C_NONE, C_IMM8, C_NONE, C_NONE,
    /* 0xD0-0xD7: Shift r/m,1  Shift r/m,CL  AAM  AAD  SALC  XLAT */
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_IMM8, C_IMM8, C_NONE, C_NONE,
    /* 0xD8-0xDF: FPU (x87) escape opcodes - all have ModR/M */
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    /* 0xE0-0xE7: LOOPNZ, LOOPZ, LOOP, JCXZ, IN, OUT */
    C_REL8, C_REL8, C_REL8, C_REL8, C_IMM8, C_IMM8, C_IMM8, C_IMM8,
    /* 0xE8-0xEF: CALL rel32, JMP rel32, JMP far, JMP rel8, IN, OUT */
    C_REL32, C_REL32, C_IMM16 | C_IMM_P66, C_REL8, C_NONE, C_NONE, C_NONE, C_NONE,
    /* 0xF0-0xF7: LOCK, INT1, REPNZ, REP, HLT, CMC, Group 3 (TEST/NOT/NEG/MUL/DIV) */
    C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_MODRM, C_MODRM,
    /* 0xF8-0xFF: CLC, STC, CLI, STI, CLD, STD, Group 4 (INC/DEC r/m8), Group 5 */
    C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_MODRM, C_MODRM
};

/*
 * Two-byte opcode table (0x0F xx: 0x00 - 0xFF)
 */
static const unsigned char hde32_table_0F[] = {
    /* 0x0F 0x00-0x07: Group 6/7, LAR, LSL, LOADALL, CLTS, LOADALL */
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_ERROR, C_ERROR, C_NONE, C_ERROR,
    /* 0x0F 0x08-0x0F: INVD, WBINVD, reserved, UD2, reserved, PREFETCH, FEMMS, 3DNow */
    C_NONE, C_NONE, C_ERROR, C_NONE, C_ERROR, C_MODRM, C_NONE, C_MODRM | C_IMM8,
    /* 0x0F 0x10-0x17: SSE MOV instructions */
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    /* 0x0F 0x18-0x1F: Prefetch hints, NOPs */
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    /* 0x0F 0x20-0x27: MOV CR/DR/TR */
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_ERROR, C_MODRM, C_ERROR,
    /* 0x0F 0x28-0x2F: SSE MOVAPS/MOVAPD, CVTPI2PS, etc. */
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    /* 0x0F 0x30-0x37: WRMSR, RDTSC, RDMSR, RDPMC, SYSENTER, SYSEXIT, reserved, GETSEC */
    C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_ERROR, C_NONE,
    /* 0x0F 0x38-0x3F: SSSE3/SSE4 3-byte escape, reserved */
    C_ERROR, C_ERROR, C_ERROR, C_ERROR, C_ERROR, C_ERROR, C_ERROR, C_ERROR,
    /* 0x0F 0x40-0x4F: CMOVcc */
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    /* 0x0F 0x50-0x5F: SSE MOVMSKPS, SQRTPS, etc. */
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    /* 0x0F 0x60-0x6F: MMX/SSE pack/unpack, MOVD, MOVQ, etc. */
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    /* 0x0F 0x70-0x7F: PSHUFW, Group 12/13/14, PCMPEQ, EMMS, VMREAD, VMWRITE, MOVD, MOVQ */
    C_MODRM | C_IMM8, C_MODRM | C_IMM8, C_MODRM | C_IMM8, C_MODRM | C_IMM8,
    C_MODRM, C_MODRM, C_MODRM, C_NONE,
    C_MODRM, C_MODRM, C_ERROR, C_ERROR, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    /* 0x0F 0x80-0x8F: Jcc near (rel32) */
    C_REL32, C_REL32, C_REL32, C_REL32, C_REL32, C_REL32, C_REL32, C_REL32,
    C_REL32, C_REL32, C_REL32, C_REL32, C_REL32, C_REL32, C_REL32, C_REL32,
    /* 0x0F 0x90-0x9F: SETcc */
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    /* 0x0F 0xA0-0xA7: PUSH FS, POP FS, CPUID, BT, SHLD, SHLD */
    C_NONE, C_NONE, C_NONE, C_MODRM, C_MODRM | C_IMM8, C_MODRM, C_ERROR, C_ERROR,
    /* 0x0F 0xA8-0xAF: PUSH GS, POP GS, RSM, BTS, SHRD, SHRD, Group 15, IMUL */
    C_NONE, C_NONE, C_NONE, C_MODRM, C_MODRM | C_IMM8, C_MODRM, C_MODRM, C_MODRM,
    /* 0x0F 0xB0-0xB7: CMPXCHG, LSS, BTR, LFS, LGS, MOVZX */
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    /* 0x0F 0xB8-0xBF: JMPE, Group 10, Group 8 r/m,imm8, BTC, BSF, BSR, MOVSX */
    C_MODRM, C_MODRM, C_MODRM | C_IMM8, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    /* 0x0F 0xC0-0xC7: XADD, SSE CMP, PINSRW, PEXTRW, SHUFPS, Group 9 (CMPXCHG8B) */
    C_MODRM, C_MODRM, C_MODRM | C_IMM8, C_MODRM, C_MODRM | C_IMM8, C_MODRM | C_IMM8,
    C_MODRM | C_IMM8, C_MODRM,
    /* 0x0F 0xC8-0xCF: BSWAP reg */
    C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE,
    /* 0x0F 0xD0-0xDF: SSE/MMX instructions */
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    /* 0x0F 0xE0-0xEF: SSE/MMX instructions */
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    /* 0x0F 0xF0-0xFF: SSE/MMX instructions */
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_ERROR
};

/*
 * Group 3 opcode extensions (0xF6/0xF7):
 * - reg=0,1: TEST r/m, imm  (has immediate)
 * - reg=2: NOT r/m           (no immediate)
 * - reg=3: NEG r/m           (no immediate)
 * - reg=4: MUL r/m           (no immediate)
 * - reg=5: IMUL r/m          (no immediate)
 * - reg=6: DIV r/m           (no immediate)
 * - reg=7: IDIV r/m          (no immediate)
 */
#define GROUP3_HAS_IMM(reg) ((reg) <= 1)

#endif /* TABLE32_H */
