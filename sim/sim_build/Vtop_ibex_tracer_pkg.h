// Verilated -*- C++ -*-
// DESCRIPTION: Verilator output: Design internal header
// See Vtop.h for the primary calling header

#ifndef VERILATED_VTOP_IBEX_TRACER_PKG_H_
#define VERILATED_VTOP_IBEX_TRACER_PKG_H_  // guard

#include "verilated.h"


class Vtop__Syms;

class alignas(VL_CACHE_LINE_BYTES) Vtop_ibex_tracer_pkg final : public VerilatedModule {
  public:

    // INTERNAL VARIABLES
    Vtop__Syms* const vlSymsp;

    // PARAMETERS
    static constexpr CData/*1:0*/ OPCODE_C0 = 0U;
    static constexpr CData/*1:0*/ OPCODE_C1 = 1U;
    static constexpr CData/*1:0*/ OPCODE_C2 = 2U;
    static constexpr SData/*15:0*/ INSN_CADDI4SPN = 0U;
    static constexpr SData/*15:0*/ INSN_CLW = 0x4000U;
    static constexpr SData/*15:0*/ INSN_CSW = 0xc000U;
    static constexpr SData/*15:0*/ INSN_CADDI = 1U;
    static constexpr SData/*15:0*/ INSN_CJAL = 0x2001U;
    static constexpr SData/*15:0*/ INSN_CJ = 0xa001U;
    static constexpr SData/*15:0*/ INSN_CLI = 0x4001U;
    static constexpr SData/*15:0*/ INSN_CLUI = 0x6001U;
    static constexpr SData/*15:0*/ INSN_CBEQZ = 0xc001U;
    static constexpr SData/*15:0*/ INSN_CBNEZ = 0xe001U;
    static constexpr SData/*15:0*/ INSN_CSRLI = 0x8001U;
    static constexpr SData/*15:0*/ INSN_CSRAI = 0x8401U;
    static constexpr SData/*15:0*/ INSN_CANDI = 0x8801U;
    static constexpr SData/*15:0*/ INSN_CSUB = 0x8c01U;
    static constexpr SData/*15:0*/ INSN_CXOR = 0x8c21U;
    static constexpr SData/*15:0*/ INSN_COR = 0x8c41U;
    static constexpr SData/*15:0*/ INSN_CAND = 0x8c61U;
    static constexpr SData/*15:0*/ INSN_CSLLI = 2U;
    static constexpr SData/*15:0*/ INSN_CLWSP = 0x4002U;
    static constexpr SData/*15:0*/ INSN_SWSP = 0xc002U;
    static constexpr SData/*15:0*/ INSN_CMV = 0x8002U;
    static constexpr SData/*15:0*/ INSN_CADD = 0x9002U;
    static constexpr SData/*15:0*/ INSN_CEBREAK = 0x9002U;
    static constexpr SData/*15:0*/ INSN_CJR = 0x8002U;
    static constexpr SData/*15:0*/ INSN_CJALR = 0x9002U;
    static constexpr IData/*31:0*/ INSN_LUI = 0x00000037U;
    static constexpr IData/*31:0*/ INSN_AUIPC = 0x00000017U;
    static constexpr IData/*31:0*/ INSN_JAL = 0x0000006fU;
    static constexpr IData/*31:0*/ INSN_JALR = 0x00000067U;
    static constexpr IData/*31:0*/ INSN_BEQ = 0x00000063U;
    static constexpr IData/*31:0*/ INSN_BNE = 0x00001063U;
    static constexpr IData/*31:0*/ INSN_BLT = 0x00004063U;
    static constexpr IData/*31:0*/ INSN_BGE = 0x00005063U;
    static constexpr IData/*31:0*/ INSN_BLTU = 0x00006063U;
    static constexpr IData/*31:0*/ INSN_BGEU = 0x00007063U;
    static constexpr IData/*31:0*/ INSN_ADDI = 0x00000013U;
    static constexpr IData/*31:0*/ INSN_SLTI = 0x00002013U;
    static constexpr IData/*31:0*/ INSN_SLTIU = 0x00003013U;
    static constexpr IData/*31:0*/ INSN_XORI = 0x00004013U;
    static constexpr IData/*31:0*/ INSN_ORI = 0x00006013U;
    static constexpr IData/*31:0*/ INSN_ANDI = 0x00007013U;
    static constexpr IData/*31:0*/ INSN_SLLI = 0x00001013U;
    static constexpr IData/*31:0*/ INSN_SRLI = 0x00005013U;
    static constexpr IData/*31:0*/ INSN_SRAI = 0x40005013U;
    static constexpr IData/*31:0*/ INSN_ADD = 0x00000033U;
    static constexpr IData/*31:0*/ INSN_SUB = 0x40000033U;
    static constexpr IData/*31:0*/ INSN_SLL = 0x00001033U;
    static constexpr IData/*31:0*/ INSN_SLT = 0x00002033U;
    static constexpr IData/*31:0*/ INSN_SLTU = 0x00003033U;
    static constexpr IData/*31:0*/ INSN_XOR = 0x00004033U;
    static constexpr IData/*31:0*/ INSN_SRL = 0x00005033U;
    static constexpr IData/*31:0*/ INSN_SRA = 0x40005033U;
    static constexpr IData/*31:0*/ INSN_OR = 0x00006033U;
    static constexpr IData/*31:0*/ INSN_AND = 0x00007033U;
    static constexpr IData/*31:0*/ INSN_CSRRW = 0x00001073U;
    static constexpr IData/*31:0*/ INSN_CSRRS = 0x00002073U;
    static constexpr IData/*31:0*/ INSN_CSRRC = 0x00003073U;
    static constexpr IData/*31:0*/ INSN_CSRRWI = 0x00005073U;
    static constexpr IData/*31:0*/ INSN_CSRRSI = 0x00006073U;
    static constexpr IData/*31:0*/ INSN_CSRRCI = 0x00007073U;
    static constexpr IData/*31:0*/ INSN_ECALL = 0x00000073U;
    static constexpr IData/*31:0*/ INSN_EBREAK = 0x00100073U;
    static constexpr IData/*31:0*/ INSN_MRET = 0x30200073U;
    static constexpr IData/*31:0*/ INSN_DRET = 0x7b200073U;
    static constexpr IData/*31:0*/ INSN_WFI = 0x10500073U;
    static constexpr IData/*31:0*/ INSN_DIV = 0x02004033U;
    static constexpr IData/*31:0*/ INSN_DIVU = 0x02005033U;
    static constexpr IData/*31:0*/ INSN_REM = 0x02006033U;
    static constexpr IData/*31:0*/ INSN_REMU = 0x02007033U;
    static constexpr IData/*31:0*/ INSN_PMUL = 0x02000033U;
    static constexpr IData/*31:0*/ INSN_PMUH = 0x02001033U;
    static constexpr IData/*31:0*/ INSN_PMULHSU = 0x02002033U;
    static constexpr IData/*31:0*/ INSN_PMULHU = 0x02003033U;
    static constexpr IData/*31:0*/ INSN_SH1ADD = 0x20002033U;
    static constexpr IData/*31:0*/ INSN_SH2ADD = 0x20004033U;
    static constexpr IData/*31:0*/ INSN_SH3ADD = 0x20006033U;
    static constexpr IData/*31:0*/ INSN_RORI = 0x60005013U;
    static constexpr IData/*31:0*/ INSN_CLZ = 0x60001013U;
    static constexpr IData/*31:0*/ INSN_CTZ = 0x60101013U;
    static constexpr IData/*31:0*/ INSN_CPOP = 0x60201013U;
    static constexpr IData/*31:0*/ INSN_SEXTB = 0x60401013U;
    static constexpr IData/*31:0*/ INSN_SEXTH = 0x60501013U;
    static constexpr IData/*31:0*/ INSN_ROL = 0x60001033U;
    static constexpr IData/*31:0*/ INSN_ROR = 0x60005033U;
    static constexpr IData/*31:0*/ INSN_MIN = 0x0a004033U;
    static constexpr IData/*31:0*/ INSN_MAX = 0x0a006033U;
    static constexpr IData/*31:0*/ INSN_MINU = 0x0a005033U;
    static constexpr IData/*31:0*/ INSN_MAXU = 0x0a007033U;
    static constexpr IData/*31:0*/ INSN_XNOR = 0x40004033U;
    static constexpr IData/*31:0*/ INSN_ORN = 0x40006033U;
    static constexpr IData/*31:0*/ INSN_ANDN = 0x40007033U;
    static constexpr IData/*31:0*/ INSN_PACK = 0x08004033U;
    static constexpr IData/*31:0*/ INSN_PACKU = 0x48004033U;
    static constexpr IData/*31:0*/ INSN_PACKH = 0x08007033U;
    static constexpr IData/*31:0*/ INSN_BCLRI = 0x48001013U;
    static constexpr IData/*31:0*/ INSN_BSETI = 0x28001013U;
    static constexpr IData/*31:0*/ INSN_BINVI = 0x68001013U;
    static constexpr IData/*31:0*/ INSN_BEXTI = 0x48005013U;
    static constexpr IData/*31:0*/ INSN_BCLR = 0x48001033U;
    static constexpr IData/*31:0*/ INSN_BSET = 0x28001033U;
    static constexpr IData/*31:0*/ INSN_BINV = 0x68001033U;
    static constexpr IData/*31:0*/ INSN_BEXT = 0x48005033U;
    static constexpr IData/*31:0*/ INSN_GREVI = 0x68005013U;
    static constexpr IData/*31:0*/ INSN_REV_P = 0x68105013U;
    static constexpr IData/*31:0*/ INSN_REV2_N = 0x68205013U;
    static constexpr IData/*31:0*/ INSN_REV_N = 0x68305013U;
    static constexpr IData/*31:0*/ INSN_REV4_B = 0x68405013U;
    static constexpr IData/*31:0*/ INSN_REV2_B = 0x68605013U;
    static constexpr IData/*31:0*/ INSN_REV_B = 0x68705013U;
    static constexpr IData/*31:0*/ INSN_REV8_H = 0x68805013U;
    static constexpr IData/*31:0*/ INSN_REV4_H = 0x68c05013U;
    static constexpr IData/*31:0*/ INSN_REV2_H = 0x68e05013U;
    static constexpr IData/*31:0*/ INSN_REV_H = 0x68f05013U;
    static constexpr IData/*31:0*/ INSN_REV16 = 0x69005013U;
    static constexpr IData/*31:0*/ INSN_REV8 = 0x69805013U;
    static constexpr IData/*31:0*/ INSN_REV4 = 0x69c05013U;
    static constexpr IData/*31:0*/ INSN_REV2 = 0x69e05013U;
    static constexpr IData/*31:0*/ INSN_REV = 0x69f05013U;
    static constexpr IData/*31:0*/ INSN_GORCI = 0x28005013U;
    static constexpr IData/*31:0*/ INSN_ORC_P = 0x28105013U;
    static constexpr IData/*31:0*/ INSN_ORC2_N = 0x28205013U;
    static constexpr IData/*31:0*/ INSN_ORC_N = 0x28305013U;
    static constexpr IData/*31:0*/ INSN_ORC4_B = 0x28405013U;
    static constexpr IData/*31:0*/ INSN_ORC2_B = 0x28605013U;
    static constexpr IData/*31:0*/ INSN_ORC_B = 0x28705013U;
    static constexpr IData/*31:0*/ INSN_ORC8_H = 0x28805013U;
    static constexpr IData/*31:0*/ INSN_ORC4_H = 0x28c05013U;
    static constexpr IData/*31:0*/ INSN_ORC2_H = 0x28e05013U;
    static constexpr IData/*31:0*/ INSN_ORC_H = 0x28f05013U;
    static constexpr IData/*31:0*/ INSN_ORC16 = 0x29005013U;
    static constexpr IData/*31:0*/ INSN_ORC8 = 0x29805013U;
    static constexpr IData/*31:0*/ INSN_ORC4 = 0x29c05013U;
    static constexpr IData/*31:0*/ INSN_ORC2 = 0x29e05013U;
    static constexpr IData/*31:0*/ INSN_ORC = 0x29f05013U;
    static constexpr IData/*31:0*/ INSN_SHFLI = 0x08001013U;
    static constexpr IData/*31:0*/ INSN_ZIP_N = 0x08101013U;
    static constexpr IData/*31:0*/ INSN_ZIP2_B = 0x08201013U;
    static constexpr IData/*31:0*/ INSN_ZIP_B = 0x08301013U;
    static constexpr IData/*31:0*/ INSN_ZIP4_H = 0x08401013U;
    static constexpr IData/*31:0*/ INSN_ZIP2_H = 0x08601013U;
    static constexpr IData/*31:0*/ INSN_ZIP_H = 0x08701013U;
    static constexpr IData/*31:0*/ INSN_ZIP8 = 0x08801013U;
    static constexpr IData/*31:0*/ INSN_ZIP4 = 0x08c01013U;
    static constexpr IData/*31:0*/ INSN_ZIP2 = 0x08e01013U;
    static constexpr IData/*31:0*/ INSN_ZIP = 0x08f01013U;
    static constexpr IData/*31:0*/ INSN_UNSHFLI = 0x08005013U;
    static constexpr IData/*31:0*/ INSN_UNZIP_N = 0x08105013U;
    static constexpr IData/*31:0*/ INSN_UNZIP2_B = 0x08205013U;
    static constexpr IData/*31:0*/ INSN_UNZIP_B = 0x08305013U;
    static constexpr IData/*31:0*/ INSN_UNZIP4_H = 0x08405013U;
    static constexpr IData/*31:0*/ INSN_UNZIP2_H = 0x08605013U;
    static constexpr IData/*31:0*/ INSN_UNZIP_H = 0x08705013U;
    static constexpr IData/*31:0*/ INSN_UNZIP8 = 0x08805013U;
    static constexpr IData/*31:0*/ INSN_UNZIP4 = 0x08c05013U;
    static constexpr IData/*31:0*/ INSN_UNZIP2 = 0x08e05013U;
    static constexpr IData/*31:0*/ INSN_UNZIP = 0x08f05013U;
    static constexpr IData/*31:0*/ INSN_GREV = 0x68005033U;
    static constexpr IData/*31:0*/ INSN_GORC = 0x28005033U;
    static constexpr IData/*31:0*/ INSN_SHFL = 0x08001033U;
    static constexpr IData/*31:0*/ INSN_UNSHFL = 0x08005033U;
    static constexpr IData/*31:0*/ INSN_XPERM_N = 0x28002033U;
    static constexpr IData/*31:0*/ INSN_XPERM_B = 0x28004033U;
    static constexpr IData/*31:0*/ INSN_XPERM_H = 0x28006033U;
    static constexpr IData/*31:0*/ INSN_SLO = 0x20001033U;
    static constexpr IData/*31:0*/ INSN_SRO = 0x20005033U;
    static constexpr IData/*31:0*/ INSN_SLOI = 0x20001013U;
    static constexpr IData/*31:0*/ INSN_SROI = 0x20005013U;
    static constexpr IData/*31:0*/ INSN_BDECOMPRESS = 0x48006033U;
    static constexpr IData/*31:0*/ INSN_BCOMPRESS = 0x08006033U;
    static constexpr IData/*31:0*/ INSN_FSRI = 0x04005013U;
    static constexpr IData/*31:0*/ INSN_CMIX = 0x06001033U;
    static constexpr IData/*31:0*/ INSN_CMOV = 0x06005033U;
    static constexpr IData/*31:0*/ INSN_FSL = 0x04001033U;
    static constexpr IData/*31:0*/ INSN_FSR = 0x04005033U;
    static constexpr IData/*31:0*/ INSN_BFP = 0x48007033U;
    static constexpr IData/*31:0*/ INSN_CLMUL = 0x0a001033U;
    static constexpr IData/*31:0*/ INSN_CLMULR = 0x0a002033U;
    static constexpr IData/*31:0*/ INSN_CLMULH = 0x0a003033U;
    static constexpr IData/*31:0*/ INSN_CRC32_B = 0x61001013U;
    static constexpr IData/*31:0*/ INSN_CRC32_H = 0x61101013U;
    static constexpr IData/*31:0*/ INSN_CRC32_W = 0x61201013U;
    static constexpr IData/*31:0*/ INSN_CRC32C_B = 0x61801013U;
    static constexpr IData/*31:0*/ INSN_CRC32C_H = 0x61901013U;
    static constexpr IData/*31:0*/ INSN_CRC32C_W = 0x61a01013U;
    static constexpr IData/*31:0*/ INSN_LOAD = 3U;
    static constexpr IData/*31:0*/ INSN_STORE = 0x00000023U;
    static constexpr IData/*31:0*/ INSN_FENCE = 0x0000000fU;
    static constexpr IData/*31:0*/ INSN_FENCEI = 0x0000100fU;

    // CONSTRUCTORS
    Vtop_ibex_tracer_pkg(Vtop__Syms* symsp, const char* v__name);
    ~Vtop_ibex_tracer_pkg();
    VL_UNCOPYABLE(Vtop_ibex_tracer_pkg);

    // INTERNAL METHODS
    void __Vconfigure(bool first);
};


#endif  // guard
