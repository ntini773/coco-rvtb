// Verilated -*- C++ -*-
// DESCRIPTION: Verilator output: Design implementation internals
// See Vtop.h for the primary calling header

#include "Vtop__pch.h"
#include "Vtop__Syms.h"
#include "Vtop_ibex_tracer_pkg.h"

// Parameter definitions for Vtop_ibex_tracer_pkg
constexpr CData/*1:0*/ Vtop_ibex_tracer_pkg::OPCODE_C0;
constexpr CData/*1:0*/ Vtop_ibex_tracer_pkg::OPCODE_C1;
constexpr CData/*1:0*/ Vtop_ibex_tracer_pkg::OPCODE_C2;
constexpr SData/*15:0*/ Vtop_ibex_tracer_pkg::INSN_CADDI4SPN;
constexpr SData/*15:0*/ Vtop_ibex_tracer_pkg::INSN_CLW;
constexpr SData/*15:0*/ Vtop_ibex_tracer_pkg::INSN_CSW;
constexpr SData/*15:0*/ Vtop_ibex_tracer_pkg::INSN_CADDI;
constexpr SData/*15:0*/ Vtop_ibex_tracer_pkg::INSN_CJAL;
constexpr SData/*15:0*/ Vtop_ibex_tracer_pkg::INSN_CJ;
constexpr SData/*15:0*/ Vtop_ibex_tracer_pkg::INSN_CLI;
constexpr SData/*15:0*/ Vtop_ibex_tracer_pkg::INSN_CLUI;
constexpr SData/*15:0*/ Vtop_ibex_tracer_pkg::INSN_CBEQZ;
constexpr SData/*15:0*/ Vtop_ibex_tracer_pkg::INSN_CBNEZ;
constexpr SData/*15:0*/ Vtop_ibex_tracer_pkg::INSN_CSRLI;
constexpr SData/*15:0*/ Vtop_ibex_tracer_pkg::INSN_CSRAI;
constexpr SData/*15:0*/ Vtop_ibex_tracer_pkg::INSN_CANDI;
constexpr SData/*15:0*/ Vtop_ibex_tracer_pkg::INSN_CSUB;
constexpr SData/*15:0*/ Vtop_ibex_tracer_pkg::INSN_CXOR;
constexpr SData/*15:0*/ Vtop_ibex_tracer_pkg::INSN_COR;
constexpr SData/*15:0*/ Vtop_ibex_tracer_pkg::INSN_CAND;
constexpr SData/*15:0*/ Vtop_ibex_tracer_pkg::INSN_CSLLI;
constexpr SData/*15:0*/ Vtop_ibex_tracer_pkg::INSN_CLWSP;
constexpr SData/*15:0*/ Vtop_ibex_tracer_pkg::INSN_SWSP;
constexpr SData/*15:0*/ Vtop_ibex_tracer_pkg::INSN_CMV;
constexpr SData/*15:0*/ Vtop_ibex_tracer_pkg::INSN_CADD;
constexpr SData/*15:0*/ Vtop_ibex_tracer_pkg::INSN_CEBREAK;
constexpr SData/*15:0*/ Vtop_ibex_tracer_pkg::INSN_CJR;
constexpr SData/*15:0*/ Vtop_ibex_tracer_pkg::INSN_CJALR;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_LUI;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_AUIPC;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_JAL;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_JALR;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_BEQ;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_BNE;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_BLT;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_BGE;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_BLTU;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_BGEU;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ADDI;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_SLTI;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_SLTIU;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_XORI;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ORI;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ANDI;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_SLLI;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_SRLI;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_SRAI;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ADD;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_SUB;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_SLL;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_SLT;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_SLTU;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_XOR;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_SRL;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_SRA;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_OR;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_AND;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_CSRRW;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_CSRRS;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_CSRRC;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_CSRRWI;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_CSRRSI;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_CSRRCI;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ECALL;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_EBREAK;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_MRET;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_DRET;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_WFI;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_DIV;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_DIVU;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_REM;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_REMU;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_PMUL;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_PMUH;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_PMULHSU;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_PMULHU;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_SH1ADD;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_SH2ADD;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_SH3ADD;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_RORI;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_CLZ;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_CTZ;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_CPOP;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_SEXTB;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_SEXTH;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ROL;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ROR;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_MIN;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_MAX;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_MINU;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_MAXU;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_XNOR;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ORN;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ANDN;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_PACK;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_PACKU;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_PACKH;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_BCLRI;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_BSETI;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_BINVI;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_BEXTI;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_BCLR;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_BSET;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_BINV;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_BEXT;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_GREVI;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_REV_P;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_REV2_N;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_REV_N;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_REV4_B;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_REV2_B;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_REV_B;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_REV8_H;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_REV4_H;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_REV2_H;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_REV_H;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_REV16;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_REV8;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_REV4;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_REV2;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_REV;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_GORCI;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ORC_P;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ORC2_N;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ORC_N;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ORC4_B;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ORC2_B;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ORC_B;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ORC8_H;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ORC4_H;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ORC2_H;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ORC_H;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ORC16;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ORC8;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ORC4;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ORC2;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ORC;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_SHFLI;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ZIP_N;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ZIP2_B;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ZIP_B;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ZIP4_H;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ZIP2_H;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ZIP_H;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ZIP8;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ZIP4;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ZIP2;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_ZIP;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_UNSHFLI;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_UNZIP_N;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_UNZIP2_B;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_UNZIP_B;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_UNZIP4_H;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_UNZIP2_H;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_UNZIP_H;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_UNZIP8;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_UNZIP4;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_UNZIP2;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_UNZIP;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_GREV;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_GORC;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_SHFL;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_UNSHFL;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_XPERM_N;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_XPERM_B;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_XPERM_H;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_SLO;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_SRO;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_SLOI;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_SROI;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_BDECOMPRESS;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_BCOMPRESS;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_FSRI;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_CMIX;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_CMOV;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_FSL;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_FSR;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_BFP;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_CLMUL;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_CLMULR;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_CLMULH;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_CRC32_B;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_CRC32_H;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_CRC32_W;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_CRC32C_B;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_CRC32C_H;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_CRC32C_W;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_LOAD;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_STORE;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_FENCE;
constexpr IData/*31:0*/ Vtop_ibex_tracer_pkg::INSN_FENCEI;


void Vtop_ibex_tracer_pkg___ctor_var_reset(Vtop_ibex_tracer_pkg* vlSelf);

Vtop_ibex_tracer_pkg::Vtop_ibex_tracer_pkg(Vtop__Syms* symsp, const char* v__name)
    : VerilatedModule{v__name}
    , vlSymsp{symsp}
 {
    // Reset structure values
    Vtop_ibex_tracer_pkg___ctor_var_reset(this);
}

void Vtop_ibex_tracer_pkg::__Vconfigure(bool first) {
    (void)first;  // Prevent unused variable warning
}

Vtop_ibex_tracer_pkg::~Vtop_ibex_tracer_pkg() {
}
