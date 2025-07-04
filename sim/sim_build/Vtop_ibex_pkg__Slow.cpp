// Verilated -*- C++ -*-
// DESCRIPTION: Verilator output: Design implementation internals
// See Vtop.h for the primary calling header

#include "Vtop__pch.h"
#include "Vtop__Syms.h"
#include "Vtop_ibex_pkg.h"

// Parameter definitions for Vtop_ibex_pkg
constexpr CData/*6:0*/ Vtop_ibex_pkg::ExcCauseIrqSoftwareM;
constexpr CData/*6:0*/ Vtop_ibex_pkg::ExcCauseIrqTimerM;
constexpr CData/*6:0*/ Vtop_ibex_pkg::ExcCauseIrqExternalM;
constexpr CData/*6:0*/ Vtop_ibex_pkg::ExcCauseIrqNm;
constexpr CData/*6:0*/ Vtop_ibex_pkg::ExcCauseInsnAddrMisa;
constexpr CData/*6:0*/ Vtop_ibex_pkg::ExcCauseInstrAccessFault;
constexpr CData/*6:0*/ Vtop_ibex_pkg::ExcCauseIllegalInsn;
constexpr CData/*6:0*/ Vtop_ibex_pkg::ExcCauseBreakpoint;
constexpr CData/*6:0*/ Vtop_ibex_pkg::ExcCauseLoadAccessFault;
constexpr CData/*6:0*/ Vtop_ibex_pkg::ExcCauseStoreAccessFault;
constexpr CData/*6:0*/ Vtop_ibex_pkg::ExcCauseEcallUMode;
constexpr CData/*6:0*/ Vtop_ibex_pkg::ExcCauseEcallMMode;
constexpr CData/*1:0*/ Vtop_ibex_pkg::CSR_MISA_MXL;
const VlWide<5>/*159:0*/ Vtop_ibex_pkg::RndCnstLfsrPermDefault = {{
    0x78a8daed, 0xc04fa438, 0x2e958152, 0x467fd1b1,
    0x1e35ecba
}};
constexpr CData/*3:0*/ Vtop_ibex_pkg::IbexMuBiOn;
constexpr CData/*3:0*/ Vtop_ibex_pkg::IbexMuBiOff;
constexpr CData/*2:0*/ Vtop_ibex_pkg::PmpMseccfgRst;
constexpr SData/*11:0*/ Vtop_ibex_pkg::CSR_OFF_PMP_CFG;
constexpr SData/*11:0*/ Vtop_ibex_pkg::CSR_OFF_PMP_ADDR;
constexpr IData/*31:0*/ Vtop_ibex_pkg::ADDR_W;
constexpr IData/*31:0*/ Vtop_ibex_pkg::BUS_SIZE;
constexpr IData/*31:0*/ Vtop_ibex_pkg::BUS_BYTES;
constexpr IData/*31:0*/ Vtop_ibex_pkg::BUS_W;
constexpr IData/*31:0*/ Vtop_ibex_pkg::IC_SIZE_BYTES;
constexpr IData/*31:0*/ Vtop_ibex_pkg::IC_NUM_WAYS;
constexpr IData/*31:0*/ Vtop_ibex_pkg::IC_LINE_SIZE;
constexpr IData/*31:0*/ Vtop_ibex_pkg::IC_LINE_BYTES;
constexpr IData/*31:0*/ Vtop_ibex_pkg::IC_LINE_W;
constexpr IData/*31:0*/ Vtop_ibex_pkg::IC_NUM_LINES;
constexpr IData/*31:0*/ Vtop_ibex_pkg::IC_LINE_BEATS;
constexpr IData/*31:0*/ Vtop_ibex_pkg::IC_LINE_BEATS_W;
constexpr IData/*31:0*/ Vtop_ibex_pkg::IC_INDEX_W;
constexpr IData/*31:0*/ Vtop_ibex_pkg::IC_INDEX_HI;
constexpr IData/*31:0*/ Vtop_ibex_pkg::IC_TAG_SIZE;
constexpr IData/*31:0*/ Vtop_ibex_pkg::IC_OUTPUT_BEATS;
constexpr IData/*31:0*/ Vtop_ibex_pkg::SCRAMBLE_KEY_W;
constexpr IData/*31:0*/ Vtop_ibex_pkg::SCRAMBLE_NONCE_W;
constexpr IData/*31:0*/ Vtop_ibex_pkg::PMP_MAX_REGIONS;
constexpr IData/*31:0*/ Vtop_ibex_pkg::PMP_CFG_W;
constexpr IData/*31:0*/ Vtop_ibex_pkg::PMP_I;
constexpr IData/*31:0*/ Vtop_ibex_pkg::PMP_I2;
constexpr IData/*31:0*/ Vtop_ibex_pkg::PMP_D;
constexpr IData/*31:0*/ Vtop_ibex_pkg::CSR_MSTATUS_MIE_BIT;
constexpr IData/*31:0*/ Vtop_ibex_pkg::CSR_MSTATUS_MPIE_BIT;
constexpr IData/*31:0*/ Vtop_ibex_pkg::CSR_MSTATUS_MPP_BIT_LOW;
constexpr IData/*31:0*/ Vtop_ibex_pkg::CSR_MSTATUS_MPP_BIT_HIGH;
constexpr IData/*31:0*/ Vtop_ibex_pkg::CSR_MSTATUS_MPRV_BIT;
constexpr IData/*31:0*/ Vtop_ibex_pkg::CSR_MSTATUS_TW_BIT;
constexpr IData/*31:0*/ Vtop_ibex_pkg::CSR_MSIX_BIT;
constexpr IData/*31:0*/ Vtop_ibex_pkg::CSR_MTIX_BIT;
constexpr IData/*31:0*/ Vtop_ibex_pkg::CSR_MEIX_BIT;
constexpr IData/*31:0*/ Vtop_ibex_pkg::CSR_MFIX_BIT_LOW;
constexpr IData/*31:0*/ Vtop_ibex_pkg::CSR_MFIX_BIT_HIGH;
constexpr IData/*31:0*/ Vtop_ibex_pkg::CSR_MSECCFG_MML_BIT;
constexpr IData/*31:0*/ Vtop_ibex_pkg::CSR_MSECCFG_MMWP_BIT;
constexpr IData/*31:0*/ Vtop_ibex_pkg::CSR_MSECCFG_RLB_BIT;
constexpr IData/*31:0*/ Vtop_ibex_pkg::CSR_MARCHID_VALUE;
constexpr IData/*31:0*/ Vtop_ibex_pkg::CSR_MCONFIGPTR_VALUE;
constexpr IData/*31:0*/ Vtop_ibex_pkg::LfsrWidth;
constexpr IData/*31:0*/ Vtop_ibex_pkg::RndCnstLfsrSeedDefault;
constexpr VlWide<4>/*127:0*/ Vtop_ibex_pkg::RndCnstIbexKeyDefault;
constexpr IData/*31:0*/ Vtop_ibex_pkg::IbexMuBiWidth;
constexpr QData/*63:0*/ Vtop_ibex_pkg::RndCnstIbexNonceDefault;
constexpr VlUnpacked<CData/*5:0*/, 16> Vtop_ibex_pkg::PmpCfgRst;
constexpr VlUnpacked<QData/*33:0*/, 16> Vtop_ibex_pkg::PmpAddrRst;


void Vtop_ibex_pkg___ctor_var_reset(Vtop_ibex_pkg* vlSelf);

Vtop_ibex_pkg::Vtop_ibex_pkg(Vtop__Syms* symsp, const char* v__name)
    : VerilatedModule{v__name}
    , vlSymsp{symsp}
 {
    // Reset structure values
    Vtop_ibex_pkg___ctor_var_reset(this);
}

void Vtop_ibex_pkg::__Vconfigure(bool first) {
    (void)first;  // Prevent unused variable warning
}

Vtop_ibex_pkg::~Vtop_ibex_pkg() {
}
