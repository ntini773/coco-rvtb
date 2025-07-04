// Verilated -*- C++ -*-
// DESCRIPTION: Verilator output: Design internal header
// See Vtop.h for the primary calling header

#ifndef VERILATED_VTOP_IBEX_PKG_H_
#define VERILATED_VTOP_IBEX_PKG_H_  // guard

#include "verilated.h"


class Vtop__Syms;

class alignas(VL_CACHE_LINE_BYTES) Vtop_ibex_pkg final : public VerilatedModule {
  public:

    // INTERNAL VARIABLES
    Vtop__Syms* const vlSymsp;

    // PARAMETERS
    static constexpr CData/*6:0*/ ExcCauseIrqSoftwareM = 0x23U;
    static constexpr CData/*6:0*/ ExcCauseIrqTimerM = 0x27U;
    static constexpr CData/*6:0*/ ExcCauseIrqExternalM = 0x2bU;
    static constexpr CData/*6:0*/ ExcCauseIrqNm = 0x3fU;
    static constexpr CData/*6:0*/ ExcCauseInsnAddrMisa = 0U;
    static constexpr CData/*6:0*/ ExcCauseInstrAccessFault = 1U;
    static constexpr CData/*6:0*/ ExcCauseIllegalInsn = 2U;
    static constexpr CData/*6:0*/ ExcCauseBreakpoint = 3U;
    static constexpr CData/*6:0*/ ExcCauseLoadAccessFault = 5U;
    static constexpr CData/*6:0*/ ExcCauseStoreAccessFault = 7U;
    static constexpr CData/*6:0*/ ExcCauseEcallUMode = 8U;
    static constexpr CData/*6:0*/ ExcCauseEcallMMode = 0x0bU;
    static constexpr CData/*1:0*/ CSR_MISA_MXL = 1U;
    static const VlWide<5>/*159:0*/ RndCnstLfsrPermDefault;
    static constexpr CData/*3:0*/ IbexMuBiOn = 5U;
    static constexpr CData/*3:0*/ IbexMuBiOff = 0x0aU;
    static constexpr CData/*2:0*/ PmpMseccfgRst = 0U;
    static constexpr SData/*11:0*/ CSR_OFF_PMP_CFG = 0x03a0U;
    static constexpr SData/*11:0*/ CSR_OFF_PMP_ADDR = 0x03b0U;
    static constexpr IData/*31:0*/ ADDR_W = 0x00000020U;
    static constexpr IData/*31:0*/ BUS_SIZE = 0x00000020U;
    static constexpr IData/*31:0*/ BUS_BYTES = 4U;
    static constexpr IData/*31:0*/ BUS_W = 2U;
    static constexpr IData/*31:0*/ IC_SIZE_BYTES = 0x00001000U;
    static constexpr IData/*31:0*/ IC_NUM_WAYS = 2U;
    static constexpr IData/*31:0*/ IC_LINE_SIZE = 0x00000040U;
    static constexpr IData/*31:0*/ IC_LINE_BYTES = 8U;
    static constexpr IData/*31:0*/ IC_LINE_W = 3U;
    static constexpr IData/*31:0*/ IC_NUM_LINES = 0x00000100U;
    static constexpr IData/*31:0*/ IC_LINE_BEATS = 2U;
    static constexpr IData/*31:0*/ IC_LINE_BEATS_W = 1U;
    static constexpr IData/*31:0*/ IC_INDEX_W = 8U;
    static constexpr IData/*31:0*/ IC_INDEX_HI = 0x0000000aU;
    static constexpr IData/*31:0*/ IC_TAG_SIZE = 0x00000016U;
    static constexpr IData/*31:0*/ IC_OUTPUT_BEATS = 2U;
    static constexpr IData/*31:0*/ SCRAMBLE_KEY_W = 0x00000080U;
    static constexpr IData/*31:0*/ SCRAMBLE_NONCE_W = 0x00000040U;
    static constexpr IData/*31:0*/ PMP_MAX_REGIONS = 0x00000010U;
    static constexpr IData/*31:0*/ PMP_CFG_W = 8U;
    static constexpr IData/*31:0*/ PMP_I = 0U;
    static constexpr IData/*31:0*/ PMP_I2 = 1U;
    static constexpr IData/*31:0*/ PMP_D = 2U;
    static constexpr IData/*31:0*/ CSR_MSTATUS_MIE_BIT = 3U;
    static constexpr IData/*31:0*/ CSR_MSTATUS_MPIE_BIT = 7U;
    static constexpr IData/*31:0*/ CSR_MSTATUS_MPP_BIT_LOW = 0x0000000bU;
    static constexpr IData/*31:0*/ CSR_MSTATUS_MPP_BIT_HIGH = 0x0000000cU;
    static constexpr IData/*31:0*/ CSR_MSTATUS_MPRV_BIT = 0x00000011U;
    static constexpr IData/*31:0*/ CSR_MSTATUS_TW_BIT = 0x00000015U;
    static constexpr IData/*31:0*/ CSR_MSIX_BIT = 3U;
    static constexpr IData/*31:0*/ CSR_MTIX_BIT = 7U;
    static constexpr IData/*31:0*/ CSR_MEIX_BIT = 0x0000000bU;
    static constexpr IData/*31:0*/ CSR_MFIX_BIT_LOW = 0x00000010U;
    static constexpr IData/*31:0*/ CSR_MFIX_BIT_HIGH = 0x0000001eU;
    static constexpr IData/*31:0*/ CSR_MSECCFG_MML_BIT = 0U;
    static constexpr IData/*31:0*/ CSR_MSECCFG_MMWP_BIT = 1U;
    static constexpr IData/*31:0*/ CSR_MSECCFG_RLB_BIT = 2U;
    static constexpr IData/*31:0*/ CSR_MARCHID_VALUE = 0x00000016U;
    static constexpr IData/*31:0*/ CSR_MCONFIGPTR_VALUE = 0U;
    static constexpr IData/*31:0*/ LfsrWidth = 0x00000020U;
    static constexpr IData/*31:0*/ RndCnstLfsrSeedDefault = 0xac533bf4U;
    static constexpr VlWide<4>/*127:0*/ RndCnstIbexKeyDefault = {{
        0xcc113298, 0x12286bb3, 0xe3040d5e, 0x14e8ceca
    }};
    static constexpr IData/*31:0*/ IbexMuBiWidth = 4U;
    static constexpr QData/*63:0*/ RndCnstIbexNonceDefault = 0xf79780bc735f3843ULL;
    static constexpr VlUnpacked<CData/*5:0*/, 16> PmpCfgRst = {{
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
    }};
    static constexpr VlUnpacked<QData/*33:0*/, 16> PmpAddrRst = {{
        0x0000000000000000ULL, 0x0000000000000000ULL,
        0x0000000000000000ULL, 0x0000000000000000ULL,
        0x0000000000000000ULL, 0x0000000000000000ULL,
        0x0000000000000000ULL, 0x0000000000000000ULL,
        0x0000000000000000ULL, 0x0000000000000000ULL,
        0x0000000000000000ULL, 0x0000000000000000ULL,
        0x0000000000000000ULL, 0x0000000000000000ULL,
        0x0000000000000000ULL, 0x0000000000000000ULL
    }};

    // CONSTRUCTORS
    Vtop_ibex_pkg(Vtop__Syms* symsp, const char* v__name);
    ~Vtop_ibex_pkg();
    VL_UNCOPYABLE(Vtop_ibex_pkg);

    // INTERNAL METHODS
    void __Vconfigure(bool first);
};


#endif  // guard
