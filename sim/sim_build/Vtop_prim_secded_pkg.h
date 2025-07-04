// Verilated -*- C++ -*-
// DESCRIPTION: Verilator output: Design internal header
// See Vtop.h for the primary calling header

#ifndef VERILATED_VTOP_PRIM_SECDED_PKG_H_
#define VERILATED_VTOP_PRIM_SECDED_PKG_H_  // guard

#include "verilated.h"


class Vtop__Syms;

class alignas(VL_CACHE_LINE_BYTES) Vtop_prim_secded_pkg final : public VerilatedModule {
  public:

    // INTERNAL VARIABLES
    Vtop__Syms* const vlSymsp;

    // PARAMETERS
    static constexpr CData/*5:0*/ Secded2216ZeroEcc = 0U;
    static constexpr CData/*5:0*/ Secded2822ZeroEcc = 0U;
    static constexpr CData/*6:0*/ Secded3932ZeroEcc = 0U;
    static constexpr CData/*6:0*/ Secded6457ZeroEcc = 0U;
    static constexpr CData/*7:0*/ Secded7264ZeroEcc = 0U;
    static constexpr CData/*5:0*/ SecdedHamming2216ZeroEcc = 0U;
    static constexpr CData/*6:0*/ SecdedHamming3932ZeroEcc = 0U;
    static constexpr CData/*7:0*/ SecdedHamming7264ZeroEcc = 0U;
    static constexpr CData/*7:0*/ SecdedHamming7668ZeroEcc = 0U;
    static constexpr CData/*5:0*/ SecdedInv2216ZeroEcc = 0x2aU;
    static constexpr CData/*5:0*/ SecdedInv2822ZeroEcc = 0x2aU;
    static constexpr CData/*6:0*/ SecdedInv3932ZeroEcc = 0x2aU;
    static constexpr CData/*6:0*/ SecdedInv6457ZeroEcc = 0x2aU;
    static constexpr CData/*7:0*/ SecdedInv7264ZeroEcc = 0xaaU;
    static constexpr CData/*5:0*/ SecdedInvHamming2216ZeroEcc = 0x2aU;
    static constexpr CData/*6:0*/ SecdedInvHamming3932ZeroEcc = 0x2aU;
    static constexpr CData/*7:0*/ SecdedInvHamming7264ZeroEcc = 0xaaU;
    static constexpr CData/*7:0*/ SecdedInvHamming7668ZeroEcc = 0xaaU;
    static constexpr IData/*21:0*/ Secded2216ZeroWord = 0U;
    static constexpr IData/*27:0*/ Secded2822ZeroWord = 0U;
    static constexpr VlWide<3>/*71:0*/ Secded7264ZeroWord = {{
        0x00000000, 0x00000000, 0x00000000
    }};
    static constexpr IData/*21:0*/ SecdedHamming2216ZeroWord = 0U;
    static constexpr VlWide<3>/*71:0*/ SecdedHamming7264ZeroWord = {{
        0x00000000, 0x00000000, 0x00000000
    }};
    static constexpr VlWide<3>/*75:0*/ SecdedHamming7668ZeroWord = {{
        0x00000000, 0x00000000, 0x00000000
    }};
    static constexpr IData/*21:0*/ SecdedInv2216ZeroWord = 0x002a0000U;
    static constexpr IData/*27:0*/ SecdedInv2822ZeroWord = 0x0a800000U;
    static constexpr VlWide<3>/*71:0*/ SecdedInv7264ZeroWord = {{
        0x00000000, 0x00000000, 0x000000aa
    }};
    static constexpr IData/*21:0*/ SecdedInvHamming2216ZeroWord = 0x002a0000U;
    static constexpr VlWide<3>/*71:0*/ SecdedInvHamming7264ZeroWord = {{
        0x00000000, 0x00000000, 0x000000aa
    }};
    static constexpr VlWide<3>/*75:0*/ SecdedInvHamming7668ZeroWord = {{
        0x00000000, 0x00000000, 0x00000aa0
    }};
    static constexpr QData/*38:0*/ Secded3932ZeroWord = 0ULL;
    static constexpr QData/*63:0*/ Secded6457ZeroWord = 0ULL;
    static constexpr QData/*38:0*/ SecdedHamming3932ZeroWord = 0ULL;
    static constexpr QData/*38:0*/ SecdedInv3932ZeroWord = 0x0000002a00000000ULL;
    static constexpr QData/*63:0*/ SecdedInv6457ZeroWord = 0x5400000000000000ULL;
    static constexpr QData/*38:0*/ SecdedInvHamming3932ZeroWord = 0x0000002a00000000ULL;

    // CONSTRUCTORS
    Vtop_prim_secded_pkg(Vtop__Syms* symsp, const char* v__name);
    ~Vtop_prim_secded_pkg();
    VL_UNCOPYABLE(Vtop_prim_secded_pkg);

    // INTERNAL METHODS
    void __Vconfigure(bool first);
};


#endif  // guard
