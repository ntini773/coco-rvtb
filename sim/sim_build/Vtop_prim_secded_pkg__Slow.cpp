// Verilated -*- C++ -*-
// DESCRIPTION: Verilator output: Design implementation internals
// See Vtop.h for the primary calling header

#include "Vtop__pch.h"
#include "Vtop__Syms.h"
#include "Vtop_prim_secded_pkg.h"

// Parameter definitions for Vtop_prim_secded_pkg
constexpr CData/*5:0*/ Vtop_prim_secded_pkg::Secded2216ZeroEcc;
constexpr CData/*5:0*/ Vtop_prim_secded_pkg::Secded2822ZeroEcc;
constexpr CData/*6:0*/ Vtop_prim_secded_pkg::Secded3932ZeroEcc;
constexpr CData/*6:0*/ Vtop_prim_secded_pkg::Secded6457ZeroEcc;
constexpr CData/*7:0*/ Vtop_prim_secded_pkg::Secded7264ZeroEcc;
constexpr CData/*5:0*/ Vtop_prim_secded_pkg::SecdedHamming2216ZeroEcc;
constexpr CData/*6:0*/ Vtop_prim_secded_pkg::SecdedHamming3932ZeroEcc;
constexpr CData/*7:0*/ Vtop_prim_secded_pkg::SecdedHamming7264ZeroEcc;
constexpr CData/*7:0*/ Vtop_prim_secded_pkg::SecdedHamming7668ZeroEcc;
constexpr CData/*5:0*/ Vtop_prim_secded_pkg::SecdedInv2216ZeroEcc;
constexpr CData/*5:0*/ Vtop_prim_secded_pkg::SecdedInv2822ZeroEcc;
constexpr CData/*6:0*/ Vtop_prim_secded_pkg::SecdedInv3932ZeroEcc;
constexpr CData/*6:0*/ Vtop_prim_secded_pkg::SecdedInv6457ZeroEcc;
constexpr CData/*7:0*/ Vtop_prim_secded_pkg::SecdedInv7264ZeroEcc;
constexpr CData/*5:0*/ Vtop_prim_secded_pkg::SecdedInvHamming2216ZeroEcc;
constexpr CData/*6:0*/ Vtop_prim_secded_pkg::SecdedInvHamming3932ZeroEcc;
constexpr CData/*7:0*/ Vtop_prim_secded_pkg::SecdedInvHamming7264ZeroEcc;
constexpr CData/*7:0*/ Vtop_prim_secded_pkg::SecdedInvHamming7668ZeroEcc;
constexpr IData/*21:0*/ Vtop_prim_secded_pkg::Secded2216ZeroWord;
constexpr IData/*27:0*/ Vtop_prim_secded_pkg::Secded2822ZeroWord;
constexpr VlWide<3>/*71:0*/ Vtop_prim_secded_pkg::Secded7264ZeroWord;
constexpr IData/*21:0*/ Vtop_prim_secded_pkg::SecdedHamming2216ZeroWord;
constexpr VlWide<3>/*71:0*/ Vtop_prim_secded_pkg::SecdedHamming7264ZeroWord;
constexpr VlWide<3>/*75:0*/ Vtop_prim_secded_pkg::SecdedHamming7668ZeroWord;
constexpr IData/*21:0*/ Vtop_prim_secded_pkg::SecdedInv2216ZeroWord;
constexpr IData/*27:0*/ Vtop_prim_secded_pkg::SecdedInv2822ZeroWord;
constexpr VlWide<3>/*71:0*/ Vtop_prim_secded_pkg::SecdedInv7264ZeroWord;
constexpr IData/*21:0*/ Vtop_prim_secded_pkg::SecdedInvHamming2216ZeroWord;
constexpr VlWide<3>/*71:0*/ Vtop_prim_secded_pkg::SecdedInvHamming7264ZeroWord;
constexpr VlWide<3>/*75:0*/ Vtop_prim_secded_pkg::SecdedInvHamming7668ZeroWord;
constexpr QData/*38:0*/ Vtop_prim_secded_pkg::Secded3932ZeroWord;
constexpr QData/*63:0*/ Vtop_prim_secded_pkg::Secded6457ZeroWord;
constexpr QData/*38:0*/ Vtop_prim_secded_pkg::SecdedHamming3932ZeroWord;
constexpr QData/*38:0*/ Vtop_prim_secded_pkg::SecdedInv3932ZeroWord;
constexpr QData/*63:0*/ Vtop_prim_secded_pkg::SecdedInv6457ZeroWord;
constexpr QData/*38:0*/ Vtop_prim_secded_pkg::SecdedInvHamming3932ZeroWord;


void Vtop_prim_secded_pkg___ctor_var_reset(Vtop_prim_secded_pkg* vlSelf);

Vtop_prim_secded_pkg::Vtop_prim_secded_pkg(Vtop__Syms* symsp, const char* v__name)
    : VerilatedModule{v__name}
    , vlSymsp{symsp}
 {
    // Reset structure values
    Vtop_prim_secded_pkg___ctor_var_reset(this);
}

void Vtop_prim_secded_pkg::__Vconfigure(bool first) {
    (void)first;  // Prevent unused variable warning
}

Vtop_prim_secded_pkg::~Vtop_prim_secded_pkg() {
}
