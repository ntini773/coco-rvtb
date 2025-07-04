// Verilated -*- C++ -*-
// DESCRIPTION: Verilator output: Design implementation internals
// See Vtop.h for the primary calling header

#include "Vtop__pch.h"
#include "Vtop__Syms.h"
#include "Vtop_prim_ram_1p_pkg.h"

// Parameter definitions for Vtop_prim_ram_1p_pkg
constexpr SData/*9:0*/ Vtop_prim_ram_1p_pkg::RAM_1P_CFG_DEFAULT;


void Vtop_prim_ram_1p_pkg___ctor_var_reset(Vtop_prim_ram_1p_pkg* vlSelf);

Vtop_prim_ram_1p_pkg::Vtop_prim_ram_1p_pkg(Vtop__Syms* symsp, const char* v__name)
    : VerilatedModule{v__name}
    , vlSymsp{symsp}
 {
    // Reset structure values
    Vtop_prim_ram_1p_pkg___ctor_var_reset(this);
}

void Vtop_prim_ram_1p_pkg::__Vconfigure(bool first) {
    (void)first;  // Prevent unused variable warning
}

Vtop_prim_ram_1p_pkg::~Vtop_prim_ram_1p_pkg() {
}
