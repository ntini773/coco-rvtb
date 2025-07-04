// Verilated -*- C++ -*-
// DESCRIPTION: Verilator output: Design implementation internals
// See Vtop.h for the primary calling header

#include "Vtop__pch.h"
#include "Vtop__Syms.h"
#include "Vtop_prim_mubi_pkg.h"

// Parameter definitions for Vtop_prim_mubi_pkg
constexpr IData/*31:0*/ Vtop_prim_mubi_pkg::MuBi4Width;
constexpr IData/*31:0*/ Vtop_prim_mubi_pkg::MuBi8Width;
constexpr IData/*31:0*/ Vtop_prim_mubi_pkg::MuBi12Width;
constexpr IData/*31:0*/ Vtop_prim_mubi_pkg::MuBi16Width;
constexpr IData/*31:0*/ Vtop_prim_mubi_pkg::MuBi20Width;
constexpr IData/*31:0*/ Vtop_prim_mubi_pkg::MuBi24Width;
constexpr IData/*31:0*/ Vtop_prim_mubi_pkg::MuBi28Width;
constexpr IData/*31:0*/ Vtop_prim_mubi_pkg::MuBi32Width;


void Vtop_prim_mubi_pkg___ctor_var_reset(Vtop_prim_mubi_pkg* vlSelf);

Vtop_prim_mubi_pkg::Vtop_prim_mubi_pkg(Vtop__Syms* symsp, const char* v__name)
    : VerilatedModule{v__name}
    , vlSymsp{symsp}
 {
    // Reset structure values
    Vtop_prim_mubi_pkg___ctor_var_reset(this);
}

void Vtop_prim_mubi_pkg::__Vconfigure(bool first) {
    (void)first;  // Prevent unused variable warning
}

Vtop_prim_mubi_pkg::~Vtop_prim_mubi_pkg() {
}
