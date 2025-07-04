// Verilated -*- C++ -*-
// DESCRIPTION: Verilator output: Design internal header
// See Vtop.h for the primary calling header

#ifndef VERILATED_VTOP_PRIM_RAM_1P_PKG_H_
#define VERILATED_VTOP_PRIM_RAM_1P_PKG_H_  // guard

#include "verilated.h"


class Vtop__Syms;

class alignas(VL_CACHE_LINE_BYTES) Vtop_prim_ram_1p_pkg final : public VerilatedModule {
  public:

    // INTERNAL VARIABLES
    Vtop__Syms* const vlSymsp;

    // PARAMETERS
    static constexpr SData/*9:0*/ RAM_1P_CFG_DEFAULT = 0U;

    // CONSTRUCTORS
    Vtop_prim_ram_1p_pkg(Vtop__Syms* symsp, const char* v__name);
    ~Vtop_prim_ram_1p_pkg();
    VL_UNCOPYABLE(Vtop_prim_ram_1p_pkg);

    // INTERNAL METHODS
    void __Vconfigure(bool first);
};


#endif  // guard
