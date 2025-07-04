// Verilated -*- C++ -*-
// DESCRIPTION: Verilator output: Design internal header
// See Vtop.h for the primary calling header

#ifndef VERILATED_VTOP_PRIM_RAM_2P_PKG_H_
#define VERILATED_VTOP_PRIM_RAM_2P_PKG_H_  // guard

#include "verilated.h"


class Vtop__Syms;

class alignas(VL_CACHE_LINE_BYTES) Vtop_prim_ram_2p_pkg final : public VerilatedModule {
  public:

    // INTERNAL VARIABLES
    Vtop__Syms* const vlSymsp;

    // PARAMETERS
    static constexpr IData/*19:0*/ RAM_2P_CFG_DEFAULT = 0U;

    // CONSTRUCTORS
    Vtop_prim_ram_2p_pkg(Vtop__Syms* symsp, const char* v__name);
    ~Vtop_prim_ram_2p_pkg();
    VL_UNCOPYABLE(Vtop_prim_ram_2p_pkg);

    // INTERNAL METHODS
    void __Vconfigure(bool first);
};


#endif  // guard
