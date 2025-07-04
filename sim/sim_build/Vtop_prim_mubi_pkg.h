// Verilated -*- C++ -*-
// DESCRIPTION: Verilator output: Design internal header
// See Vtop.h for the primary calling header

#ifndef VERILATED_VTOP_PRIM_MUBI_PKG_H_
#define VERILATED_VTOP_PRIM_MUBI_PKG_H_  // guard

#include "verilated.h"


class Vtop__Syms;

class alignas(VL_CACHE_LINE_BYTES) Vtop_prim_mubi_pkg final : public VerilatedModule {
  public:

    // INTERNAL VARIABLES
    Vtop__Syms* const vlSymsp;

    // PARAMETERS
    static constexpr IData/*31:0*/ MuBi4Width = 4U;
    static constexpr IData/*31:0*/ MuBi8Width = 8U;
    static constexpr IData/*31:0*/ MuBi12Width = 0x0000000cU;
    static constexpr IData/*31:0*/ MuBi16Width = 0x00000010U;
    static constexpr IData/*31:0*/ MuBi20Width = 0x00000014U;
    static constexpr IData/*31:0*/ MuBi24Width = 0x00000018U;
    static constexpr IData/*31:0*/ MuBi28Width = 0x0000001cU;
    static constexpr IData/*31:0*/ MuBi32Width = 0x00000020U;

    // CONSTRUCTORS
    Vtop_prim_mubi_pkg(Vtop__Syms* symsp, const char* v__name);
    ~Vtop_prim_mubi_pkg();
    VL_UNCOPYABLE(Vtop_prim_mubi_pkg);

    // INTERNAL METHODS
    void __Vconfigure(bool first);
};


#endif  // guard
