// Verilated -*- C++ -*-
// DESCRIPTION: Verilator output: Design internal header
// See Vtop.h for the primary calling header

#ifndef VERILATED_VTOP_PRIM_CIPHER_PKG_H_
#define VERILATED_VTOP_PRIM_CIPHER_PKG_H_  // guard

#include "verilated.h"


class Vtop__Syms;

class alignas(VL_CACHE_LINE_BYTES) Vtop_prim_cipher_pkg final : public VerilatedModule {
  public:

    // INTERNAL VARIABLES
    Vtop__Syms* const vlSymsp;

    // PARAMETERS
    static const QData/*63:0*/ PRINCE_SBOX4;
    static const QData/*63:0*/ PRINCE_SBOX4_INV;
    static const QData/*63:0*/ PRINCE_SHIFT_ROWS64;
    static const QData/*63:0*/ PRINCE_SHIFT_ROWS64_INV;
    static const QData/*63:0*/ PRESENT_SBOX4;
    static const QData/*63:0*/ PRESENT_SBOX4_INV;
    static const VlWide<5>/*159:0*/ PRESENT_PERM32;
    static const VlWide<5>/*159:0*/ PRESENT_PERM32_INV;
    static const VlWide<12>/*383:0*/ PRESENT_PERM64;
    static const VlWide<12>/*383:0*/ PRESENT_PERM64_INV;
    static constexpr SData/*15:0*/ PRINCE_SHIFT_ROWS_CONST0 = 0x7bdeU;
    static constexpr SData/*15:0*/ PRINCE_SHIFT_ROWS_CONST1 = 0xbde7U;
    static constexpr SData/*15:0*/ PRINCE_SHIFT_ROWS_CONST2 = 0xde7bU;
    static constexpr SData/*15:0*/ PRINCE_SHIFT_ROWS_CONST3 = 0xe7bdU;
    static const VlWide<24>/*767:0*/ PRINCE_ROUND_CONST;
    static constexpr QData/*63:0*/ PRINCE_ALPHA_CONST = 0xc0ac29b7c97c50ddULL;

    // CONSTRUCTORS
    Vtop_prim_cipher_pkg(Vtop__Syms* symsp, const char* v__name);
    ~Vtop_prim_cipher_pkg();
    VL_UNCOPYABLE(Vtop_prim_cipher_pkg);

    // INTERNAL METHODS
    void __Vconfigure(bool first);
};


#endif  // guard
