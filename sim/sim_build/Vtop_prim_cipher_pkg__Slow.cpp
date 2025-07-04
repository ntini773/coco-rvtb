// Verilated -*- C++ -*-
// DESCRIPTION: Verilator output: Design implementation internals
// See Vtop.h for the primary calling header

#include "Vtop__pch.h"
#include "Vtop__Syms.h"
#include "Vtop_prim_cipher_pkg.h"

// Parameter definitions for Vtop_prim_cipher_pkg
const QData/*63:0*/ Vtop_prim_cipher_pkg::PRINCE_SBOX4 = 0x4d5e087619ca23fbULL;
const QData/*63:0*/ Vtop_prim_cipher_pkg::PRINCE_SBOX4_INV = 0x1ce5046a98df237bULL;
const QData/*63:0*/ Vtop_prim_cipher_pkg::PRINCE_SHIFT_ROWS64 = 0xfa50b61c72d83e94ULL;
const QData/*63:0*/ Vtop_prim_cipher_pkg::PRINCE_SHIFT_ROWS64_INV = 0xf258be147ad0369cULL;
const QData/*63:0*/ Vtop_prim_cipher_pkg::PRESENT_SBOX4 = 0x21748fe3da09b65cULL;
const QData/*63:0*/ Vtop_prim_cipher_pkg::PRESENT_SBOX4_INV = 0xa970364bd21c8fe5ULL;
const VlWide<5>/*159:0*/ Vtop_prim_cipher_pkg::PRESENT_PERM32 = {{
    0x521c4100, 0x3d4942cc, 0x5184dcd6, 0xc6ed5a5e,
    0xfdde7f59
}};
const VlWide<5>/*159:0*/ Vtop_prim_cipher_pkg::PRESENT_PERM32_INV = {{
    0x29062080, 0x16a4a1e6, 0x28c2ee6b, 0xe3f6ad27,
    0xfeef37ac
}};
const VlWide<12>/*383:0*/ Vtop_prim_cipher_pkg::PRESENT_PERM64 = {{
    0x41c20400, 0x2482c614, 0xce34c3ca, 0x45d24504,
    0x6586d655, 0xde75c7da, 0x49e28608, 0xa68ae696,
    0xeeb6cbea, 0x4df2c70c, 0xe78ef6d7, 0xfef7cffa
}};
const VlWide<12>/*383:0*/ Vtop_prim_cipher_pkg::PRESENT_PERM64_INV = {{
    0x10308100, 0x89207185, 0xf38d30b2, 0x51349141,
    0x99617595, 0xf79d71b6, 0x9238a182, 0xa9a279a5,
    0xfbadb2ba, 0xd33cb1c3, 0xb9e37db5, 0xffbdf3be
}};
constexpr SData/*15:0*/ Vtop_prim_cipher_pkg::PRINCE_SHIFT_ROWS_CONST0;
constexpr SData/*15:0*/ Vtop_prim_cipher_pkg::PRINCE_SHIFT_ROWS_CONST1;
constexpr SData/*15:0*/ Vtop_prim_cipher_pkg::PRINCE_SHIFT_ROWS_CONST2;
constexpr SData/*15:0*/ Vtop_prim_cipher_pkg::PRINCE_SHIFT_ROWS_CONST3;
const VlWide<24>/*767:0*/ Vtop_prim_cipher_pkg::PRINCE_ROUND_CONST = {{
    0x00000000, 0x00000000, 0x03707344, 0x13198a2e,
    0x299f31d0, 0xa4093822, 0xec4e6c89, 0x082efa98,
    0x38d01377, 0x452821e6, 0x34e90c6c, 0xbe5466cf,
    0xfd955cb1, 0x7ef84f78, 0xf1ac43aa, 0x85840851,
    0x25323c54, 0xc882d32f, 0xe0e3610d, 0x64a51195,
    0xca0c2399, 0xd3b5a399, 0xc97c50dd, 0xc0ac29b7
}};
constexpr QData/*63:0*/ Vtop_prim_cipher_pkg::PRINCE_ALPHA_CONST;


void Vtop_prim_cipher_pkg___ctor_var_reset(Vtop_prim_cipher_pkg* vlSelf);

Vtop_prim_cipher_pkg::Vtop_prim_cipher_pkg(Vtop__Syms* symsp, const char* v__name)
    : VerilatedModule{v__name}
    , vlSymsp{symsp}
 {
    // Reset structure values
    Vtop_prim_cipher_pkg___ctor_var_reset(this);
}

void Vtop_prim_cipher_pkg::__Vconfigure(bool first) {
    (void)first;  // Prevent unused variable warning
}

Vtop_prim_cipher_pkg::~Vtop_prim_cipher_pkg() {
}
