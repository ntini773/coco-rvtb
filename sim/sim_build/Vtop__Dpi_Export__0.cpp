// Verilated -*- C++ -*-
// DESCRIPTION: Verilator output: Implementation of DPI export functions.
//
#include "Vtop.h"
#include "Vtop__Syms.h"
#include "verilated_dpi.h"


unsigned int Vtop::mhpmcounter_num() {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root::mhpmcounter_num\n"); );
    // Init
    IData/*31:0*/ mhpmcounter_num__Vfuncrtn__Vcvt;
    mhpmcounter_num__Vfuncrtn__Vcvt = 0;
    // Body
    static int __Vfuncnum = -1;
    if (VL_UNLIKELY(__Vfuncnum == -1)) __Vfuncnum = Verilated::exportFuncNum("mhpmcounter_num");
    const VerilatedScope* __Vscopep = Verilated::dpiScope();
    Vtop__Vcb_mhpmcounter_num_t __Vcb = (Vtop__Vcb_mhpmcounter_num_t)(VerilatedScope::exportFind(__Vscopep, __Vfuncnum));
    (*__Vcb)((Vtop__Syms*)(__Vscopep->symsp()), mhpmcounter_num__Vfuncrtn__Vcvt);
    unsigned int mhpmcounter_num__Vfuncrtn;
    for (size_t mhpmcounter_num__Vfuncrtn__Vidx = 0; mhpmcounter_num__Vfuncrtn__Vidx < 1; ++mhpmcounter_num__Vfuncrtn__Vidx) mhpmcounter_num__Vfuncrtn = mhpmcounter_num__Vfuncrtn__Vcvt;
    return mhpmcounter_num__Vfuncrtn;
}

unsigned long long Vtop::mhpmcounter_get(int index) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root::mhpmcounter_get\n"); );
    // Init
    IData/*31:0*/ index__Vcvt;
    index__Vcvt = 0;
    QData/*63:0*/ mhpmcounter_get__Vfuncrtn__Vcvt;
    mhpmcounter_get__Vfuncrtn__Vcvt = 0;
    // Body
    static int __Vfuncnum = -1;
    if (VL_UNLIKELY(__Vfuncnum == -1)) __Vfuncnum = Verilated::exportFuncNum("mhpmcounter_get");
    const VerilatedScope* __Vscopep = Verilated::dpiScope();
    Vtop__Vcb_mhpmcounter_get_t __Vcb = (Vtop__Vcb_mhpmcounter_get_t)(VerilatedScope::exportFind(__Vscopep, __Vfuncnum));
    index__Vcvt = index;
    (*__Vcb)((Vtop__Syms*)(__Vscopep->symsp()), index__Vcvt, mhpmcounter_get__Vfuncrtn__Vcvt);
    unsigned long long mhpmcounter_get__Vfuncrtn;
    for (size_t mhpmcounter_get__Vfuncrtn__Vidx = 0; mhpmcounter_get__Vfuncrtn__Vidx < 1; ++mhpmcounter_get__Vfuncrtn__Vidx) mhpmcounter_get__Vfuncrtn = mhpmcounter_get__Vfuncrtn__Vcvt;
    return mhpmcounter_get__Vfuncrtn;
}

int Vtop::simutil_get_scramble_key(svBitVecVal* val) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root::simutil_get_scramble_key\n"); );
    // Init
    VlWide<4>/*127:0*/ val__Vcvt;
    VL_ZERO_W(128, val__Vcvt);
    IData/*31:0*/ simutil_get_scramble_key__Vfuncrtn__Vcvt;
    simutil_get_scramble_key__Vfuncrtn__Vcvt = 0;
    // Body
    static int __Vfuncnum = -1;
    if (VL_UNLIKELY(__Vfuncnum == -1)) __Vfuncnum = Verilated::exportFuncNum("simutil_get_scramble_key");
    const VerilatedScope* __Vscopep = Verilated::dpiScope();
    Vtop__Vcb_simutil_get_scramble_key_t __Vcb = (Vtop__Vcb_simutil_get_scramble_key_t)(VerilatedScope::exportFind(__Vscopep, __Vfuncnum));
    (*__Vcb)((Vtop__Syms*)(__Vscopep->symsp()), val__Vcvt, simutil_get_scramble_key__Vfuncrtn__Vcvt);
    for (size_t val__Vidx = 0; val__Vidx < 1; ++val__Vidx) VL_SET_SVBV_W(128, val + 4 * val__Vidx, val__Vcvt);
    int simutil_get_scramble_key__Vfuncrtn;
    for (size_t simutil_get_scramble_key__Vfuncrtn__Vidx = 0; simutil_get_scramble_key__Vfuncrtn__Vidx < 1; ++simutil_get_scramble_key__Vfuncrtn__Vidx) simutil_get_scramble_key__Vfuncrtn = simutil_get_scramble_key__Vfuncrtn__Vcvt;
    return simutil_get_scramble_key__Vfuncrtn;
}

int Vtop::simutil_get_scramble_nonce(svBitVecVal* nonce) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root::simutil_get_scramble_nonce\n"); );
    // Init
    VlWide<10>/*319:0*/ nonce__Vcvt;
    VL_ZERO_W(320, nonce__Vcvt);
    IData/*31:0*/ simutil_get_scramble_nonce__Vfuncrtn__Vcvt;
    simutil_get_scramble_nonce__Vfuncrtn__Vcvt = 0;
    // Body
    static int __Vfuncnum = -1;
    if (VL_UNLIKELY(__Vfuncnum == -1)) __Vfuncnum = Verilated::exportFuncNum("simutil_get_scramble_nonce");
    const VerilatedScope* __Vscopep = Verilated::dpiScope();
    Vtop__Vcb_simutil_get_scramble_nonce_t __Vcb = (Vtop__Vcb_simutil_get_scramble_nonce_t)(VerilatedScope::exportFind(__Vscopep, __Vfuncnum));
    (*__Vcb)((Vtop__Syms*)(__Vscopep->symsp()), nonce__Vcvt, simutil_get_scramble_nonce__Vfuncrtn__Vcvt);
    for (size_t nonce__Vidx = 0; nonce__Vidx < 1; ++nonce__Vidx) VL_SET_SVBV_W(320, nonce + 10 * nonce__Vidx, nonce__Vcvt);
    int simutil_get_scramble_nonce__Vfuncrtn;
    for (size_t simutil_get_scramble_nonce__Vfuncrtn__Vidx = 0; simutil_get_scramble_nonce__Vfuncrtn__Vidx < 1; ++simutil_get_scramble_nonce__Vfuncrtn__Vidx) simutil_get_scramble_nonce__Vfuncrtn = simutil_get_scramble_nonce__Vfuncrtn__Vcvt;
    return simutil_get_scramble_nonce__Vfuncrtn;
}

void Vtop::simutil_memload(const char* file) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root::simutil_memload\n"); );
    // Init
    static thread_local std::string file__Vcvt;
    // Body
    static int __Vfuncnum = -1;
    if (VL_UNLIKELY(__Vfuncnum == -1)) __Vfuncnum = Verilated::exportFuncNum("simutil_memload");
    const VerilatedScope* __Vscopep = Verilated::dpiScope();
    Vtop__Vcb_simutil_memload_t __Vcb = (Vtop__Vcb_simutil_memload_t)(VerilatedScope::exportFind(__Vscopep, __Vfuncnum));
    file__Vcvt = VL_CVT_N_CSTR(file);
    (*__Vcb)((Vtop__Syms*)(__Vscopep->symsp()), file__Vcvt);
}

int Vtop::simutil_set_mem(int index, const svBitVecVal* val) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root::simutil_set_mem\n"); );
    // Init
    IData/*31:0*/ index__Vcvt;
    index__Vcvt = 0;
    VlWide<10>/*311:0*/ val__Vcvt;
    VL_ZERO_W(312, val__Vcvt);
    IData/*31:0*/ simutil_set_mem__Vfuncrtn__Vcvt;
    simutil_set_mem__Vfuncrtn__Vcvt = 0;
    // Body
    static int __Vfuncnum = -1;
    if (VL_UNLIKELY(__Vfuncnum == -1)) __Vfuncnum = Verilated::exportFuncNum("simutil_set_mem");
    const VerilatedScope* __Vscopep = Verilated::dpiScope();
    Vtop__Vcb_simutil_set_mem_t __Vcb = (Vtop__Vcb_simutil_set_mem_t)(VerilatedScope::exportFind(__Vscopep, __Vfuncnum));
    index__Vcvt = index;
    VL_SET_W_SVBV(312,val__Vcvt,val + 0);
(*__Vcb)((Vtop__Syms*)(__Vscopep->symsp()), index__Vcvt, val__Vcvt, simutil_set_mem__Vfuncrtn__Vcvt);
    int simutil_set_mem__Vfuncrtn;
    for (size_t simutil_set_mem__Vfuncrtn__Vidx = 0; simutil_set_mem__Vfuncrtn__Vidx < 1; ++simutil_set_mem__Vfuncrtn__Vidx) simutil_set_mem__Vfuncrtn = simutil_set_mem__Vfuncrtn__Vcvt;
    return simutil_set_mem__Vfuncrtn;
}

int Vtop::simutil_get_mem(int index, svBitVecVal* val) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root::simutil_get_mem\n"); );
    // Init
    IData/*31:0*/ index__Vcvt;
    index__Vcvt = 0;
    VlWide<10>/*311:0*/ val__Vcvt;
    VL_ZERO_W(312, val__Vcvt);
    IData/*31:0*/ simutil_get_mem__Vfuncrtn__Vcvt;
    simutil_get_mem__Vfuncrtn__Vcvt = 0;
    // Body
    static int __Vfuncnum = -1;
    if (VL_UNLIKELY(__Vfuncnum == -1)) __Vfuncnum = Verilated::exportFuncNum("simutil_get_mem");
    const VerilatedScope* __Vscopep = Verilated::dpiScope();
    Vtop__Vcb_simutil_get_mem_t __Vcb = (Vtop__Vcb_simutil_get_mem_t)(VerilatedScope::exportFind(__Vscopep, __Vfuncnum));
    index__Vcvt = index;
    (*__Vcb)((Vtop__Syms*)(__Vscopep->symsp()), index__Vcvt, val__Vcvt, simutil_get_mem__Vfuncrtn__Vcvt);
    for (size_t val__Vidx = 0; val__Vidx < 1; ++val__Vidx) VL_SET_SVBV_W(312, val + 10 * val__Vidx, val__Vcvt);
    int simutil_get_mem__Vfuncrtn;
    for (size_t simutil_get_mem__Vfuncrtn__Vidx = 0; simutil_get_mem__Vfuncrtn__Vidx < 1; ++simutil_get_mem__Vfuncrtn__Vidx) simutil_get_mem__Vfuncrtn = simutil_get_mem__Vfuncrtn__Vcvt;
    return simutil_get_mem__Vfuncrtn;
}
