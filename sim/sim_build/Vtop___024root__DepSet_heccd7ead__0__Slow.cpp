// Verilated -*- C++ -*-
// DESCRIPTION: Verilator output: Design implementation internals
// See Vtop.h for the primary calling header

#include "Vtop__pch.h"
#include "Vtop___024root.h"

VL_ATTR_COLD void Vtop___024root___eval_static__TOP(Vtop___024root* vlSelf);

VL_ATTR_COLD void Vtop___024root___eval_static(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___eval_static\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Body
    Vtop___024root___eval_static__TOP(vlSelf);
}

VL_ATTR_COLD void Vtop___024root___eval_static__TOP(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___eval_static__TOP\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Body
    vlSelfRef.ibex_simple_system__DOT__clk_sys = 0U;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_noscramble__DOT__unused_scramble_inputs = 0U;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__unused_rvfi_order 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_order;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__unused_rvfi_trap 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_trap;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__unused_rvfi_halt 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_halt;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__unused_rvfi_intr 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_intr;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__unused_rvfi_mode 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_mode;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__unused_rvfi_ixl 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ixl;
}

VL_ATTR_COLD void Vtop___024root___eval_initial__TOP(Vtop___024root* vlSelf);

VL_ATTR_COLD void Vtop___024root___eval_initial(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___eval_initial\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Body
    Vtop___024root___eval_initial__TOP(vlSelf);
    vlSelfRef.__Vtrigprevexpr___TOP__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_executing_spec__0 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_executing_spec;
    vlSelfRef.__Vtrigprevexpr___TOP__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__en_wb__0 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__en_wb;
    vlSelfRef.__Vtrigprevexpr___TOP__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__id_in_ready_o__0 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__id_in_ready_o;
    vlSelfRef.__Vtrigprevexpr___TOP__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_executing_spec__1 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_executing_spec;
    vlSelfRef.__Vtrigprevexpr___TOP__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__en_wb__1 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__en_wb;
    vlSelfRef.__Vtrigprevexpr___TOP__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__id_in_ready_o__1 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__id_in_ready_o;
    vlSelfRef.__Vtrigprevexpr___TOP__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_executing_spec__2 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_executing_spec;
    vlSelfRef.__Vtrigprevexpr___TOP__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__en_wb__2 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__en_wb;
    vlSelfRef.__Vtrigprevexpr___TOP__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__id_in_ready_o__2 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__id_in_ready_o;
    vlSelfRef.__Vtrigprevexpr___TOP__ibex_simple_system__DOT__clk_sys__0 
        = vlSelfRef.ibex_simple_system__DOT__clk_sys;
    vlSelfRef.__Vtrigprevexpr___TOP__ibex_simple_system__DOT__rst_sys_n__0 
        = vlSelfRef.ibex_simple_system__DOT__rst_sys_n;
    vlSelfRef.__Vtrigprevexpr___TOP__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__clk__0 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__clk;
}

VL_ATTR_COLD void Vtop___024root___eval_final__TOP(Vtop___024root* vlSelf);

VL_ATTR_COLD void Vtop___024root___eval_final(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___eval_final\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Body
    Vtop___024root___eval_final__TOP(vlSelf);
}

VL_ATTR_COLD void Vtop___024root___eval_final__TOP(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___eval_final__TOP\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Body
    if (VL_UNLIKELY(((0U != vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__file_handle)))) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__unnamedblk1__DOT__fh 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__file_handle;
        VL_FCLOSE_I(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__unnamedblk1__DOT__fh); }
    VL_FCLOSE_I(vlSelfRef.ibex_simple_system__DOT__u_simulator_ctrl__DOT__log_fd); }

#ifdef VL_DEBUG
VL_ATTR_COLD void Vtop___024root___dump_triggers__stl(Vtop___024root* vlSelf);
#endif  // VL_DEBUG
VL_ATTR_COLD bool Vtop___024root___eval_phase__stl(Vtop___024root* vlSelf);

VL_ATTR_COLD void Vtop___024root___eval_settle(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___eval_settle\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Init
    IData/*31:0*/ __VstlIterCount;
    CData/*0:0*/ __VstlContinue;
    // Body
    __VstlIterCount = 0U;
    vlSelfRef.__VstlFirstIteration = 1U;
    __VstlContinue = 1U;
    while (__VstlContinue) {
        if (VL_UNLIKELY(((0x64U < __VstlIterCount)))) {
#ifdef VL_DEBUG
            Vtop___024root___dump_triggers__stl(vlSelf);
#endif
            VL_FATAL_MT("../ibex/examples/simple_system/rtl/ibex_simple_system.sv", 33, "", "Settle region did not converge.");
        }
        __VstlIterCount = ((IData)(1U) + __VstlIterCount);
        __VstlContinue = 0U;
        if (Vtop___024root___eval_phase__stl(vlSelf)) {
            __VstlContinue = 1U;
        }
        vlSelfRef.__VstlFirstIteration = 0U;
    }
}

#ifdef VL_DEBUG
VL_ATTR_COLD void Vtop___024root___dump_triggers__stl(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___dump_triggers__stl\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Body
    if ((1U & (~ vlSelfRef.__VstlTriggered.any()))) {
        VL_DBG_MSGF("         No triggers active\n");
    }
    if ((1ULL & vlSelfRef.__VstlTriggered.word(0U))) {
        VL_DBG_MSGF("         'stl' region trigger index 0 is active: Internal 'stl' trigger - first iteration\n");
    }
    if ((2ULL & vlSelfRef.__VstlTriggered.word(0U))) {
        VL_DBG_MSGF("         'stl' region trigger index 1 is active: @([hybrid] ibex_simple_system.u_top.u_ibex_top.u_ibex_core.id_stage_i.instr_executing_spec)\n");
    }
    if ((4ULL & vlSelfRef.__VstlTriggered.word(0U))) {
        VL_DBG_MSGF("         'stl' region trigger index 2 is active: @([hybrid] ibex_simple_system.u_top.u_ibex_top.u_ibex_core.en_wb)\n");
    }
    if ((8ULL & vlSelfRef.__VstlTriggered.word(0U))) {
        VL_DBG_MSGF("         'stl' region trigger index 3 is active: @([hybrid] ibex_simple_system.u_top.u_ibex_top.u_ibex_core.id_stage_i.controller_i.id_in_ready_o)\n");
    }
}
#endif  // VL_DEBUG

VL_ATTR_COLD void Vtop___024root___stl_sequent__TOP__0(Vtop___024root* vlSelf);
void Vtop___024root___ico_sequent__TOP__1(Vtop___024root* vlSelf);
void Vtop___024root___ico_comb__TOP__0(Vtop___024root* vlSelf);
void Vtop___024root___ico_comb__TOP__1(Vtop___024root* vlSelf);
void Vtop___024root___ico_comb__TOP__2(Vtop___024root* vlSelf);

VL_ATTR_COLD void Vtop___024root___eval_stl(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___eval_stl\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Body
    if ((1ULL & vlSelfRef.__VstlTriggered.word(0U))) {
        Vtop___024root___stl_sequent__TOP__0(vlSelf);
        Vtop___024root___ico_sequent__TOP__1(vlSelf);
    }
    if ((7ULL & vlSelfRef.__VstlTriggered.word(0U))) {
        Vtop___024root___ico_comb__TOP__0(vlSelf);
    }
    if ((3ULL & vlSelfRef.__VstlTriggered.word(0U))) {
        Vtop___024root___ico_comb__TOP__1(vlSelf);
    }
    if ((0xfULL & vlSelfRef.__VstlTriggered.word(0U))) {
        Vtop___024root___ico_comb__TOP__2(vlSelf);
    }
}

VL_ATTR_COLD void Vtop___024root___eval_triggers__stl(Vtop___024root* vlSelf);

VL_ATTR_COLD bool Vtop___024root___eval_phase__stl(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___eval_phase__stl\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Init
    CData/*0:0*/ __VstlExecute;
    // Body
    Vtop___024root___eval_triggers__stl(vlSelf);
    __VstlExecute = vlSelfRef.__VstlTriggered.any();
    if (__VstlExecute) {
        Vtop___024root___eval_stl(vlSelf);
    }
    return (__VstlExecute);
}

#ifdef VL_DEBUG
VL_ATTR_COLD void Vtop___024root___dump_triggers__ico(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___dump_triggers__ico\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Body
    if ((1U & (~ vlSelfRef.__VicoTriggered.any()))) {
        VL_DBG_MSGF("         No triggers active\n");
    }
    if ((1ULL & vlSelfRef.__VicoTriggered.word(0U))) {
        VL_DBG_MSGF("         'ico' region trigger index 0 is active: Internal 'ico' trigger - first iteration\n");
    }
    if ((2ULL & vlSelfRef.__VicoTriggered.word(0U))) {
        VL_DBG_MSGF("         'ico' region trigger index 1 is active: Internal 'ico' trigger - DPI export trigger\n");
    }
    if ((4ULL & vlSelfRef.__VicoTriggered.word(0U))) {
        VL_DBG_MSGF("         'ico' region trigger index 2 is active: @([hybrid] ibex_simple_system.u_top.u_ibex_top.u_ibex_core.id_stage_i.instr_executing_spec)\n");
    }
    if ((8ULL & vlSelfRef.__VicoTriggered.word(0U))) {
        VL_DBG_MSGF("         'ico' region trigger index 3 is active: @([hybrid] ibex_simple_system.u_top.u_ibex_top.u_ibex_core.en_wb)\n");
    }
    if ((0x10ULL & vlSelfRef.__VicoTriggered.word(0U))) {
        VL_DBG_MSGF("         'ico' region trigger index 4 is active: @([hybrid] ibex_simple_system.u_top.u_ibex_top.u_ibex_core.id_stage_i.controller_i.id_in_ready_o)\n");
    }
}
#endif  // VL_DEBUG

#ifdef VL_DEBUG
VL_ATTR_COLD void Vtop___024root___dump_triggers__act(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___dump_triggers__act\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Body
    if ((1U & (~ vlSelfRef.__VactTriggered.any()))) {
        VL_DBG_MSGF("         No triggers active\n");
    }
    if ((1ULL & vlSelfRef.__VactTriggered.word(0U))) {
        VL_DBG_MSGF("         'act' region trigger index 0 is active: Internal 'act' trigger - DPI export trigger\n");
    }
    if ((2ULL & vlSelfRef.__VactTriggered.word(0U))) {
        VL_DBG_MSGF("         'act' region trigger index 1 is active: @([hybrid] ibex_simple_system.u_top.u_ibex_top.u_ibex_core.id_stage_i.instr_executing_spec)\n");
    }
    if ((4ULL & vlSelfRef.__VactTriggered.word(0U))) {
        VL_DBG_MSGF("         'act' region trigger index 2 is active: @([hybrid] ibex_simple_system.u_top.u_ibex_top.u_ibex_core.en_wb)\n");
    }
    if ((8ULL & vlSelfRef.__VactTriggered.word(0U))) {
        VL_DBG_MSGF("         'act' region trigger index 3 is active: @([hybrid] ibex_simple_system.u_top.u_ibex_top.u_ibex_core.id_stage_i.controller_i.id_in_ready_o)\n");
    }
    if ((0x10ULL & vlSelfRef.__VactTriggered.word(0U))) {
        VL_DBG_MSGF("         'act' region trigger index 4 is active: @(posedge ibex_simple_system.clk_sys)\n");
    }
    if ((0x20ULL & vlSelfRef.__VactTriggered.word(0U))) {
        VL_DBG_MSGF("         'act' region trigger index 5 is active: @(negedge ibex_simple_system.rst_sys_n)\n");
    }
    if ((0x40ULL & vlSelfRef.__VactTriggered.word(0U))) {
        VL_DBG_MSGF("         'act' region trigger index 6 is active: @(posedge ibex_simple_system.u_top.u_ibex_top.clk)\n");
    }
    if ((0x80ULL & vlSelfRef.__VactTriggered.word(0U))) {
        VL_DBG_MSGF("         'act' region trigger index 7 is active: @(negedge ibex_simple_system.u_top.u_ibex_top.clk)\n");
    }
}
#endif  // VL_DEBUG

#ifdef VL_DEBUG
VL_ATTR_COLD void Vtop___024root___dump_triggers__nba(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___dump_triggers__nba\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Body
    if ((1U & (~ vlSelfRef.__VnbaTriggered.any()))) {
        VL_DBG_MSGF("         No triggers active\n");
    }
    if ((1ULL & vlSelfRef.__VnbaTriggered.word(0U))) {
        VL_DBG_MSGF("         'nba' region trigger index 0 is active: Internal 'nba' trigger - DPI export trigger\n");
    }
    if ((2ULL & vlSelfRef.__VnbaTriggered.word(0U))) {
        VL_DBG_MSGF("         'nba' region trigger index 1 is active: @([hybrid] ibex_simple_system.u_top.u_ibex_top.u_ibex_core.id_stage_i.instr_executing_spec)\n");
    }
    if ((4ULL & vlSelfRef.__VnbaTriggered.word(0U))) {
        VL_DBG_MSGF("         'nba' region trigger index 2 is active: @([hybrid] ibex_simple_system.u_top.u_ibex_top.u_ibex_core.en_wb)\n");
    }
    if ((8ULL & vlSelfRef.__VnbaTriggered.word(0U))) {
        VL_DBG_MSGF("         'nba' region trigger index 3 is active: @([hybrid] ibex_simple_system.u_top.u_ibex_top.u_ibex_core.id_stage_i.controller_i.id_in_ready_o)\n");
    }
    if ((0x10ULL & vlSelfRef.__VnbaTriggered.word(0U))) {
        VL_DBG_MSGF("         'nba' region trigger index 4 is active: @(posedge ibex_simple_system.clk_sys)\n");
    }
    if ((0x20ULL & vlSelfRef.__VnbaTriggered.word(0U))) {
        VL_DBG_MSGF("         'nba' region trigger index 5 is active: @(negedge ibex_simple_system.rst_sys_n)\n");
    }
    if ((0x40ULL & vlSelfRef.__VnbaTriggered.word(0U))) {
        VL_DBG_MSGF("         'nba' region trigger index 6 is active: @(posedge ibex_simple_system.u_top.u_ibex_top.clk)\n");
    }
    if ((0x80ULL & vlSelfRef.__VnbaTriggered.word(0U))) {
        VL_DBG_MSGF("         'nba' region trigger index 7 is active: @(negedge ibex_simple_system.u_top.u_ibex_top.clk)\n");
    }
}
#endif  // VL_DEBUG

VL_ATTR_COLD void Vtop___024root___ctor_var_reset(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___ctor_var_reset\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Body
    vlSelf->IO_CLK = VL_RAND_RESET_I(1);
    vlSelf->IO_RST_N = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__IO_CLK = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__IO_RST_N = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__clk_sys = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__rst_sys_n = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__timer_irq = VL_RAND_RESET_I(1);
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__host_req[__Vi0] = VL_RAND_RESET_I(1);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__host_gnt[__Vi0] = VL_RAND_RESET_I(1);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__host_addr[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__host_we[__Vi0] = VL_RAND_RESET_I(1);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__host_be[__Vi0] = VL_RAND_RESET_I(4);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__host_wdata[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__host_rvalid[__Vi0] = VL_RAND_RESET_I(1);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__host_rdata[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__host_err[__Vi0] = VL_RAND_RESET_I(1);
    }
    vlSelf->ibex_simple_system__DOT__data_rdata_intg = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__instr_rdata_intg = VL_RAND_RESET_I(7);
    for (int __Vi0 = 0; __Vi0 < 3; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__device_req[__Vi0] = VL_RAND_RESET_I(1);
    }
    for (int __Vi0 = 0; __Vi0 < 3; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__device_addr[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 3; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__device_we[__Vi0] = VL_RAND_RESET_I(1);
    }
    for (int __Vi0 = 0; __Vi0 < 3; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__device_be[__Vi0] = VL_RAND_RESET_I(4);
    }
    for (int __Vi0 = 0; __Vi0 < 3; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__device_wdata[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 3; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__device_rvalid[__Vi0] = VL_RAND_RESET_I(1);
    }
    for (int __Vi0 = 0; __Vi0 < 3; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__device_rdata[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 3; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__device_err[__Vi0] = VL_RAND_RESET_I(1);
    }
    for (int __Vi0 = 0; __Vi0 < 3; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__cfg_device_addr_base[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 3; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__cfg_device_addr_mask[__Vi0] = VL_RAND_RESET_I(32);
    }
    vlSelf->ibex_simple_system__DOT__instr_req = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__instr_gnt = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__instr_rvalid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__instr_addr = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__instr_rdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__instr_err = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_bus__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_bus__DOT__rst_ni = VL_RAND_RESET_I(1);
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_bus__DOT__host_req_i[__Vi0] = VL_RAND_RESET_I(1);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_bus__DOT__host_gnt_o[__Vi0] = VL_RAND_RESET_I(1);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_bus__DOT__host_addr_i[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_bus__DOT__host_we_i[__Vi0] = VL_RAND_RESET_I(1);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_bus__DOT__host_be_i[__Vi0] = VL_RAND_RESET_I(4);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_bus__DOT__host_wdata_i[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_bus__DOT__host_rvalid_o[__Vi0] = VL_RAND_RESET_I(1);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_bus__DOT__host_rdata_o[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_bus__DOT__host_err_o[__Vi0] = VL_RAND_RESET_I(1);
    }
    for (int __Vi0 = 0; __Vi0 < 3; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_bus__DOT__device_req_o[__Vi0] = VL_RAND_RESET_I(1);
    }
    for (int __Vi0 = 0; __Vi0 < 3; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_bus__DOT__device_addr_o[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 3; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_bus__DOT__device_we_o[__Vi0] = VL_RAND_RESET_I(1);
    }
    for (int __Vi0 = 0; __Vi0 < 3; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_bus__DOT__device_be_o[__Vi0] = VL_RAND_RESET_I(4);
    }
    for (int __Vi0 = 0; __Vi0 < 3; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_bus__DOT__device_wdata_o[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 3; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_bus__DOT__device_rvalid_i[__Vi0] = VL_RAND_RESET_I(1);
    }
    for (int __Vi0 = 0; __Vi0 < 3; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_bus__DOT__device_rdata_i[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 3; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_bus__DOT__device_err_i[__Vi0] = VL_RAND_RESET_I(1);
    }
    for (int __Vi0 = 0; __Vi0 < 3; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_bus__DOT__cfg_device_addr_base[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 3; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_bus__DOT__cfg_device_addr_mask[__Vi0] = VL_RAND_RESET_I(32);
    }
    vlSelf->ibex_simple_system__DOT__u_bus__DOT__host_sel_valid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_bus__DOT__device_sel_valid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_bus__DOT__decode_err_resp = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_bus__DOT__host_sel_req = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_bus__DOT__host_sel_resp = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_bus__DOT__device_sel_req = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_bus__DOT__device_sel_resp = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_bus__DOT__unnamedblk1__DOT__host = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_bus__DOT__unnamedblk2__DOT__device = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_bus__DOT__unnamedblk3__DOT__device = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_bus__DOT__unnamedblk4__DOT__host = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_bus__DOT____Vlvbound_h668b8a91__0 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_bus__DOT____Vlvbound_h3ed7c4b5__0 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_bus__DOT____Vlvbound_h53a6baaf__0 = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_bus__DOT____Vlvbound_hf6e2d899__0 = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_bus__DOT____Vlvbound_h0cc97a4e__0 = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_bus__DOT____Vlvbound_h28d63177__0 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_bus__DOT____Vlvbound_h984de552__0 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_bus__DOT____Vlvbound_h6ad861f2__0 = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__test_en_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__scan_rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__ram_cfg_i = VL_RAND_RESET_I(10);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__hart_id_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__boot_addr_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__instr_req_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__instr_gnt_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__instr_rvalid_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__instr_addr_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__instr_rdata_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__instr_rdata_intg_i = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__instr_err_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__data_req_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__data_gnt_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__data_rvalid_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__data_we_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__data_be_o = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__data_addr_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__data_wdata_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__data_wdata_intg_o = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__data_rdata_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__data_rdata_intg_i = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__data_err_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__irq_software_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__irq_timer_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__irq_external_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__irq_fast_i = VL_RAND_RESET_I(15);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__irq_nm_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__scramble_key_valid_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__scramble_key_i[0] = 0U;
    vlSelf->ibex_simple_system__DOT__u_top__DOT__scramble_key_i[1] = 0U;
    vlSelf->ibex_simple_system__DOT__u_top__DOT__scramble_key_i[2] = 0U;
    vlSelf->ibex_simple_system__DOT__u_top__DOT__scramble_key_i[3] = 0U;
    vlSelf->ibex_simple_system__DOT__u_top__DOT__scramble_nonce_i = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__scramble_req_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__debug_req_i = VL_RAND_RESET_I(1);
    VL_RAND_RESET_W(160, vlSelf->ibex_simple_system__DOT__u_top__DOT__crash_dump_o);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__double_fault_seen_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__fetch_enable_i = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__alert_minor_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__alert_major_internal_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__alert_major_bus_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__core_sleep_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_valid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_order = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_insn = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_trap = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_halt = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_intr = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_mode = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_ixl = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_rs1_addr = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_rs2_addr = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_rs3_addr = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_rs1_rdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_rs2_rdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_rs3_rdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_rd_addr = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_rd_wdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_pc_rdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_pc_wdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_mem_addr = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_mem_rmask = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_mem_wmask = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_mem_rdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_mem_wdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_ext_pre_mip = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_ext_post_mip = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_ext_nmi = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_ext_nmi_int = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_ext_debug_req = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_ext_debug_mode = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_ext_rf_wr_suppress = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mcycle = VL_RAND_RESET_Q(64);
    for (int __Vi0 = 0; __Vi0 < 10; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcounters[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 10; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcountersh[__Vi0] = VL_RAND_RESET_I(32);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_ext_ic_scr_key_valid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__rvfi_ext_irq_valid = VL_RAND_RESET_I(1);
    for (int __Vi0 = 0; __Vi0 < 10; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__unused_perf_regs[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 10; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__unused_perf_regsh[__Vi0] = VL_RAND_RESET_I(32);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__unused_rvfi_ext_pre_mip = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__unused_rvfi_ext_post_mip = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__unused_rvfi_ext_nmi = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__unused_rvfi_ext_nmi_int = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__unused_rvfi_ext_debug_req = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__unused_rvfi_ext_debug_mode = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__unused_rvfi_ext_rf_wr_suppress = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__unused_rvfi_ext_mcycle = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__unused_rvfi_ext_ic_scr_key_valid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__unused_rvfi_ext_irq_valid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__test_en_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__ram_cfg_i = VL_RAND_RESET_I(10);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__hart_id_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__boot_addr_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__instr_req_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__instr_gnt_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__instr_rvalid_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__instr_addr_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__instr_rdata_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__instr_rdata_intg_i = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__instr_err_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_req_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_gnt_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rvalid_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_we_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_be_o = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_addr_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_wdata_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_wdata_intg_o = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_intg_i = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_err_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__irq_software_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__irq_timer_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__irq_external_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__irq_fast_i = VL_RAND_RESET_I(15);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__irq_nm_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__scramble_key_valid_i = VL_RAND_RESET_I(1);
    VL_RAND_RESET_W(128, vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__scramble_key_i);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__scramble_nonce_i = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__scramble_req_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__debug_req_i = VL_RAND_RESET_I(1);
    VL_RAND_RESET_W(160, vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__crash_dump_o);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__double_fault_seen_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_valid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_order = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_insn = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_trap = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_halt = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_intr = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_mode = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ixl = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_rs1_addr = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_rs2_addr = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_rs3_addr = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_rs1_rdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_rs2_rdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_rs3_rdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_rd_addr = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_rd_wdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_pc_rdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_pc_wdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_mem_addr = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_mem_rmask = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_mem_wmask = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_mem_rdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_mem_wdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_pre_mip = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_post_mip = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_nmi = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_nmi_int = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_debug_req = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_debug_mode = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_rf_wr_suppress = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mcycle = VL_RAND_RESET_Q(64);
    for (int __Vi0 = 0; __Vi0 < 10; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcounters[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 10; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcountersh[__Vi0] = VL_RAND_RESET_I(32);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_ic_scr_key_valid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_irq_valid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__fetch_enable_i = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__alert_minor_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__alert_major_internal_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__alert_major_bus_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__core_sleep_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__scan_rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__clk = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__core_busy_d = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__core_busy_q = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__clock_en = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__irq_pending = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__dummy_instr_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__dummy_instr_wb = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_raddr_a = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_raddr_b = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_waddr_wb = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_we_wb = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_rdata_a_ecc = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_rdata_a_ecc_buf = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_rdata_b_ecc = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_rdata_b_ecc_buf = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_wdata_core = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__instr_rdata_core = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__ic_tag_req = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__ic_tag_write = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__ic_tag_addr = VL_RAND_RESET_I(8);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__ic_tag_wdata = VL_RAND_RESET_I(22);
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__ic_tag_rdata[__Vi0] = VL_RAND_RESET_I(22);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__ic_data_req = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__ic_data_write = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__ic_data_addr = VL_RAND_RESET_I(8);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__ic_data_wdata = VL_RAND_RESET_Q(64);
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__ic_data_rdata[__Vi0] = VL_RAND_RESET_Q(64);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__ic_scr_key_req = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__core_alert_major_internal = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__core_alert_major_bus = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__core_alert_minor = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__lockstep_alert_major_internal = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__lockstep_alert_major_bus = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__lockstep_alert_minor = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__scramble_key_q[0] = 0U;
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__scramble_key_q[1] = 0U;
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__scramble_key_q[2] = 0U;
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__scramble_key_q[3] = 0U;
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__scramble_nonce_q = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__scramble_key_valid_d = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__scramble_key_valid_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__scramble_req_d = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__scramble_req_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__fetch_enable_buf = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_alert_major_internal = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__icache_tag_alert = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__icache_data_alert = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__icache_alert_major_internal = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__g_clock_en_non_secure__DOT__unused_core_busy = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_non_mem_rdata_ecc__DOT__unused_intg = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_noscramble__DOT__unused_scramble_inputs = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_norams__DOT__unused_ram_cfg = VL_RAND_RESET_I(10);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_norams__DOT__unused_ram_inputs = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_no_lockstep__DOT__unused_scan = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__core_clock_gate_i__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__core_clock_gate_i__DOT__en_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__core_clock_gate_i__DOT__test_en_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__core_clock_gate_i__DOT__clk_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__core_clock_gate_i__DOT__en_latch = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_fetch_enable_buf__DOT__in_i = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_fetch_enable_buf__DOT__out_o = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_fetch_enable_buf__DOT__gen_generic__DOT__u_impl_generic__DOT__in_i = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_fetch_enable_buf__DOT__gen_generic__DOT__u_impl_generic__DOT__out_o = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_fetch_enable_buf__DOT__gen_generic__DOT__u_impl_generic__DOT__inv = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_rf_rdata_a_ecc_buf__DOT__in_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_rf_rdata_a_ecc_buf__DOT__out_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_rf_rdata_a_ecc_buf__DOT__gen_generic__DOT__u_impl_generic__DOT__in_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_rf_rdata_a_ecc_buf__DOT__gen_generic__DOT__u_impl_generic__DOT__out_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_rf_rdata_a_ecc_buf__DOT__gen_generic__DOT__u_impl_generic__DOT__inv = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_rf_rdata_b_ecc_buf__DOT__in_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_rf_rdata_b_ecc_buf__DOT__out_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_rf_rdata_b_ecc_buf__DOT__gen_generic__DOT__u_impl_generic__DOT__in_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_rf_rdata_b_ecc_buf__DOT__gen_generic__DOT__u_impl_generic__DOT__out_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_rf_rdata_b_ecc_buf__DOT__gen_generic__DOT__u_impl_generic__DOT__inv = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__hart_id_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__boot_addr_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_req_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_gnt_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_rvalid_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_addr_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_rdata_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_err_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__data_req_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__data_gnt_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__data_rvalid_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__data_we_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__data_be_o = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__data_addr_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__data_wdata_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__data_rdata_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__data_err_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__dummy_instr_id_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__dummy_instr_wb_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_raddr_a_o = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_raddr_b_o = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_waddr_wb_o = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_we_wb_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_wdata_wb_ecc_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_rdata_a_ecc_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_rdata_b_ecc_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ic_tag_req_o = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ic_tag_write_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ic_tag_addr_o = VL_RAND_RESET_I(8);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ic_tag_wdata_o = VL_RAND_RESET_I(22);
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ic_tag_rdata_i[__Vi0] = VL_RAND_RESET_I(22);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ic_data_req_o = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ic_data_write_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ic_data_addr_o = VL_RAND_RESET_I(8);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ic_data_wdata_o = VL_RAND_RESET_Q(64);
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ic_data_rdata_i[__Vi0] = VL_RAND_RESET_Q(64);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ic_scr_key_valid_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ic_scr_key_req_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irq_software_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irq_timer_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irq_external_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irq_fast_i = VL_RAND_RESET_I(15);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irq_nm_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irq_pending_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__debug_req_i = VL_RAND_RESET_I(1);
    VL_RAND_RESET_W(160, vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__crash_dump_o);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__double_fault_seen_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_valid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_order = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_insn = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_trap = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_halt = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_intr = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mode = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ixl = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs1_addr = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs2_addr = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs3_addr = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs1_rdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs2_rdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs3_rdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rd_addr = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rd_wdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_pc_rdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_pc_wdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_addr = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_rmask = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_wmask = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_rdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_wdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_pre_mip = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_post_mip = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_nmi = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_nmi_int = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_debug_req = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_debug_mode = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_rf_wr_suppress = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mcycle = VL_RAND_RESET_Q(64);
    for (int __Vi0 = 0; __Vi0 < 10; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcounters[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 10; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcountersh[__Vi0] = VL_RAND_RESET_I(32);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_ic_scr_key_valid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_irq_valid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__fetch_enable_i = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__alert_minor_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__alert_major_internal_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__alert_major_bus_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__core_busy_o = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__dummy_instr_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_valid_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_new_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_rdata_id = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_rdata_alu_id = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_rdata_c_id = VL_RAND_RESET_I(16);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_is_compressed_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_perf_count_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_bp_taken_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_fetch_err = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_fetch_err_plus2 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__illegal_c_insn_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__pc_if = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__pc_id = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__pc_wb = VL_RAND_RESET_I(32);
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__imd_val_d_ex[__Vi0] = VL_RAND_RESET_Q(34);
    }
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__imd_val_q_ex[__Vi0] = VL_RAND_RESET_Q(34);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__imd_val_we_ex = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__data_ind_timing = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__dummy_instr_en = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__dummy_instr_mask = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__dummy_instr_seed_en = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__dummy_instr_seed = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__icache_enable = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__icache_inval = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__icache_ecc_error = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__pc_mismatch_alert = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_shadow_err = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_first_cycle_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_valid_clear = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__pc_set = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__nt_branch_mispredict = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__nt_branch_addr = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__pc_mux_id = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__exc_pc_mux_id = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__exc_cause = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_intg_err = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_load_err = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_load_err_raw = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_store_err = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_store_err_raw = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_load_resp_intg_err = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_store_resp_intg_err = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__expecting_load_resp_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__expecting_store_resp_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_addr_incr_req = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_addr_last = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__branch_target_ex = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__branch_decision = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ctrl_busy = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_busy = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_busy = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_raddr_a = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_rdata_a = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_raddr_b = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_rdata_b = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_ren_a = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_ren_b = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_waddr_wb = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_wdata_wb = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_wdata_fwd_wb = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_wdata_lsu = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_we_wb = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_we_lsu = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_ecc_err_comb = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_waddr_id = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_wdata_id = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_we_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_rd_a_wb_match = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_rd_b_wb_match = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__alu_operator_ex = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__alu_operand_a_ex = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__alu_operand_b_ex = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__bt_a_operand = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__bt_b_operand = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__alu_adder_result_ex = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__result_ex = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__mult_en_ex = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__div_en_ex = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__mult_sel_ex = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__div_sel_ex = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__multdiv_operator_ex = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__multdiv_signed_mode_ex = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__multdiv_operand_a_ex = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__multdiv_operand_b_ex = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__multdiv_ready_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_access = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_op = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_op_en = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr = VL_RAND_RESET_I(12);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_rdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_wdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__illegal_csr_insn_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_we = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_type = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_sign_ext = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_req = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_rdata_valid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_wdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_req_done = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_in_ready = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_valid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_resp_valid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_resp_err = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_req_int = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_req_gated = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_exec = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__en_wb = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_type_wb = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ready_wb = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_write_wb = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__outstanding_load_wb = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__outstanding_store_wb = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__dummy_instr_wb = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__nmi_mode = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irqs = VL_RAND_RESET_I(18);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_mstatus_mie = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_mepc = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_depc = VL_RAND_RESET_I(32);
    for (int __Vi0 = 0; __Vi0 < 4; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_pmp_addr[__Vi0] = VL_RAND_RESET_Q(34);
    }
    for (int __Vi0 = 0; __Vi0 < 4; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_pmp_cfg[__Vi0] = VL_RAND_RESET_I(6);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_pmp_mseccfg = VL_RAND_RESET_I(3);
    for (int __Vi0 = 0; __Vi0 < 3; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__pmp_req_err[__Vi0] = VL_RAND_RESET_I(1);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__data_req_out = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_save_if = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_save_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_save_wb = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_restore_mret_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_restore_dret_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_save_cause = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_mtvec_init = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_mtvec = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_mtval = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_mstatus_tw = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__priv_mode_id = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__priv_mode_lsu = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__debug_mode = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__debug_mode_entering = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__debug_cause = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__debug_csr_save = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__debug_single_step = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__debug_ebreakm = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__debug_ebreaku = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__trigger_match = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_id_done = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_done_wb = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__perf_instr_ret_wb = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__perf_instr_ret_compressed_wb = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__perf_instr_ret_wb_spec = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__perf_instr_ret_compressed_wb_spec = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__perf_iside_wait = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__perf_dside_wait = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__perf_mul_wait = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__perf_div_wait = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__perf_jump = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__perf_branch = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__perf_tbranch = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__perf_load = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__perf_store = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__illegal_insn_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__unused_illegal_insn_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__crash_dump_mtval = VL_RAND_RESET_I(32);
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_valid[__Vi0] = VL_RAND_RESET_I(1);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_order[__Vi0] = VL_RAND_RESET_Q(64);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_insn[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_trap[__Vi0] = VL_RAND_RESET_I(1);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_halt[__Vi0] = VL_RAND_RESET_I(1);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_intr[__Vi0] = VL_RAND_RESET_I(1);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mode[__Vi0] = VL_RAND_RESET_I(2);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_ixl[__Vi0] = VL_RAND_RESET_I(2);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_addr[__Vi0] = VL_RAND_RESET_I(5);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_addr[__Vi0] = VL_RAND_RESET_I(5);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_addr[__Vi0] = VL_RAND_RESET_I(5);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_rdata[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_rdata[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_rdata[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_addr[__Vi0] = VL_RAND_RESET_I(5);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_wdata[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_rdata[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_wdata[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_addr[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rmask[__Vi0] = VL_RAND_RESET_I(4);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wmask[__Vi0] = VL_RAND_RESET_I(4);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rdata[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wdata[__Vi0] = VL_RAND_RESET_I(32);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_instr_new_wb = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_intr_d = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_intr_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_set_trap_pc_d = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_set_trap_pc_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_insn_id = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs1_addr_d = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs1_addr_q = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs2_addr_d = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs2_addr_q = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs3_addr_d = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs1_data_d = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs1_data_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs2_data_d = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs2_data_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs3_data_d = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rd_addr_wb = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rd_addr_q = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rd_addr_d = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rd_wdata_wb = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rd_wdata_d = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rd_wdata_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rd_we_wb = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_mask_int = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_rdata_d = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_rdata_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_wdata_d = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_wdata_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_addr_d = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_addr_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_trap_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_trap_wb = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_irq_valid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_order_d = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_id_done = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_wb_done = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__new_debug_req = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__new_nmi = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__new_nmi_int = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__new_irq = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_mip = VL_RAND_RESET_I(18);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_nmi = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_nmi_int = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_debug_req = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_valid = VL_RAND_RESET_I(1);
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip[__Vi0] = VL_RAND_RESET_I(18);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_post_mip[__Vi0] = VL_RAND_RESET_I(18);
    }
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi[__Vi0] = VL_RAND_RESET_I(1);
    }
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int[__Vi0] = VL_RAND_RESET_I(1);
    }
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req[__Vi0] = VL_RAND_RESET_I(1);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_mode[__Vi0] = VL_RAND_RESET_I(1);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mcycle[__Vi0] = VL_RAND_RESET_Q(64);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        for (int __Vi1 = 0; __Vi1 < 10; ++__Vi1) {
            vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters[__Vi0][__Vi1] = VL_RAND_RESET_I(32);
        }
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        for (int __Vi1 = 0; __Vi1 < 10; ++__Vi1) {
            vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh[__Vi0][__Vi1] = VL_RAND_RESET_I(32);
        }
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_ic_scr_key_valid[__Vi0] = VL_RAND_RESET_I(1);
    }
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_irq_valid[__Vi0] = VL_RAND_RESET_I(1);
    }
    for (int __Vi0 = 0; __Vi0 < 1; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_valid_d[__Vi0] = VL_RAND_RESET_I(1);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__fcov_rf_ecc_err_a_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__unused_fcov_rf_ecc_err_a_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__fcov_rf_ecc_err_b_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__unused_fcov_rf_ecc_err_b_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__fcov_csr_read_only = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__unused_fcov_csr_read_only = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__fcov_csr_write = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__unused_fcov_csr_write = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__g_instr_req_gated_non_secure__DOT__unused_fetch_enable = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__g_no_check_mem_response__DOT__unused_expecting_load_resp_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__g_no_check_mem_response__DOT__unused_expecting_store_resp_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__gen_no_regfile_ecc__DOT__unused_rf_ren_a = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__gen_no_regfile_ecc__DOT__unused_rf_ren_b = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__gen_no_regfile_ecc__DOT__unused_rf_rd_a_wb_match = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__gen_no_regfile_ecc__DOT__unused_rf_rd_b_wb_match = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__g_no_pmp__DOT__unused_priv_lvl_ls = VL_RAND_RESET_I(2);
    for (int __Vi0 = 0; __Vi0 < 4; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__g_no_pmp__DOT__unused_csr_pmp_addr[__Vi0] = VL_RAND_RESET_Q(34);
    }
    for (int __Vi0 = 0; __Vi0 < 4; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__g_no_pmp__DOT__unused_csr_pmp_cfg[__Vi0] = VL_RAND_RESET_I(6);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__g_no_pmp__DOT__unused_csr_pmp_mseccfg = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__g_rvfi_stages__BRA__0__KET____DOT__unnamedblk1__DOT__k = 0;
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h5795fcef__0 = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h49acdc58__0 = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__boot_addr_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__req_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_req_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_addr_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_gnt_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rvalid_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_bus_err_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_intg_err_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__ic_tag_req_o = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__ic_tag_write_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__ic_tag_addr_o = VL_RAND_RESET_I(8);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__ic_tag_wdata_o = VL_RAND_RESET_I(22);
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__ic_tag_rdata_i[__Vi0] = VL_RAND_RESET_I(22);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__ic_data_req_o = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__ic_data_write_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__ic_data_addr_o = VL_RAND_RESET_I(8);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__ic_data_wdata_o = VL_RAND_RESET_Q(64);
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__ic_data_rdata_i[__Vi0] = VL_RAND_RESET_Q(64);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__ic_scr_key_valid_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__ic_scr_key_req_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_valid_id_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_new_id_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_alu_id_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_c_id_o = VL_RAND_RESET_I(16);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_is_compressed_id_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_bp_taken_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_fetch_err_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_fetch_err_plus2_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__illegal_c_insn_id_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__dummy_instr_id_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__pc_if_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__pc_id_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__pmp_err_if_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__pmp_err_if_plus2_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_valid_clear_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__pc_set_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__pc_mux_i = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__nt_branch_mispredict_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__nt_branch_addr_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__exc_pc_mux_i = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__exc_cause = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__dummy_instr_en_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__dummy_instr_mask_i = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__dummy_instr_seed_en_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__dummy_instr_seed_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__icache_enable_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__icache_inval_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__icache_ecc_error_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__branch_target_ex_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__csr_mepc_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__csr_depc_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__csr_mtvec_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__csr_mtvec_init_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__id_in_ready_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__pc_mismatch_alert_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_busy_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_valid_id_d = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_valid_id_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_new_id_d = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_new_id_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_err = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_intg_err = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__prefetch_busy = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__branch_req = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__fetch_addr_n = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__unused_fetch_addr_n0 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__prefetch_branch = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__prefetch_addr = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__fetch_valid_raw = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__fetch_valid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__fetch_ready = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__fetch_rdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__fetch_addr = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__fetch_err = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__fetch_err_plus2 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_decompressed = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__illegal_c_insn = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_is_compressed = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_valid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_addr = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_bus_err = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_pmp_err = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_err = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_err_plus2 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__exc_pc = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_id_pipe_reg_we = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__stall_dummy_instr = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_out = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_is_compressed_out = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__illegal_c_instr_out = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_err_out = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__predict_branch_taken = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__predict_branch_pc = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__irq_vec = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__pc_mux_internal = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__unused_boot_addr = VL_RAND_RESET_I(8);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__unused_csr_mtvec = VL_RAND_RESET_I(8);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__unused_exc_cause = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__fcov_dummy_instr_type = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__unused_fcov_dummy_instr_type = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__fcov_insert_dummy_instr = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__unused_fcov_insert_dummy_instr = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__unused_icen = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__unused_icinv = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__unused_scr_key_valid = VL_RAND_RESET_I(1);
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__unused_tag_ram_input[__Vi0] = VL_RAND_RESET_I(22);
    }
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__unused_data_ram_input[__Vi0] = VL_RAND_RESET_Q(64);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_no_dummy_instr__DOT__unused_dummy_en = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_no_dummy_instr__DOT__unused_dummy_mask = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_no_dummy_instr__DOT__unused_dummy_seed_en = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_no_dummy_instr__DOT__unused_dummy_seed = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__valid_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__instr_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__instr_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__is_compressed_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__illegal_instr_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__unused_valid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__req_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__branch_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__addr_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__ready_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__valid_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__rdata_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__addr_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__err_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__err_plus2_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__instr_req_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__instr_gnt_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__instr_addr_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__instr_rdata_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__instr_err_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__instr_rvalid_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__busy_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__valid_new_req = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__valid_req = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__valid_req_d = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__valid_req_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__discard_req_d = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__discard_req_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__rdata_outstanding_n = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__rdata_outstanding_s = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__rdata_outstanding_q = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__branch_discard_n = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__branch_discard_s = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__branch_discard_q = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__rdata_outstanding_rev = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__stored_addr_d = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__stored_addr_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__stored_addr_en = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fetch_addr_d = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fetch_addr_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fetch_addr_en = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__instr_addr = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__instr_addr_w_aligned = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_valid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_addr = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_ready = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_clear = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_busy = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__clear_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__busy_o = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__in_valid_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__in_addr_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__in_rdata_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__in_err_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__out_valid_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__out_ready_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__out_addr_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__out_rdata_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__out_err_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__out_err_plus2_o = VL_RAND_RESET_I(1);
    VL_RAND_RESET_W(96, vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__rdata_d);
    VL_RAND_RESET_W(96, vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__rdata_q);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__err_d = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__err_q = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_d = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_q = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__lowest_free_entry = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_pushed = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_popped = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__entry_en = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__pop_fifo = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__rdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__rdata_unaligned = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__err = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__err_unaligned = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__err_plus2 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_unaligned = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__aligned_is_compressed = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__unaligned_is_compressed = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__addr_incr_two = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__instr_addr_next = VL_RAND_RESET_I(31);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__instr_addr_d = VL_RAND_RESET_I(31);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__instr_addr_q = VL_RAND_RESET_I(31);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__instr_addr_en = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__unused_addr_in = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT____VdfgRegularize_hb4cbc9db_0_10 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT____VdfgRegularize_hb4cbc9db_0_14 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT____VdfgRegularize_hb4cbc9db_0_15 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT____VdfgRegularize_hb4cbc9db_0_16 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT____VdfgRegularize_hb4cbc9db_0_19 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT____VdfgRegularize_hb4cbc9db_0_20 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT____VdfgRegularize_hb4cbc9db_0_21 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT____VdfgRegularize_hb4cbc9db_0_23 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__ctrl_busy_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__illegal_insn_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_valid_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_rdata_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_rdata_alu_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_rdata_c_i = VL_RAND_RESET_I(16);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_is_compressed_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_bp_taken_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_req_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_first_cycle_id_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_valid_clear_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__id_in_ready_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_exec_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__icache_inval_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__branch_decision_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__pc_set_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__pc_mux_o = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__nt_branch_mispredict_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__nt_branch_addr_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__exc_pc_mux_o = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__exc_cause_o = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__illegal_c_insn_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_fetch_err_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_fetch_err_plus2_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__pc_id_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__ex_valid_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__lsu_resp_valid_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__alu_operator_ex_o = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__alu_operand_a_ex_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__alu_operand_b_ex_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_we_ex_i = VL_RAND_RESET_I(2);
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_d_ex_i[__Vi0] = VL_RAND_RESET_Q(34);
    }
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q_ex_o[__Vi0] = VL_RAND_RESET_Q(34);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__bt_a_operand_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__bt_b_operand_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__mult_en_ex_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__div_en_ex_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__mult_sel_ex_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__div_sel_ex_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__multdiv_operator_ex_o = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__multdiv_signed_mode_ex_o = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__multdiv_operand_a_ex_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__multdiv_operand_b_ex_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__multdiv_ready_id_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__csr_access_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__csr_op_o = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__csr_addr_o = VL_RAND_RESET_I(12);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__csr_op_en_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__csr_save_if_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__csr_save_id_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__csr_save_wb_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__csr_restore_mret_id_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__csr_restore_dret_id_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__csr_save_cause_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__csr_mtval_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__priv_mode_i = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__csr_mstatus_tw_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__illegal_csr_insn_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__data_ind_timing_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__lsu_req_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__lsu_we_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__lsu_type_o = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__lsu_sign_ext_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__lsu_wdata_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__lsu_req_done_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__lsu_addr_incr_req_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__lsu_addr_last_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__csr_mstatus_mie_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__irq_pending_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__irqs_i = VL_RAND_RESET_I(18);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__irq_nm_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__nmi_mode_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__lsu_load_err_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__lsu_load_resp_intg_err_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__lsu_store_err_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__lsu_store_resp_intg_err_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__expecting_load_resp_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__expecting_store_resp_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__debug_mode_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__debug_mode_entering_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__debug_cause_o = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__debug_csr_save_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__debug_req_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__debug_single_step_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__debug_ebreakm_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__debug_ebreaku_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__trigger_match_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__result_ex_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__csr_rdata_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_raddr_a_o = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_rdata_a_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_raddr_b_o = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_rdata_b_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_ren_a_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_ren_b_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_waddr_id_o = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_wdata_id_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_we_id_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_rd_a_wb_match_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_rd_b_wb_match_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_waddr_wb_i = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_wdata_fwd_wb_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_write_wb_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__en_wb_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_type_wb_o = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_perf_count_id_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__ready_wb_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__outstanding_load_wb_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__outstanding_store_wb_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__perf_jump_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__perf_branch_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__perf_tbranch_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__perf_dside_wait_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__perf_mul_wait_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__perf_div_wait_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_id_done_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__illegal_insn_dec = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__illegal_dret_insn = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__illegal_umode_insn = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__ebrk_insn = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__mret_insn_dec = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__dret_insn_dec = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__ecall_insn_dec = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__wfi_insn_dec = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__wb_exception = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__id_exception = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__branch_in_dec = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__branch_set = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__branch_set_raw = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__branch_set_raw_d = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__branch_jump_set_done_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__branch_jump_set_done_d = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__branch_not_set = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__branch_taken = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__jump_in_dec = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__jump_set_dec = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__jump_set = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__jump_set_raw = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_first_cycle = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_executing_spec = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_executing = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_done = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_run = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__stall_ld_hz = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__stall_mem = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__stall_multdiv = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__stall_branch = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__stall_jump = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__stall_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__stall_wb = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__flush_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__multicycle_done = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__mem_resp_intg_err = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imm_i_type = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imm_s_type = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imm_b_type = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imm_u_type = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imm_j_type = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__zimm_rs1_type = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imm_a = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imm_b = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_wdata_sel = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_we_dec = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_we_raw = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_ren_a = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_ren_b = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_ren_a_dec = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_ren_b_dec = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_rdata_a_fwd = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_rdata_b_fwd = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__alu_operator = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__alu_op_a_mux_sel = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__alu_op_a_mux_sel_dec = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__alu_op_b_mux_sel = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__alu_op_b_mux_sel_dec = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__alu_multicycle_dec = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__stall_alu = VL_RAND_RESET_I(1);
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q[__Vi0] = VL_RAND_RESET_Q(34);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__bt_a_mux_sel = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__bt_b_mux_sel = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imm_a_mux_sel = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imm_b_mux_sel = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imm_b_mux_sel_dec = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__mult_en_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__mult_en_dec = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__div_en_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__div_en_dec = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__multdiv_en_dec = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__multdiv_operator = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__multdiv_signed_mode = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__lsu_we = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__lsu_type = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__lsu_sign_ext = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__lsu_req = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__lsu_req_dec = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__data_req_allowed = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__no_flush_csr_addr = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__csr_pipe_flush = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__alu_operand_a = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__alu_operand_b = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__id_fsm_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__id_fsm_d = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__fcov_rf_rd_wb_hz = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__unused_fcov_rf_rd_wb_hz = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__fcov_branch_taken = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__unused_fcov_branch_taken = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__fcov_branch_not_taken = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__unused_fcov_branch_not_taken = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__g_nobtalu__DOT__unused_a_mux_sel = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__g_nobtalu__DOT__unused_b_mux_sel = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__g_branch_set_flop__DOT__branch_set_raw_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__gen_no_stall_mem__DOT__unused_data_req_done_ex = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__gen_no_stall_mem__DOT__unused_rf_waddr_wb = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__gen_no_stall_mem__DOT__unused_rf_write_wb = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__gen_no_stall_mem__DOT__unused_outstanding_load_wb = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__gen_no_stall_mem__DOT__unused_outstanding_store_wb = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__gen_no_stall_mem__DOT__unused_wb_exception = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__gen_no_stall_mem__DOT__unused_rf_wdata_fwd_wb = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__gen_no_stall_mem__DOT__unused_id_exception = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT____VdfgRegularize_hc182f6fb_0_7 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__illegal_insn_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__ebrk_insn_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__mret_insn_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__dret_insn_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__ecall_insn_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__wfi_insn_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__jump_set_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__branch_taken_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__icache_inval_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__instr_first_cycle_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__instr_rdata_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__instr_rdata_alu_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__illegal_c_insn_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__imm_a_mux_sel_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__imm_b_mux_sel_o = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__bt_a_mux_sel_o = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__bt_b_mux_sel_o = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__imm_i_type_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__imm_s_type_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__imm_b_type_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__imm_u_type_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__imm_j_type_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__zimm_rs1_type_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__rf_wdata_sel_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__rf_we_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__rf_raddr_a_o = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__rf_raddr_b_o = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__rf_waddr_o = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__rf_ren_a_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__rf_ren_b_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__alu_operator_o = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__alu_op_a_mux_sel_o = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__alu_op_b_mux_sel_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__alu_multicycle_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__mult_en_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__div_en_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__mult_sel_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__div_sel_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__multdiv_operator_o = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__multdiv_signed_mode_o = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__csr_access_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__csr_op_o = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__csr_addr_o = VL_RAND_RESET_I(12);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__data_req_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__data_we_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__data_type_o = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__data_sign_extension_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__jump_in_dec_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__branch_in_dec_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__illegal_insn = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__illegal_reg_rv32e = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__csr_illegal = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__rf_we = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__instr = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__instr_alu = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__unused_instr_alu = VL_RAND_RESET_I(10);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__instr_rs1 = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__instr_rs2 = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__instr_rs3 = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__instr_rd = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__use_rs3_d = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__use_rs3_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__csr_op = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__opcode = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__opcode_alu = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__gen_no_rs3_flop__DOT__unused_clk = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__gen_no_rs3_flop__DOT__unused_rst_n = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT____VdfgRegularize_h50863dbe_1_9 = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT____VdfgRegularize_h50863dbe_1_14 = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT____VdfgRegularize_h50863dbe_1_29 = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT____VdfgRegularize_h50863dbe_1_30 = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT____VdfgRegularize_h50863dbe_2_6 = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__ctrl_busy_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__illegal_insn_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__ecall_insn_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__mret_insn_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__dret_insn_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__wfi_insn_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__ebrk_insn_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__csr_pipe_flush_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__instr_valid_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__instr_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__instr_compressed_i = VL_RAND_RESET_I(16);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__instr_is_compressed_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__instr_bp_taken_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__instr_fetch_err_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__instr_fetch_err_plus2_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__pc_id_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__instr_valid_clear_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__id_in_ready_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__controller_run_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__instr_exec_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__instr_req_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__pc_set_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__pc_mux_o = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__nt_branch_mispredict_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__exc_pc_mux_o = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__exc_cause_o = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__lsu_addr_last_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__load_err_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__store_err_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__mem_resp_intg_err_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__wb_exception_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__id_exception_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__branch_set_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__branch_not_set_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__jump_set_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__csr_mstatus_mie_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__irq_pending_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__irqs_i = VL_RAND_RESET_I(18);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__irq_nm_ext_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__nmi_mode_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_req_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_cause_o = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_csr_save_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_mode_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_mode_entering_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_single_step_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_ebreakm_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_ebreaku_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__trigger_match_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__csr_save_if_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__csr_save_id_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__csr_save_wb_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__csr_restore_mret_id_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__csr_restore_dret_id_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__csr_save_cause_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__csr_mtval_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__priv_mode_i = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__stall_id_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__stall_wb_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__flush_id_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__ready_wb_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__perf_jump_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__perf_tbranch_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__ctrl_fsm_cs = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__ctrl_fsm_ns = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__nmi_mode_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__nmi_mode_d = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_mode_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_mode_d = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_cause_d = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_cause_q = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__load_err_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__load_err_d = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__store_err_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__store_err_d = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__exc_req_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__exc_req_d = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__illegal_insn_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__illegal_insn_d = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__instr_fetch_err_prio = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__illegal_insn_prio = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__ecall_insn_prio = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__ebrk_insn_prio = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__store_err_prio = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__load_err_prio = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__stall = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__halt_if = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__retain_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__flush_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__exc_req_lsu = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__special_req = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__special_req_pc_change = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__special_req_flush_only = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__do_single_step_d = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__do_single_step_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__enter_debug_mode_prio_d = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__enter_debug_mode_prio_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__enter_debug_mode = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__ebreak_into_debug = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__irq_enabled = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__handle_irq = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__id_wb_pending = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__irq_nm = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__irq_nm_int = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__irq_nm_int_mtval = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__irq_nm_int_cause = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__mfip_id = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__unused_irq_timer = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__ecall_insn = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__mret_insn = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__dret_insn = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__wfi_insn = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__ebrk_insn = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__csr_pipe_flush = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__instr_fetch_err = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__fcov_all_debug_req = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__unused_fcov_all_debug_req = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__fcov_debug_wakeup = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__unused_fcov_debug_wakeup = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__fcov_interrupt_taken = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__unused_fcov_interrupt_taken = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__fcov_debug_entry_if = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__unused_fcov_debug_entry_if = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__fcov_debug_entry_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__unused_fcov_debug_entry_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__fcov_pipe_flush = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__unused_fcov_pipe_flush = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__fcov_debug_req = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__unused_fcov_debug_req = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__fcov_debug_single_step_taken = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__unused_fcov_debug_single_step_taken = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__rvfi_flush_next = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__g_no_intg_irq_int__DOT__unused_mem_resp_intg_err_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__gen_mfip_id__DOT__unnamedblk1__DOT__i = 0;
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_operator_i = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_operand_a_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_operand_b_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_instr_first_cycle_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__bt_a_operand_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__bt_b_operand_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__multdiv_operator_i = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__mult_en_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__div_en_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__mult_sel_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__div_sel_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__multdiv_signed_mode_i = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__multdiv_operand_a_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__multdiv_operand_b_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__multdiv_ready_id_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__data_ind_timing_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__imd_val_we_o = VL_RAND_RESET_I(2);
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__imd_val_d_o[__Vi0] = VL_RAND_RESET_Q(34);
    }
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__imd_val_q_i[__Vi0] = VL_RAND_RESET_Q(34);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_adder_result_ex_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__result_ex_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__branch_target_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__branch_decision_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__ex_valid_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_result = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__multdiv_result = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__multdiv_alu_operand_b = VL_RAND_RESET_Q(33);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__multdiv_alu_operand_a = VL_RAND_RESET_Q(33);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_adder_result_ext = VL_RAND_RESET_Q(34);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_cmp_result = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_is_equal_result = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__multdiv_valid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__multdiv_sel = VL_RAND_RESET_I(1);
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_imd_val_q[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_imd_val_d[__Vi0] = VL_RAND_RESET_I(32);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_imd_val_we = VL_RAND_RESET_I(2);
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__multdiv_imd_val_d[__Vi0] = VL_RAND_RESET_Q(34);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__multdiv_imd_val_we = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__g_no_branch_target_alu__DOT__unused_bt_a_operand = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__g_no_branch_target_alu__DOT__unused_bt_b_operand = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__operator_i = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__operand_a_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__operand_b_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__instr_first_cycle_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__multdiv_operand_a_i = VL_RAND_RESET_Q(33);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__multdiv_operand_b_i = VL_RAND_RESET_Q(33);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__multdiv_sel_i = VL_RAND_RESET_I(1);
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__imd_val_q_i[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__imd_val_d_o[__Vi0] = VL_RAND_RESET_I(32);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__imd_val_we_o = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__adder_result_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__adder_result_ext_o = VL_RAND_RESET_Q(34);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__result_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__comparison_result_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__is_equal_result_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__operand_a_rev = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__operand_b_neg = VL_RAND_RESET_Q(33);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__adder_op_a_shift1 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__adder_op_a_shift2 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__adder_op_a_shift3 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__adder_op_b_negate = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__adder_in_a = VL_RAND_RESET_Q(33);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__adder_in_b = VL_RAND_RESET_Q(33);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__adder_result = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__is_equal = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__is_greater_equal = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__cmp_signed = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__cmp_result = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__shift_left = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__shift_ones = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__shift_arith = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__shift_funnel = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__shift_sbmode = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__shift_amt = VL_RAND_RESET_I(6);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__shift_amt_compl = VL_RAND_RESET_I(6);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__shift_operand = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__shift_result_ext_signed = VL_RAND_RESET_Q(33);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__shift_result_ext = VL_RAND_RESET_Q(33);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__unused_shift_result_ext = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__shift_result = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__shift_result_rev = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__bfp_op = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__bfp_len = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__bfp_off = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__bfp_mask = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__bfp_mask_rev = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__bfp_result = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__bwlogic_or = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__bwlogic_and = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__bwlogic_operand_b = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__bwlogic_or_result = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__bwlogic_and_result = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__bwlogic_xor_result = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__bwlogic_result = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__bwlogic_op_b_negate = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__bitcnt_result = VL_RAND_RESET_I(6);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__minmax_result = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__pack_result = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__sext_result = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__singlebit_result = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__rev_result = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__shuffle_result = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__xperm_result = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__butterfly_result = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__invbutterfly_result = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__clmul_result = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__multicycle_result = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__unused_shift_amt_compl = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__unnamedblk1__DOT__i = 0;
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__g_no_alu_rvb__DOT__unused_imd_val_q[__Vi0] = VL_RAND_RESET_I(32);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__g_no_alu_rvb__DOT__unused_butterfly_result = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__g_no_alu_rvb__DOT__unused_invbutterfly_result = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__mult_en_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__div_en_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__mult_sel_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__div_sel_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__operator_i = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__signed_mode_i = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__op_a_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__op_b_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__alu_adder_ext_i = VL_RAND_RESET_Q(34);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__alu_adder_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__equal_to_zero_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__data_ind_timing_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__alu_operand_a_o = VL_RAND_RESET_Q(33);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__alu_operand_b_o = VL_RAND_RESET_Q(33);
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__imd_val_q_i[__Vi0] = VL_RAND_RESET_Q(34);
    }
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__imd_val_d_o[__Vi0] = VL_RAND_RESET_Q(34);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__imd_val_we_o = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__multdiv_ready_id_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__multdiv_result_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__valid_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__mac_res_signed = VL_RAND_RESET_Q(35);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__mac_res_ext = VL_RAND_RESET_Q(35);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__accum = VL_RAND_RESET_Q(34);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__sign_a = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__sign_b = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__mult_valid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__signed_mult = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__mac_res_d = VL_RAND_RESET_Q(34);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__op_remainder_d = VL_RAND_RESET_Q(34);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__mac_res = VL_RAND_RESET_Q(34);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__div_sign_a = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__div_sign_b = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__is_greater_equal = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__div_change_sign = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__rem_change_sign = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__one_shift = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__op_denominator_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__op_numerator_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__op_quotient_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__op_denominator_d = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__op_numerator_d = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__op_quotient_d = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__next_remainder = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__next_quotient = VL_RAND_RESET_Q(33);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__res_adder_h = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__div_valid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__div_counter_q = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__div_counter_d = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__multdiv_en = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__mult_hold = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__div_hold = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__div_by_zero_d = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__div_by_zero_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__mult_en_internal = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__div_en_internal = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__sva_mul_fsm_idle = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__md_state_q = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__md_state_d = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__unused_mult_sel_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__unused_imd_val = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__unused_mac_res_ext = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__unused_alu_adder_ext = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__unused_sva_mul_fsm_idle = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__gen_mult_fast__DOT__mult_op_a = VL_RAND_RESET_I(16);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__gen_mult_fast__DOT__mult_op_b = VL_RAND_RESET_I(16);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__gen_mult_fast__DOT__mult_state_q = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__gen_mult_fast__DOT__mult_state_d = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_req_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_gnt_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_rvalid_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_bus_err_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_pmp_err_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_addr_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_we_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_be_o = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_wdata_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_rdata_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__lsu_we_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__lsu_type_i = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__lsu_wdata_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__lsu_sign_ext_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__lsu_rdata_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__lsu_rdata_valid_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__lsu_req_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__adder_result_ex_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__addr_incr_req_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__addr_last_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__lsu_req_done_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__lsu_resp_valid_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__load_err_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__load_resp_intg_err_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__store_err_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__store_resp_intg_err_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__busy_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__perf_load_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__perf_store_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_addr = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_addr_w_aligned = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__addr_last_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__addr_last_d = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__addr_update = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__ctrl_update = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_update = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_q = VL_RAND_RESET_I(24);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_offset_q = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_type_q = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_sign_ext_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_we_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_offset = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_be = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_wdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_rdata_ext = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_w_ext = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_h_ext = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_b_ext = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__split_misaligned_access = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__handle_misaligned_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__handle_misaligned_d = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__pmp_err_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__pmp_err_d = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__lsu_err_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__lsu_err_d = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_intg_err = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_or_pmp_err = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__ls_fsm_cs = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__ls_fsm_ns = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_mis_2_en_d = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_mis_2_en_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_mis_rvalid_1 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_mis_rvalid_2 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_mis_bus_err_1_d = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_mis_bus_err_1_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_ls_error_exception = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__unused_fcov_ls_error_exception = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_ls_pmp_exception = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__unused_fcov_ls_pmp_exception = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_ls_first_req = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__unused_fcov_ls_first_req = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_ls_second_req = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__unused_fcov_ls_second_req = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_ls_mis_pmp_err_1 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__unused_fcov_ls_mis_pmp_err_1 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_ls_mis_pmp_err_2 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__unused_fcov_ls_mis_pmp_err_2 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT____VdfgRegularize_he001948a_0_3 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__en_wb_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__instr_type_wb_i = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__pc_id_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__instr_is_compressed_id_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__instr_perf_count_id_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__ready_wb_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__rf_write_wb_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__outstanding_load_wb_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__outstanding_store_wb_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__pc_wb_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__perf_instr_ret_wb_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__perf_instr_ret_compressed_wb_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__perf_instr_ret_wb_spec_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__perf_instr_ret_compressed_wb_spec_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__rf_waddr_id_i = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__rf_wdata_id_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__rf_we_id_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__dummy_instr_id_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__rf_wdata_lsu_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__rf_we_lsu_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__rf_wdata_fwd_wb_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__rf_waddr_wb_o = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__rf_wdata_wb_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__rf_we_wb_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__dummy_instr_wb_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__lsu_resp_valid_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__lsu_resp_err_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__instr_done_wb_o = VL_RAND_RESET_I(1);
    for (int __Vi0 = 0; __Vi0 < 2; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__rf_wdata_wb_mux[__Vi0] = VL_RAND_RESET_I(32);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__rf_wdata_wb_mux_we = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__fcov_wb_valid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__unused_fcov_wb_valid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__g_bypass_wb__DOT__unused_clk = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__g_bypass_wb__DOT__unused_rst = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__g_bypass_wb__DOT__unused_instr_type_wb = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__g_bypass_wb__DOT__unused_pc_id = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__g_bypass_wb__DOT__unused_dummy_instr_id = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__hart_id_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__priv_mode_id_o = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__priv_mode_lsu_o = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_mstatus_tw_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_mtvec_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_mtvec_init_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__boot_addr_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_access_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_addr_i = VL_RAND_RESET_I(12);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_wdata_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_op_i = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_op_en_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__irq_software_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__irq_timer_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__irq_external_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__irq_fast_i = VL_RAND_RESET_I(15);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__nmi_mode_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__irq_pending_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__irqs_o = VL_RAND_RESET_I(18);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_mstatus_mie_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_mepc_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_mtval_o = VL_RAND_RESET_I(32);
    for (int __Vi0 = 0; __Vi0 < 4; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_pmp_cfg_o[__Vi0] = VL_RAND_RESET_I(6);
    }
    for (int __Vi0 = 0; __Vi0 < 4; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_pmp_addr_o[__Vi0] = VL_RAND_RESET_Q(34);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_pmp_mseccfg_o = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__debug_mode_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__debug_mode_entering_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__debug_cause_i = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__debug_csr_save_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_depc_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__debug_single_step_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__debug_ebreakm_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__debug_ebreaku_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__trigger_match_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pc_if_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pc_id_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pc_wb_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__data_ind_timing_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dummy_instr_en_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dummy_instr_mask_o = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dummy_instr_seed_en_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dummy_instr_seed_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__icache_enable_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_shadow_err_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__ic_scr_key_valid_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_save_if_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_save_id_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_save_wb_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_restore_mret_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_restore_dret_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_save_cause_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_mcause_i = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_mtval_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr_insn_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__double_fault_seen_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__instr_ret_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__instr_ret_compressed_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__instr_ret_spec_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__instr_ret_compressed_spec_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__iside_wait_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__jump_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__branch_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__branch_taken_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mem_load_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mem_store_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dside_wait_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mul_wait_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__div_wait_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__exception_pc = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__priv_lvl_q = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__priv_lvl_d = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mstatus_q = VL_RAND_RESET_I(6);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mstatus_d = VL_RAND_RESET_I(6);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mstatus_err = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mstatus_en = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mie_q = VL_RAND_RESET_I(18);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mie_d = VL_RAND_RESET_I(18);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mie_en = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mscratch_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mscratch_en = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mepc_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mepc_d = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mepc_en = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcause_q = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcause_d = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcause_en = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mtval_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mtval_d = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mtval_en = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mtvec_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mtvec_d = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mtvec_err = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mtvec_en = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mip = VL_RAND_RESET_I(18);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dcsr_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dcsr_d = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dcsr_en = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__depc_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__depc_d = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__depc_en = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dscratch0_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dscratch1_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dscratch0_en = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dscratch1_en = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mstack_q = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mstack_d = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mstack_en = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mstack_epc_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mstack_epc_d = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mstack_cause_q = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mstack_cause_d = VL_RAND_RESET_I(7);
    for (int __Vi0 = 0; __Vi0 < 16; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_addr_rdata[__Vi0] = VL_RAND_RESET_I(32);
    }
    for (int __Vi0 = 0; __Vi0 < 16; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_cfg_rdata[__Vi0] = VL_RAND_RESET_I(8);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_csr_err = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_mseccfg = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcountinhibit = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcountinhibit_d = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcountinhibit_q = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcountinhibit_we = VL_RAND_RESET_I(1);
    for (int __Vi0 = 0; __Vi0 < 32; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter[__Vi0] = VL_RAND_RESET_Q(64);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_incr = VL_RAND_RESET_I(32);
    for (int __Vi0 = 0; __Vi0 < 32; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmevent[__Vi0] = VL_RAND_RESET_I(32);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__unused_mhpmcounter_we_1 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__unused_mhpmcounterh_we_1 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__unused_mhpmcounter_incr_1 = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_next = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_raw = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__tselect_rdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__tmatch_control_rdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__tmatch_value_rdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__cpuctrlsts_part_q = VL_RAND_RESET_I(8);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__cpuctrlsts_part_d = VL_RAND_RESET_I(8);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__cpuctrlsts_part_wdata_raw = VL_RAND_RESET_I(8);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__cpuctrlsts_part_wdata = VL_RAND_RESET_I(8);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__cpuctrlsts_part_we = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__cpuctrlsts_part_err = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__cpuctrlsts_ic_scr_key_valid_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__cpuctrlsts_ic_scr_key_err = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_wdata_int = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_we_int = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_wr = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dbg_csr = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr_priv = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr_dbg = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr_write = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__unused_boot_addr = VL_RAND_RESET_I(8);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__unused_csr_addr = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_addr = VL_RAND_RESET_I(12);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__gen_mhpmcounter_incr__DOT__unnamedblk1__DOT__i = 0;
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__gen_mhpmevent__DOT__unnamedblk2__DOT__i = 0;
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__gen_mhpmevent__DOT__unnamedblk3__DOT__i = 0;
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__gen_cntrs__BRA__7__KET____DOT__gen_unimp__DOT__gen_no_compressed_instr_cnt__DOT__unused_instr_ret_compressed_spec_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__g_mcountinhibit_reduced__DOT__unused_mhphcounter_we = VL_RAND_RESET_I(29);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__g_mcountinhibit_reduced__DOT__unused_mhphcounterh_we = VL_RAND_RESET_I(29);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__g_mcountinhibit_reduced__DOT__unused_mhphcounter_incr = VL_RAND_RESET_I(29);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__gen_no_dit__DOT__unused_dit = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__gen_no_dummy__DOT__unused_dummy_en = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__gen_no_dummy__DOT__unused_dummy_mask = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__gen_no_icache__DOT__unused_icen = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__gen_no_icache__DOT__unused_ic_scr_key_valid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstatus_csr__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstatus_csr__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstatus_csr__DOT__wr_data_i = VL_RAND_RESET_I(6);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstatus_csr__DOT__wr_en_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstatus_csr__DOT__rd_data_o = VL_RAND_RESET_I(6);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstatus_csr__DOT__rd_error_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstatus_csr__DOT__rdata_q = VL_RAND_RESET_I(6);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mepc_csr__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mepc_csr__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mepc_csr__DOT__wr_data_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mepc_csr__DOT__wr_en_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mepc_csr__DOT__rd_data_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mepc_csr__DOT__rd_error_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mepc_csr__DOT__rdata_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mie_csr__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mie_csr__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mie_csr__DOT__wr_data_i = VL_RAND_RESET_I(18);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mie_csr__DOT__wr_en_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mie_csr__DOT__rd_data_o = VL_RAND_RESET_I(18);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mie_csr__DOT__rd_error_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mie_csr__DOT__rdata_q = VL_RAND_RESET_I(18);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mscratch_csr__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mscratch_csr__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mscratch_csr__DOT__wr_data_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mscratch_csr__DOT__wr_en_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mscratch_csr__DOT__rd_data_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mscratch_csr__DOT__rd_error_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mscratch_csr__DOT__rdata_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mcause_csr__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mcause_csr__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mcause_csr__DOT__wr_data_i = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mcause_csr__DOT__wr_en_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mcause_csr__DOT__rd_data_o = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mcause_csr__DOT__rd_error_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mcause_csr__DOT__rdata_q = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtval_csr__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtval_csr__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtval_csr__DOT__wr_data_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtval_csr__DOT__wr_en_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtval_csr__DOT__rd_data_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtval_csr__DOT__rd_error_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtval_csr__DOT__rdata_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtvec_csr__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtvec_csr__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtvec_csr__DOT__wr_data_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtvec_csr__DOT__wr_en_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtvec_csr__DOT__rd_data_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtvec_csr__DOT__rd_error_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtvec_csr__DOT__rdata_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dcsr_csr__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dcsr_csr__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dcsr_csr__DOT__wr_data_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dcsr_csr__DOT__wr_en_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dcsr_csr__DOT__rd_data_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dcsr_csr__DOT__rd_error_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dcsr_csr__DOT__rdata_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_depc_csr__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_depc_csr__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_depc_csr__DOT__wr_data_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_depc_csr__DOT__wr_en_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_depc_csr__DOT__rd_data_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_depc_csr__DOT__rd_error_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_depc_csr__DOT__rdata_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch0_csr__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch0_csr__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch0_csr__DOT__wr_data_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch0_csr__DOT__wr_en_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch0_csr__DOT__rd_data_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch0_csr__DOT__rd_error_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch0_csr__DOT__rdata_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch1_csr__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch1_csr__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch1_csr__DOT__wr_data_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch1_csr__DOT__wr_en_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch1_csr__DOT__rd_data_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch1_csr__DOT__rd_error_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch1_csr__DOT__rdata_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_csr__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_csr__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_csr__DOT__wr_data_i = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_csr__DOT__wr_en_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_csr__DOT__rd_data_o = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_csr__DOT__rd_error_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_csr__DOT__rdata_q = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_epc_csr__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_epc_csr__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_epc_csr__DOT__wr_data_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_epc_csr__DOT__wr_en_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_epc_csr__DOT__rd_data_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_epc_csr__DOT__rd_error_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_epc_csr__DOT__rdata_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_cause_csr__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_cause_csr__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_cause_csr__DOT__wr_data_i = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_cause_csr__DOT__wr_en_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_cause_csr__DOT__rd_data_o = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_cause_csr__DOT__rd_error_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_cause_csr__DOT__rdata_q = VL_RAND_RESET_I(7);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__counter_inc_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__counterh_we_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__counter_we_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__counter_val_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__counter_val_o = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__counter_val_upd_o = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__counter = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__counter_upd = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__counter_load = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__we = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__counter_d = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__counter_q = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counter_inc_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counterh_we_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counter_we_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counter_val_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counter_val_o = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counter_val_upd_o = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counter = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counter_upd = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counter_load = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__we = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counter_d = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counter_q = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_cpuctrlsts_part_csr__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_cpuctrlsts_part_csr__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_cpuctrlsts_part_csr__DOT__wr_data_i = VL_RAND_RESET_I(8);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_cpuctrlsts_part_csr__DOT__wr_en_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_cpuctrlsts_part_csr__DOT__rd_data_o = VL_RAND_RESET_I(8);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_cpuctrlsts_part_csr__DOT__rd_error_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_cpuctrlsts_part_csr__DOT__rdata_q = VL_RAND_RESET_I(8);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__test_en_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__dummy_instr_id_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__dummy_instr_wb_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__raddr_a_i = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rdata_a_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__raddr_b_i = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rdata_b_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__waddr_a_i = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__wdata_a_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__err_o = VL_RAND_RESET_I(1);
    for (int __Vi0 = 0; __Vi0 < 32; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[__Vi0] = VL_RAND_RESET_I(32);
    }
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__oh_raddr_a_err = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__oh_raddr_b_err = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__oh_we_err = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__unused_test_en = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_decoder__DOT__unnamedblk1__DOT__i = 0;
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__gen_no_wren_check__DOT__unused_strobe = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__1__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__2__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__3__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__4__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__5__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__6__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__7__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__8__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__9__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__10__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__11__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__12__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__13__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__14__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__15__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__16__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__17__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__18__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__19__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__20__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__21__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__22__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__23__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__24__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__25__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__26__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__27__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__28__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__29__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__30__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__31__KET____DOT__rf_reg_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_normal_r0__DOT__unused_dummy_instr = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__hart_id_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_valid = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_order = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_insn = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_trap = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_halt = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_intr = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_mode = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_ixl = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_rs1_addr = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_rs2_addr = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_rs3_addr = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_rs1_rdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_rs2_rdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_rs3_rdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_rd_addr = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_rd_wdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_pc_rdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_pc_wdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_mem_addr = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_mem_rmask = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_mem_wmask = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_mem_rdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_mem_wdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__unused_rvfi_order = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__unused_rvfi_trap = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__unused_rvfi_halt = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__unused_rvfi_intr = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__unused_rvfi_mode = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__unused_rvfi_ixl = VL_RAND_RESET_I(2);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__file_handle = 0;
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__cycle = 0;
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__insn_is_compressed = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__data_accessed = VL_RAND_RESET_I(5);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__trace_log_enable = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__unnamedblk1__DOT__fh = 0;
    vlSelf->ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__unnamedblk2__DOT__fh = 0;
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__a_req_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__a_we_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__a_be_i = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__a_addr_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__a_wdata_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__a_rvalid_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__a_rdata_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__b_req_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__b_we_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__b_be_i = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__b_addr_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__b_wdata_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__b_rvalid_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__b_rdata_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__a_addr_idx = VL_RAND_RESET_I(18);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__unused_a_addr_parts = VL_RAND_RESET_I(14);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__b_addr_idx = VL_RAND_RESET_I(18);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__unused_b_addr_parts = VL_RAND_RESET_I(14);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__a_wmask = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__b_wmask = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__unnamedblk1__DOT__i = 0;
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__clk_a_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__clk_b_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__a_req_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__a_write_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__a_addr_i = VL_RAND_RESET_I(18);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__a_wdata_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__a_wmask_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__a_rdata_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__b_req_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__b_write_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__b_addr_i = VL_RAND_RESET_I(18);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__b_wdata_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__b_wmask_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__b_rdata_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__cfg_i = VL_RAND_RESET_I(20);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__clk_a_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__clk_b_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__a_req_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__a_write_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__a_addr_i = VL_RAND_RESET_I(18);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__a_wdata_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__a_wmask_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__a_rdata_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__b_req_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__b_write_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__b_addr_i = VL_RAND_RESET_I(18);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__b_wdata_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__b_wmask_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__b_rdata_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__cfg_i = VL_RAND_RESET_I(20);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__unused_cfg = VL_RAND_RESET_I(1);
    for (int __Vi0 = 0; __Vi0 < 262144; ++__Vi0) {
        vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__mem[__Vi0] = VL_RAND_RESET_I(32);
    }
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__a_wmask = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__b_wmask = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__simutil_set_mem__Vstatic__valid = 0;
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__simutil_get_mem__Vstatic__valid = 0;
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__unnamedblk1__DOT__i = 0;
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__unnamedblk2__DOT__i = 0;
    vlSelf->ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__unnamedblk3__DOT__show_mem_paths = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_simulator_ctrl__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_simulator_ctrl__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_simulator_ctrl__DOT__req_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_simulator_ctrl__DOT__we_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_simulator_ctrl__DOT__be_i = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_simulator_ctrl__DOT__addr_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_simulator_ctrl__DOT__wdata_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_simulator_ctrl__DOT__rvalid_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_simulator_ctrl__DOT__rdata_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_simulator_ctrl__DOT__ctrl_addr = VL_RAND_RESET_I(8);
    vlSelf->ibex_simple_system__DOT__u_simulator_ctrl__DOT__sim_finish = VL_RAND_RESET_I(3);
    vlSelf->ibex_simple_system__DOT__u_simulator_ctrl__DOT__log_fd = 0;
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__clk_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__rst_ni = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__timer_req_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__timer_addr_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__timer_we_i = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__timer_be_i = VL_RAND_RESET_I(4);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__timer_wdata_i = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__timer_rvalid_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__timer_rdata_o = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__timer_err_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__timer_intr_o = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__timer_we = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__mtime_we = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__mtimeh_we = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__mtimecmp_we = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__mtimecmph_we = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__mtime_wdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__mtimeh_wdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__mtimecmp_wdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__mtimecmph_wdata = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__mtime_q = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__mtime_d = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__mtime_inc = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__mtimecmp_q = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__mtimecmp_d = VL_RAND_RESET_Q(64);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__interrupt_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__interrupt_d = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__error_q = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__error_d = VL_RAND_RESET_I(1);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__rdata_q = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__rdata_d = VL_RAND_RESET_I(32);
    vlSelf->ibex_simple_system__DOT__u_timer__DOT__rvalid_q = VL_RAND_RESET_I(1);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_cb_insn__11__imm = VL_RAND_RESET_I(8);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_cb_insn__11__jump_target = VL_RAND_RESET_I(32);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_compressed_store_insn__14__imm = VL_RAND_RESET_I(8);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_cb_insn__15__imm = VL_RAND_RESET_I(8);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_cb_insn__15__jump_target = VL_RAND_RESET_I(32);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_compressed_store_insn__16__imm = VL_RAND_RESET_I(8);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_cb_insn__22__imm = VL_RAND_RESET_I(8);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_cb_insn__22__jump_target = VL_RAND_RESET_I(32);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_cb_sr_insn__25__shamt = VL_RAND_RESET_I(6);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_cb_sr_insn__28__shamt = VL_RAND_RESET_I(6);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_cb_insn__43__imm = VL_RAND_RESET_I(8);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_cb_insn__43__jump_target = VL_RAND_RESET_I(32);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_cb_sr_insn__46__shamt = VL_RAND_RESET_I(6);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_cb_sr_insn__49__shamt = VL_RAND_RESET_I(6);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_ci_caddi16sp_insn__52__nzimm = VL_RAND_RESET_I(10);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_ci_clui_insn__53__nzimm = VL_RAND_RESET_I(6);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_compressed_load_insn__56__imm = VL_RAND_RESET_I(8);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_ci_cli_insn__57__imm = VL_RAND_RESET_I(6);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_compressed_load_insn__58__imm = VL_RAND_RESET_I(8);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_ci_cslli_insn__63__shamt = VL_RAND_RESET_I(6);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_ci_caddi_insn__64__nzimm = VL_RAND_RESET_I(6);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_ciw_insn__66__nzuimm = VL_RAND_RESET_I(10);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_b_insn__71__branch_target = VL_RAND_RESET_I(32);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_b_insn__71__imm = VL_RAND_RESET_I(32);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_b_insn__72__branch_target = VL_RAND_RESET_I(32);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_b_insn__72__imm = VL_RAND_RESET_I(32);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_b_insn__73__branch_target = VL_RAND_RESET_I(32);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_b_insn__73__imm = VL_RAND_RESET_I(32);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_b_insn__74__branch_target = VL_RAND_RESET_I(32);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_b_insn__74__imm = VL_RAND_RESET_I(32);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_b_insn__75__branch_target = VL_RAND_RESET_I(32);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_b_insn__75__imm = VL_RAND_RESET_I(32);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_b_insn__76__branch_target = VL_RAND_RESET_I(32);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_b_insn__76__imm = VL_RAND_RESET_I(32);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_i_shift_insn__84__shamt = VL_RAND_RESET_I(5);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_i_shift_insn__85__shamt = VL_RAND_RESET_I(5);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_i_shift_insn__86__shamt = VL_RAND_RESET_I(5);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_csr_insn__97__csr = VL_RAND_RESET_I(12);
    vlSelf->__Vfunc_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__get_csr_name__98__csr_addr = VL_RAND_RESET_I(12);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_csr_insn__99__csr = VL_RAND_RESET_I(12);
    vlSelf->__Vfunc_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__get_csr_name__100__csr_addr = VL_RAND_RESET_I(12);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_csr_insn__101__csr = VL_RAND_RESET_I(12);
    vlSelf->__Vfunc_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__get_csr_name__102__csr_addr = VL_RAND_RESET_I(12);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_csr_insn__103__csr = VL_RAND_RESET_I(12);
    vlSelf->__Vfunc_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__get_csr_name__104__csr_addr = VL_RAND_RESET_I(12);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_csr_insn__105__csr = VL_RAND_RESET_I(12);
    vlSelf->__Vfunc_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__get_csr_name__106__csr_addr = VL_RAND_RESET_I(12);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_csr_insn__107__csr = VL_RAND_RESET_I(12);
    vlSelf->__Vfunc_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__get_csr_name__108__csr_addr = VL_RAND_RESET_I(12);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_load_insn__122__size = VL_RAND_RESET_I(3);
    vlSelf->__Vfunc_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__get_fence_description__128__bits = VL_RAND_RESET_I(4);
    vlSelf->__Vfunc_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__get_fence_description__129__bits = VL_RAND_RESET_I(4);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_i_shift_insn__134__shamt = VL_RAND_RESET_I(5);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_i_shift_insn__152__shamt = VL_RAND_RESET_I(5);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_i_shift_insn__153__shamt = VL_RAND_RESET_I(5);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_i_shift_insn__154__shamt = VL_RAND_RESET_I(5);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_i_shift_insn__155__shamt = VL_RAND_RESET_I(5);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_i_shift_insn__225__shamt = VL_RAND_RESET_I(5);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_i_shift_insn__226__shamt = VL_RAND_RESET_I(5);
    vlSelf->__Vtask_ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__decode_i_funnelshift_insn__231__shamt = VL_RAND_RESET_I(6);
    vlSelf->__Vdpi_export_trigger = 0;
    vlSelf->__Vdly__ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__cycle = 0;
    vlSelf->__Vtrigprevexpr___TOP__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_executing_spec__0 = VL_RAND_RESET_I(1);
    vlSelf->__Vtrigprevexpr___TOP__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__en_wb__0 = VL_RAND_RESET_I(1);
    vlSelf->__Vtrigprevexpr___TOP__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__id_in_ready_o__0 = VL_RAND_RESET_I(1);
    vlSelf->__VstlDidInit = 0;
    vlSelf->__Vtrigprevexpr___TOP__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_executing_spec__1 = VL_RAND_RESET_I(1);
    vlSelf->__Vtrigprevexpr___TOP__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__en_wb__1 = VL_RAND_RESET_I(1);
    vlSelf->__Vtrigprevexpr___TOP__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__id_in_ready_o__1 = VL_RAND_RESET_I(1);
    vlSelf->__VicoDidInit = 0;
    vlSelf->__Vtrigprevexpr___TOP__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_executing_spec__2 = VL_RAND_RESET_I(1);
    vlSelf->__Vtrigprevexpr___TOP__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__en_wb__2 = VL_RAND_RESET_I(1);
    vlSelf->__Vtrigprevexpr___TOP__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__id_in_ready_o__2 = VL_RAND_RESET_I(1);
    vlSelf->__Vtrigprevexpr___TOP__ibex_simple_system__DOT__clk_sys__0 = VL_RAND_RESET_I(1);
    vlSelf->__Vtrigprevexpr___TOP__ibex_simple_system__DOT__rst_sys_n__0 = VL_RAND_RESET_I(1);
    vlSelf->__Vtrigprevexpr___TOP__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__clk__0 = VL_RAND_RESET_I(1);
    vlSelf->__VactDidInit = 0;
}
