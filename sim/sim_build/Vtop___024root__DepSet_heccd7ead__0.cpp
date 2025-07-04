// Verilated -*- C++ -*-
// DESCRIPTION: Verilator output: Design implementation internals
// See Vtop.h for the primary calling header

#include "Vtop__pch.h"
#include "Vtop___024root.h"

void Vtop___024root___ico_sequent__TOP__0(Vtop___024root* vlSelf);
void Vtop___024root___ico_sequent__TOP__1(Vtop___024root* vlSelf);
void Vtop___024root___ico_comb__TOP__0(Vtop___024root* vlSelf);
void Vtop___024root___ico_comb__TOP__1(Vtop___024root* vlSelf);
void Vtop___024root___ico_comb__TOP__2(Vtop___024root* vlSelf);

void Vtop___024root___eval_ico(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___eval_ico\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Body
    if ((1ULL & vlSelfRef.__VicoTriggered.word(0U))) {
        Vtop___024root___ico_sequent__TOP__0(vlSelf);
        Vtop___024root___ico_sequent__TOP__1(vlSelf);
    }
    if ((0xdULL & vlSelfRef.__VicoTriggered.word(0U))) {
        Vtop___024root___ico_comb__TOP__0(vlSelf);
    }
    if ((5ULL & vlSelfRef.__VicoTriggered.word(0U))) {
        Vtop___024root___ico_comb__TOP__1(vlSelf);
    }
    if ((0x1dULL & vlSelfRef.__VicoTriggered.word(0U))) {
        Vtop___024root___ico_comb__TOP__2(vlSelf);
    }
}

VL_INLINE_OPT void Vtop___024root___ico_comb__TOP__0(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___ico_comb__TOP__0\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Body
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_op_en 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__csr_access_o) 
           & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_executing_spec) 
              & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__en_wb)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_op_en_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_op_en;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__csr_op_en_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_op_en;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__csr_pipe_flush 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_op_en) 
           & ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__no_flush_csr_addr)) 
              & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_wr)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_we_int 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_wr) 
           & ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__illegal_csr_insn_id)) 
              & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_op_en)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__fcov_csr_read_only 
        = ((0U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__csr_op_o)) 
           & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__csr_access_o) 
              & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_op_en) 
                 | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__illegal_insn_o))));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__fcov_csr_write 
        = (((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_wr) 
            & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_access)) 
           & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_op_en) 
              | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__illegal_insn_id)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__csr_pipe_flush_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__csr_pipe_flush;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__csr_pipe_flush 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__csr_pipe_flush) 
           & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_valid_id_q));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mscratch_en = 0U;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dscratch0_en = 0U;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dscratch1_en = 0U;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mie_en = 0U;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcountinhibit_we = 0U;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we = 0U;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we = 0U;
    if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_we_int) {
        if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                      >> 0xbU)))) {
            if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                          >> 0xaU)))) {
                if ((0x200U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    if ((0x100U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                        if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                      >> 7U)))) {
                            if ((0x40U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                              >> 5U)))) {
                                    if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                  >> 4U)))) {
                                        if ((1U & (~ 
                                                   ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                    >> 3U)))) {
                                            if ((1U 
                                                 & (~ 
                                                    ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                     >> 2U)))) {
                                                if (
                                                    (1U 
                                                     & (~ 
                                                        ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                         >> 1U)))) {
                                                    if (
                                                        (1U 
                                                         & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)))) {
                                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mscratch_en = 1U;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                          >> 6U)))) {
                                if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                              >> 5U)))) {
                                    if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                  >> 4U)))) {
                                        if ((1U & (~ 
                                                   ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                    >> 3U)))) {
                                            if ((4U 
                                                 & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                                if (
                                                    (1U 
                                                     & (~ 
                                                        ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                         >> 1U)))) {
                                                    if (
                                                        (1U 
                                                         & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)))) {
                                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mie_en = 1U;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                if ((0x20U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                    if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                  >> 4U)))) {
                                        if ((1U & (~ 
                                                   ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                    >> 3U)))) {
                                            if ((1U 
                                                 & (~ 
                                                    ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                     >> 2U)))) {
                                                if (
                                                    (1U 
                                                     & (~ 
                                                        ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                         >> 1U)))) {
                                                    if (
                                                        (1U 
                                                         & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)))) {
                                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcountinhibit_we = 1U;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if ((0x400U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                if ((0x200U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    if ((0x100U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                        if ((0x80U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                            if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                          >> 6U)))) {
                                if ((0x20U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                    if ((0x10U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                        if ((1U & (~ 
                                                   ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                    >> 3U)))) {
                                            if ((1U 
                                                 & (~ 
                                                    ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                     >> 2U)))) {
                                                if (
                                                    (2U 
                                                     & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                                    if (
                                                        (1U 
                                                         & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)))) {
                                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dscratch0_en = 1U;
                                                    }
                                                    if (
                                                        (1U 
                                                         & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dscratch1_en = 1U;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if ((0x800U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
            if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                          >> 0xaU)))) {
                if ((0x200U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    if ((0x100U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                        if ((0x80U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                            if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                          >> 6U)))) {
                                if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                              >> 5U)))) {
                                    if ((0x10U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we 
                                            = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we 
                                               | (0xffffffffULL 
                                                  & ((IData)(1U) 
                                                     << (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx))));
                                    } else if ((8U 
                                                & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we 
                                            = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we 
                                               | (0xffffffffULL 
                                                  & ((IData)(1U) 
                                                     << (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx))));
                                    } else if ((4U 
                                                & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we 
                                            = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we 
                                               | (0xffffffffULL 
                                                  & ((IData)(1U) 
                                                     << (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx))));
                                    } else if ((2U 
                                                & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we 
                                            = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we 
                                               | (0xffffffffULL 
                                                  & ((IData)(1U) 
                                                     << (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx))));
                                    } else if ((1U 
                                                & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)))) {
                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we 
                                            = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we 
                                               | (0xffffffffULL 
                                                  & ((IData)(1U) 
                                                     << (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx))));
                                    }
                                }
                            }
                        }
                        if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                      >> 7U)))) {
                            if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                          >> 6U)))) {
                                if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                              >> 5U)))) {
                                    if ((0x10U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we 
                                            = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we 
                                               | (0xffffffffULL 
                                                  & ((IData)(1U) 
                                                     << (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx))));
                                    } else if ((8U 
                                                & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we 
                                            = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we 
                                               | (0xffffffffULL 
                                                  & ((IData)(1U) 
                                                     << (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx))));
                                    } else if ((4U 
                                                & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we 
                                            = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we 
                                               | (0xffffffffULL 
                                                  & ((IData)(1U) 
                                                     << (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx))));
                                    } else if ((2U 
                                                & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we 
                                            = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we 
                                               | (0xffffffffULL 
                                                  & ((IData)(1U) 
                                                     << (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx))));
                                    } else if ((1U 
                                                & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)))) {
                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we 
                                            = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we 
                                               | (0xffffffffULL 
                                                  & ((IData)(1U) 
                                                     << (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx))));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__unused_fcov_csr_read_only 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__fcov_csr_read_only;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__unused_fcov_csr_write 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__fcov_csr_write;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__special_req_flush_only 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__wfi_insn) 
           | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__csr_pipe_flush));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mscratch_csr__DOT__wr_en_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mscratch_en;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch0_csr__DOT__wr_en_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dscratch0_en;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch1_csr__DOT__wr_en_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dscratch1_en;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mie_csr__DOT__wr_en_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mie_en;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcountinhibit_d 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcountinhibit_we)
            ? (((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__gen_no_dummy__DOT__unused_dummy_en) 
                << 2U) | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__gen_no_icache__DOT__unused_icen))
            : (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcountinhibit_q));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__counterh_we_i 
        = (1U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we 
                 >> 0U));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counterh_we_i 
        = (1U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we 
                 >> 2U));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__unused_mhpmcounterh_we_1 
        = (1U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we 
                 >> 1U));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__g_mcountinhibit_reduced__DOT__unused_mhphcounterh_we 
        = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we 
           >> 3U);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__counter_we_i 
        = (1U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we 
                 >> 0U));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counter_we_i 
        = (1U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we 
                 >> 2U));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__unused_mhpmcounter_we_1 
        = (1U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we 
                 >> 1U));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__g_mcountinhibit_reduced__DOT__unused_mhphcounter_we 
        = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we 
           >> 3U);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__special_req 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__special_req_pc_change) 
           | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__special_req_flush_only));
}

void Vtop___024root___eval_triggers__ico(Vtop___024root* vlSelf);

bool Vtop___024root___eval_phase__ico(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___eval_phase__ico\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Init
    CData/*0:0*/ __VicoExecute;
    // Body
    Vtop___024root___eval_triggers__ico(vlSelf);
    __VicoExecute = vlSelfRef.__VicoTriggered.any();
    if (__VicoExecute) {
        Vtop___024root___eval_ico(vlSelf);
    }
    return (__VicoExecute);
}

void Vtop___024root___eval_act(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___eval_act\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Body
    if ((6ULL & vlSelfRef.__VactTriggered.word(0U))) {
        Vtop___024root___ico_comb__TOP__0(vlSelf);
    }
    if ((2ULL & vlSelfRef.__VactTriggered.word(0U))) {
        Vtop___024root___ico_comb__TOP__1(vlSelf);
    }
    if ((0xeULL & vlSelfRef.__VactTriggered.word(0U))) {
        Vtop___024root___ico_comb__TOP__2(vlSelf);
    }
}

void Vtop___024root___nba_sequent__TOP__0(Vtop___024root* vlSelf);
void Vtop___024root___nba_sequent__TOP__1(Vtop___024root* vlSelf);
void Vtop___024root___nba_sequent__TOP__2(Vtop___024root* vlSelf);
void Vtop___024root___nba_sequent__TOP__3(Vtop___024root* vlSelf);
void Vtop___024root___nba_sequent__TOP__4(Vtop___024root* vlSelf);
void Vtop___024root___nba_comb__TOP__0(Vtop___024root* vlSelf);
void Vtop___024root___nba_sequent__TOP__5(Vtop___024root* vlSelf);
void Vtop___024root___nba_sequent__TOP__6(Vtop___024root* vlSelf);
void Vtop___024root___nba_sequent__TOP__7(Vtop___024root* vlSelf);
void Vtop___024root___nba_comb__TOP__1(Vtop___024root* vlSelf);
void Vtop___024root___nba_comb__TOP__2(Vtop___024root* vlSelf);
void Vtop___024root___nba_comb__TOP__3(Vtop___024root* vlSelf);
void Vtop___024root___nba_comb__TOP__4(Vtop___024root* vlSelf);
void Vtop___024root___nba_comb__TOP__6(Vtop___024root* vlSelf);

void Vtop___024root___eval_nba(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___eval_nba\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Body
    if ((0x30ULL & vlSelfRef.__VnbaTriggered.word(0U))) {
        Vtop___024root___nba_sequent__TOP__0(vlSelf);
    }
    if ((0x60ULL & vlSelfRef.__VnbaTriggered.word(0U))) {
        Vtop___024root___nba_sequent__TOP__1(vlSelf);
    }
    if ((0x10ULL & vlSelfRef.__VnbaTriggered.word(0U))) {
        Vtop___024root___nba_sequent__TOP__2(vlSelf);
    }
    if ((0x80ULL & vlSelfRef.__VnbaTriggered.word(0U))) {
        Vtop___024root___nba_sequent__TOP__3(vlSelf);
    }
    if ((0x40ULL & vlSelfRef.__VnbaTriggered.word(0U))) {
        Vtop___024root___nba_sequent__TOP__4(vlSelf);
    }
    if ((0x70ULL & vlSelfRef.__VnbaTriggered.word(0U))) {
        Vtop___024root___nba_comb__TOP__0(vlSelf);
    }
    if ((0x30ULL & vlSelfRef.__VnbaTriggered.word(0U))) {
        Vtop___024root___nba_sequent__TOP__5(vlSelf);
    }
    if ((0x60ULL & vlSelfRef.__VnbaTriggered.word(0U))) {
        Vtop___024root___nba_sequent__TOP__6(vlSelf);
        Vtop___024root___nba_sequent__TOP__7(vlSelf);
    }
    if ((0x30ULL & vlSelfRef.__VnbaTriggered.word(0U))) {
        Vtop___024root___nba_comb__TOP__1(vlSelf);
    }
    if ((0x60ULL & vlSelfRef.__VnbaTriggered.word(0U))) {
        Vtop___024root___nba_comb__TOP__2(vlSelf);
    }
    if ((0x70ULL & vlSelfRef.__VnbaTriggered.word(0U))) {
        Vtop___024root___nba_comb__TOP__3(vlSelf);
    }
    if ((0x66ULL & vlSelfRef.__VnbaTriggered.word(0U))) {
        Vtop___024root___nba_comb__TOP__4(vlSelf);
    }
    if ((0x72ULL & vlSelfRef.__VnbaTriggered.word(0U))) {
        Vtop___024root___ico_comb__TOP__1(vlSelf);
    }
    if ((0x76ULL & vlSelfRef.__VnbaTriggered.word(0U))) {
        Vtop___024root___nba_comb__TOP__6(vlSelf);
    }
    if ((0x7eULL & vlSelfRef.__VnbaTriggered.word(0U))) {
        Vtop___024root___ico_comb__TOP__2(vlSelf);
    }
}

VL_INLINE_OPT void Vtop___024root___nba_sequent__TOP__0(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___nba_sequent__TOP__0\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Init
    CData/*2:0*/ __Vdly__ibex_simple_system__DOT__u_simulator_ctrl__DOT__sim_finish;
    __Vdly__ibex_simple_system__DOT__u_simulator_ctrl__DOT__sim_finish = 0;
    // Body
    vlSelfRef.__Vdly__ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__cycle 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__cycle;
    __Vdly__ibex_simple_system__DOT__u_simulator_ctrl__DOT__sim_finish 
        = vlSelfRef.ibex_simple_system__DOT__u_simulator_ctrl__DOT__sim_finish;
    vlSelfRef.ibex_simple_system__DOT__u_ram__DOT__b_rvalid_o 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && (IData)(vlSelfRef.ibex_simple_system__DOT__instr_req));
    vlSelfRef.ibex_simple_system__DOT__u_timer__DOT__interrupt_q 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && (IData)(vlSelfRef.ibex_simple_system__DOT__u_timer__DOT__interrupt_d));
    vlSelfRef.ibex_simple_system__DOT__u_ram__DOT__a_rvalid_o 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && vlSelfRef.ibex_simple_system__DOT__device_req
           [0U]);
    vlSelfRef.ibex_simple_system__DOT__u_timer__DOT__rvalid_q 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && vlSelfRef.ibex_simple_system__DOT__device_req
           [2U]);
    if (vlSelfRef.ibex_simple_system__DOT__rst_sys_n) {
        vlSelfRef.__Vdly__ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__cycle 
            = ((IData)(1U) + vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__cycle);
        vlSelfRef.ibex_simple_system__DOT__u_timer__DOT__mtime_q 
            = vlSelfRef.ibex_simple_system__DOT__u_timer__DOT__mtime_d;
        if (((IData)(vlSelfRef.ibex_simple_system__DOT__u_timer__DOT__mtimecmp_we) 
             | (IData)(vlSelfRef.ibex_simple_system__DOT__u_timer__DOT__mtimecmph_we))) {
            vlSelfRef.ibex_simple_system__DOT__u_timer__DOT__mtimecmp_q 
                = vlSelfRef.ibex_simple_system__DOT__u_timer__DOT__mtimecmp_d;
        }
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__core_busy_q 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__core_busy_d;
    } else {
        vlSelfRef.__Vdly__ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__cycle = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_timer__DOT__mtime_q = 0ULL;
        vlSelfRef.ibex_simple_system__DOT__u_timer__DOT__mtimecmp_q = 0ULL;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__core_busy_q = 0xaU;
    }
    if (vlSelfRef.ibex_simple_system__DOT__rst_sys_n) {
        if ((vlSelfRef.ibex_simple_system__DOT__device_req
             [1U] & vlSelfRef.ibex_simple_system__DOT__device_we
             [1U])) {
            if ((0U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_simulator_ctrl__DOT__ctrl_addr))) {
                if (VL_UNLIKELY(((1U & vlSelfRef.ibex_simple_system__DOT__device_be
                                  [1U])))) {
                    VL_FWRITEF_NX(vlSelfRef.ibex_simple_system__DOT__u_simulator_ctrl__DOT__log_fd,"%c",0,
                                  8,(0xffU & vlSelfRef.ibex_simple_system__DOT__device_wdata
                                     [1U]));
                    if (vlSelfRef.ibex_simple_system__DOT__u_simulator_ctrl__DOT__log_fd) { VL_FFLUSH_I(vlSelfRef.ibex_simple_system__DOT__u_simulator_ctrl__DOT__log_fd); }
                }
            } else if ((2U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_simulator_ctrl__DOT__ctrl_addr))) {
                if (VL_UNLIKELY((((vlSelfRef.ibex_simple_system__DOT__device_be
                                   [1U] & vlSelfRef.ibex_simple_system__DOT__device_wdata
                                   [1U]) & (0U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_simulator_ctrl__DOT__sim_finish)))))) {
                    VL_WRITEF_NX("Terminating simulation by software request.\n",0);
                    __Vdly__ibex_simple_system__DOT__u_simulator_ctrl__DOT__sim_finish = 1U;
                }
            }
        }
        vlSelfRef.ibex_simple_system__DOT__u_simulator_ctrl__DOT__rvalid_o 
            = vlSelfRef.ibex_simple_system__DOT__device_req
            [1U];
    } else {
        vlSelfRef.ibex_simple_system__DOT__u_simulator_ctrl__DOT__rvalid_o = 0U;
        __Vdly__ibex_simple_system__DOT__u_simulator_ctrl__DOT__sim_finish = 0U;
    }
    if ((0U != (IData)(vlSelfRef.ibex_simple_system__DOT__u_simulator_ctrl__DOT__sim_finish))) {
        __Vdly__ibex_simple_system__DOT__u_simulator_ctrl__DOT__sim_finish 
            = (7U & ((IData)(1U) + (IData)(vlSelfRef.ibex_simple_system__DOT__u_simulator_ctrl__DOT__sim_finish)));
    }
    if (VL_UNLIKELY(((2U <= (IData)(vlSelfRef.ibex_simple_system__DOT__u_simulator_ctrl__DOT__sim_finish))))) {
        VL_FINISH_MT("../ibex/shared/rtl/sim/simulator_ctrl.sv", 93, "");
    }
    vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__device_sel_resp 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n)
            ? (IData)(vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__device_sel_req)
            : 0U);
    vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__decode_err_resp 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && ((IData)(vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__host_sel_valid) 
               & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__device_sel_valid))));
    vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__host_sel_resp 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && (IData)(vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__host_sel_req));
    vlSelfRef.ibex_simple_system__DOT__u_simulator_ctrl__DOT__sim_finish 
        = __Vdly__ibex_simple_system__DOT__u_simulator_ctrl__DOT__sim_finish;
    vlSelfRef.ibex_simple_system__DOT__u_timer__DOT__mtime_inc 
        = (1ULL + vlSelfRef.ibex_simple_system__DOT__u_timer__DOT__mtime_q);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__g_clock_en_non_secure__DOT__unused_core_busy 
        = (1U & VL_REDXOR_32((7U & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__core_busy_q) 
                                    >> 1U))));
    vlSelfRef.ibex_simple_system__DOT__instr_rvalid 
        = vlSelfRef.ibex_simple_system__DOT__u_ram__DOT__b_rvalid_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_intg_err 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_ram__DOT__b_rvalid_o) 
           & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_intg_err));
    vlSelfRef.ibex_simple_system__DOT__u_timer__DOT__timer_intr_o 
        = vlSelfRef.ibex_simple_system__DOT__u_timer__DOT__interrupt_q;
    vlSelfRef.ibex_simple_system__DOT__timer_irq = vlSelfRef.ibex_simple_system__DOT__u_timer__DOT__interrupt_q;
    vlSelfRef.ibex_simple_system__DOT__device_rvalid[0U] 
        = vlSelfRef.ibex_simple_system__DOT__u_ram__DOT__a_rvalid_o;
    vlSelfRef.ibex_simple_system__DOT__u_timer__DOT__timer_rvalid_o 
        = vlSelfRef.ibex_simple_system__DOT__u_timer__DOT__rvalid_q;
    vlSelfRef.ibex_simple_system__DOT__device_rvalid[2U] 
        = vlSelfRef.ibex_simple_system__DOT__u_timer__DOT__rvalid_q;
    vlSelfRef.ibex_simple_system__DOT__device_rvalid[1U] 
        = vlSelfRef.ibex_simple_system__DOT__u_simulator_ctrl__DOT__rvalid_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__instr_rvalid_i 
        = vlSelfRef.ibex_simple_system__DOT__instr_rvalid;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_intg_err_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_intg_err;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__irq_timer_i 
        = vlSelfRef.ibex_simple_system__DOT__timer_irq;
    vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__device_rvalid_i[0U] 
        = vlSelfRef.ibex_simple_system__DOT__device_rvalid
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__device_rvalid_i[1U] 
        = vlSelfRef.ibex_simple_system__DOT__device_rvalid
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__device_rvalid_i[2U] 
        = vlSelfRef.ibex_simple_system__DOT__device_rvalid
        [2U];
    if (vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__host_sel_resp) {
        vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__host_rvalid_o[0U] = 0U;
    } else {
        vlSelfRef.ibex_simple_system__DOT__u_bus__DOT____Vlvbound_h28d63177__0 
            = (((2U >= (IData)(vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__device_sel_resp)) 
                && vlSelfRef.ibex_simple_system__DOT__device_rvalid
                [vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__device_sel_resp]) 
               | (IData)(vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__decode_err_resp));
        vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__host_rvalid_o[0U] 
            = vlSelfRef.ibex_simple_system__DOT__u_bus__DOT____Vlvbound_h28d63177__0;
    }
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__instr_rvalid_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__instr_rvalid_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__irq_timer_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__irq_timer_i;
    vlSelfRef.ibex_simple_system__DOT__host_rvalid[0U] 
        = vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__host_rvalid_o
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_rvalid_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__instr_rvalid_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irq_timer_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__irq_timer_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__data_rvalid_i 
        = vlSelfRef.ibex_simple_system__DOT__host_rvalid
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT____VdfgRegularize_he001948a_0_3 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_intg_err) 
           & vlSelfRef.ibex_simple_system__DOT__host_rvalid
           [0U]);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rvalid_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_rvalid_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__irq_timer_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irq_timer_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rvalid_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__data_rvalid_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__instr_rvalid_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rvalid_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__data_rvalid_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rvalid_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_rvalid_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__data_rvalid_i;
}

VL_INLINE_OPT void Vtop___024root___nba_sequent__TOP__1(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___nba_sequent__TOP__1\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Init
    CData/*0:0*/ __Vdly__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_valid;
    __Vdly__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_valid = 0;
    CData/*0:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi__v1 = 0;
    IData/*17:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v1 = 0;
    CData/*0:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v1 = 0;
    CData/*0:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req__v1 = 0;
    CData/*0:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_irq_valid__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_irq_valid__v0 = 0;
    CData/*0:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_irq_valid__v1;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_irq_valid__v1 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wdata__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wdata__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wdata__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wdata__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wdata__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wdata__v1 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rdata__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rdata__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rdata__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rdata__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rdata__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rdata__v1 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_wdata__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_wdata__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_wdata__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_wdata__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_wdata__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_wdata__v1 = 0;
    CData/*4:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_addr__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_addr__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_addr__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_addr__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_addr__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_addr__v1 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_rdata__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_rdata__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_rdata__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_rdata__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_rdata__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_rdata__v1 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_rdata__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_rdata__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_rdata__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_rdata__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_rdata__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_rdata__v1 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v0 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v1;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v1 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v1 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v2;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v2 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v2;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v2 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v3;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v3 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v3;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v3 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v4;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v4 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v4;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v4 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v5;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v5 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v5;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v5 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v6;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v6 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v6;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v6 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v7;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v7 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v7;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v7 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v8;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v8 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v8;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v8 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v9;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v9 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v9;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v9 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v10;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v10 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_wdata__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_wdata__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_wdata__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_wdata__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_wdata__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_wdata__v1 = 0;
    IData/*17:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v2;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v2 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v2;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v2 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v3;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v3 = 0;
    CData/*0:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_ic_scr_key_valid__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_ic_scr_key_valid__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_ic_scr_key_valid__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_ic_scr_key_valid__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_ic_scr_key_valid__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_ic_scr_key_valid__v1 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_rdata__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_rdata__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_rdata__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_rdata__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_rdata__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_rdata__v1 = 0;
    CData/*0:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_intr__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_intr__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_intr__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_intr__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_intr__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_intr__v1 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_rdata__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_rdata__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_rdata__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_rdata__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_rdata__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_rdata__v1 = 0;
    QData/*63:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_order__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_order__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_order__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_order__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_order__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_order__v1 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_halt__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_halt__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_halt__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_halt__v1 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_addr__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_addr__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_addr__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_addr__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_addr__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_addr__v1 = 0;
    CData/*4:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_addr__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_addr__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_addr__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_addr__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_addr__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_addr__v1 = 0;
    CData/*0:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_trap__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_trap__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_trap__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_trap__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_trap__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_trap__v1 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_insn__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_insn__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_insn__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_insn__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_insn__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_insn__v1 = 0;
    CData/*3:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rmask__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rmask__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rmask__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rmask__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rmask__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rmask__v1 = 0;
    CData/*1:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mode__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mode__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mode__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mode__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mode__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mode__v1 = 0;
    CData/*3:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wmask__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wmask__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wmask__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wmask__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wmask__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wmask__v1 = 0;
    CData/*0:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v2;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v2 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v2;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v2 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v3;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v3 = 0;
    CData/*0:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_valid__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_valid__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_ixl__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_ixl__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_ixl__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_ixl__v1 = 0;
    CData/*0:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_mode__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_mode__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_mode__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_mode__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_mode__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_mode__v1 = 0;
    CData/*4:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_addr__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_addr__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_addr__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_addr__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_addr__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_addr__v1 = 0;
    QData/*63:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mcycle__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mcycle__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mcycle__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mcycle__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mcycle__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mcycle__v1 = 0;
    CData/*4:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_addr__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_addr__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_addr__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_addr__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_addr__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_addr__v1 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v0 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v1;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v1 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v1 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v2;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v2 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v2;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v2 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v3;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v3 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v3;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v3 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v4;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v4 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v4;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v4 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v5;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v5 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v5;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v5 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v6;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v6 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v6;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v6 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v7;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v7 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v7;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v7 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v8;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v8 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v8;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v8 = 0;
    IData/*31:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v9;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v9 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v9;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v9 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v10;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v10 = 0;
    IData/*17:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_post_mip__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_post_mip__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_post_mip__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_post_mip__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_post_mip__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_post_mip__v1 = 0;
    CData/*0:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi__v2;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi__v2 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi__v2;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi__v2 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi__v3;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi__v3 = 0;
    CData/*0:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req__v2;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req__v2 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req__v2;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req__v2 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req__v3;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req__v3 = 0;
    QData/*33:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q__v0;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q__v0;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q__v0 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q__v1;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q__v1 = 0;
    QData/*33:0*/ __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q__v2;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q__v2 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q__v2;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q__v2 = 0;
    CData/*0:0*/ __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q__v3;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q__v3 = 0;
    // Body
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_halt__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_halt__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_ixl__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_ixl__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_ic_scr_key_valid__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_ic_scr_key_valid__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mcycle__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mcycle__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_rdata__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_rdata__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rmask__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rmask__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_trap__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_trap__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wdata__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wdata__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rdata__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rdata__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_intr__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_intr__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_addr__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_addr__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_rdata__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_rdata__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_rdata__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_rdata__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_wdata__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_wdata__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wmask__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wmask__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_order__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_order__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi__v2 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi__v3 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v2 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v3 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v2 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v3 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req__v2 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req__v3 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_mode__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_mode__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_addr__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_addr__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_insn__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_insn__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_addr__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_addr__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_addr__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_addr__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_addr__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_addr__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_wdata__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_wdata__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mode__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mode__v1 = 0U;
    __Vdly__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_valid 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_valid;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_post_mip__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_post_mip__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_rdata__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_rdata__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v2 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v3 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v4 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v5 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v6 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v7 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v8 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v9 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v10 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v2 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v3 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v4 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v5 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v6 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v7 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v8 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v9 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v10 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q__v0 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q__v1 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q__v2 = 0U;
    __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q__v3 = 0U;
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_valid__v0 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_valid_d
           [0U]);
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_irq_valid__v1 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_irq_valid
           [0U]);
    __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_irq_valid__v0 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_irq_valid));
    if (vlSelfRef.ibex_simple_system__DOT__rst_sys_n) {
        if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_id_done) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__g_rvfi_stages__BRA__0__KET____DOT__unnamedblk1__DOT__k = 1U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__g_rvfi_stages__BRA__0__KET____DOT__unnamedblk1__DOT__k = 2U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__g_rvfi_stages__BRA__0__KET____DOT__unnamedblk1__DOT__k = 3U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__g_rvfi_stages__BRA__0__KET____DOT__unnamedblk1__DOT__k = 4U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__g_rvfi_stages__BRA__0__KET____DOT__unnamedblk1__DOT__k = 5U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__g_rvfi_stages__BRA__0__KET____DOT__unnamedblk1__DOT__k = 6U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__g_rvfi_stages__BRA__0__KET____DOT__unnamedblk1__DOT__k = 7U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__g_rvfi_stages__BRA__0__KET____DOT__unnamedblk1__DOT__k = 8U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__g_rvfi_stages__BRA__0__KET____DOT__unnamedblk1__DOT__k = 9U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__g_rvfi_stages__BRA__0__KET____DOT__unnamedblk1__DOT__k = 0xaU;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_halt__v0 = 1U;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_ixl__v0 = 1U;
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_ic_scr_key_valid__v0 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__cpuctrlsts_ic_scr_key_valid_q;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_ic_scr_key_valid__v0 = 1U;
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mcycle__v0 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__counter_val_o;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mcycle__v0 = 1U;
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_rdata__v0 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs3_data_d;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_rdata__v0 = 1U;
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rmask__v0 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_mask_int;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rmask__v0 = 1U;
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_trap__v0 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_trap_id;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_trap__v0 = 1U;
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wdata__v0 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_wdata_d;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wdata__v0 = 1U;
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rdata__v0 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_rdata_d;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rdata__v0 = 1U;
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_intr__v0 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_intr_d;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_intr__v0 = 1U;
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_addr__v0 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_addr_d;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_addr__v0 = 1U;
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_rdata__v0 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs2_data_d;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_rdata__v0 = 1U;
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_rdata__v0 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs1_data_d;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_rdata__v0 = 1U;
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_wdata__v0 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rd_wdata_d;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_wdata__v0 = 1U;
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wmask__v0 
                = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__data_we_o)
                    ? (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_mask_int)
                    : 0U);
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wmask__v0 = 1U;
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_order__v0 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_order_d;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_order__v0 = 1U;
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_mode__v0 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__debug_mode;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_mode__v0 = 1U;
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_addr__v0 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs3_addr_d;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_addr__v0 = 1U;
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_insn__v0 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_insn_id;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_insn__v0 = 1U;
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_addr__v0 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rd_addr_d;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_addr__v0 = 1U;
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_addr__v0 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs1_addr_d;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_addr__v0 = 1U;
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_addr__v0 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs2_addr_d;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_addr__v0 = 1U;
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_wdata__v0 
                = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__pc_set)
                    ? vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__branch_target_ex
                    : vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__pc_if);
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_wdata__v0 = 1U;
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mode__v0 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__priv_mode_id;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mode__v0 = 1U;
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_rdata__v0 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__pc_id;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_rdata__v0 = 1U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h5795fcef__0 
                = (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                          [3U]);
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v0 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h5795fcef__0;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v0 = 1U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h5795fcef__0 
                = (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                          [4U]);
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v1 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h5795fcef__0;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v1 = 1U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h5795fcef__0 
                = (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                          [5U]);
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v2 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h5795fcef__0;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v2 = 1U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h5795fcef__0 
                = (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                          [6U]);
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v3 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h5795fcef__0;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v3 = 1U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h5795fcef__0 
                = (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                          [7U]);
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v4 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h5795fcef__0;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v4 = 1U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h5795fcef__0 
                = (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                          [8U]);
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v5 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h5795fcef__0;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v5 = 1U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h5795fcef__0 
                = (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                          [9U]);
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v6 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h5795fcef__0;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v6 = 1U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h5795fcef__0 
                = (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                          [0xaU]);
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v7 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h5795fcef__0;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v7 = 1U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h5795fcef__0 
                = (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                          [0xbU]);
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v8 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h5795fcef__0;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v8 = 1U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h5795fcef__0 
                = (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                          [0xcU]);
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v9 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h5795fcef__0;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v9 = 1U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h49acdc58__0 
                = (IData)((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                           [3U] >> 0x20U));
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v0 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h49acdc58__0;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v0 = 1U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h49acdc58__0 
                = (IData)((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                           [4U] >> 0x20U));
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v1 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h49acdc58__0;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v1 = 1U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h49acdc58__0 
                = (IData)((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                           [5U] >> 0x20U));
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v2 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h49acdc58__0;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v2 = 1U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h49acdc58__0 
                = (IData)((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                           [6U] >> 0x20U));
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v3 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h49acdc58__0;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v3 = 1U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h49acdc58__0 
                = (IData)((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                           [7U] >> 0x20U));
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v4 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h49acdc58__0;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v4 = 1U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h49acdc58__0 
                = (IData)((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                           [8U] >> 0x20U));
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v5 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h49acdc58__0;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v5 = 1U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h49acdc58__0 
                = (IData)((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                           [9U] >> 0x20U));
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v6 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h49acdc58__0;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v6 = 1U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h49acdc58__0 
                = (IData)((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                           [0xaU] >> 0x20U));
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v7 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h49acdc58__0;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v7 = 1U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h49acdc58__0 
                = (IData)((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                           [0xbU] >> 0x20U));
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v8 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h49acdc58__0;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v8 = 1U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h49acdc58__0 
                = (IData)((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                           [0xcU] >> 0x20U));
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v9 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT____Vlvbound_h49acdc58__0;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v9 = 1U;
        }
        if (((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_id_done) 
             | vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_irq_valid
             [0U])) {
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi__v2 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi
                [0U];
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi__v2 = 1U;
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v2 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip
                [0U];
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v2 = 1U;
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v2 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int
                [0U];
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v2 = 1U;
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req__v2 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req
                [0U];
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req__v2 = 1U;
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_post_mip__v0 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mip;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_post_mip__v0 = 1U;
        }
        if ((((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_valid_id_d) 
              & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_new_id_d)) 
             | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_irq_valid))) {
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi__v0 
                = ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_valid_id) 
                             | (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_valid))))) 
                   && (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_nmi));
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi__v0 = 1U;
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req__v0 
                = ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_valid_id) 
                             | (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_valid))))) 
                   && (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_debug_req));
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req__v0 = 1U;
            if ((1U & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_valid_id) 
                       | (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_valid))))) {
                __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v0 
                    = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__irq_nm_int;
                __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v0 
                    = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mip;
            } else {
                __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v0 
                    = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_nmi_int;
                __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v0 
                    = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_mip;
            }
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v0 = 1U;
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v0 = 1U;
        }
        if ((1U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__imd_val_we_ex))) {
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q__v0 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__imd_val_d_ex
                [0U];
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q__v0 = 1U;
        }
        if ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__imd_val_we_ex))) {
            __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q__v2 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__imd_val_d_ex
                [1U];
            __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q__v2 = 1U;
        }
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_addr_q 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_addr_d;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_rdata_q 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_rdata_d;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_wdata_q 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_wdata_d;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs1_data_q 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs1_data_d;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs1_addr_q 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs1_addr_d;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs2_data_q 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs2_data_d;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs2_addr_q 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs2_addr_d;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rd_addr_q 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rd_addr_d;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rd_wdata_q 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rd_wdata_d;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_cause_q 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_cause_d;
        if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__ctrl_update) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_sign_ext_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_sign_ext;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_type_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_type;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_offset_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_offset;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_we_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_we;
        }
        if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__div_en_internal) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__op_numerator_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__op_numerator_d;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__div_by_zero_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__div_by_zero_d;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__op_quotient_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__op_quotient_d;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__div_counter_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__div_counter_d;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__md_state_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__md_state_d;
        }
        if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mstack_en) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_csr__DOT__rdata_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mstack_d;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_epc_csr__DOT__rdata_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mstack_epc_d;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_cause_csr__DOT__rdata_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mstack_cause_d;
        }
        if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_update) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_q 
                = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core 
                   >> 8U);
        }
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__rdata_outstanding_q 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__rdata_outstanding_s;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__branch_discard_q 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__branch_discard_s;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__counter_q 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__counter_d;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counter_q 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counter_d;
        if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mtvec_en) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtvec_csr__DOT__rdata_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mtvec_d;
        }
        if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcause_en) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mcause_csr__DOT__rdata_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcause_d;
        }
        if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mtval_en) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtval_csr__DOT__rdata_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mtval_d;
        }
        if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mscratch_en) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mscratch_csr__DOT__rdata_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_wdata_int;
        }
        if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dscratch0_en) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch0_csr__DOT__rdata_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_wdata_int;
        }
        if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dscratch1_en) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch1_csr__DOT__rdata_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_wdata_int;
        }
        if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__depc_en) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_depc_csr__DOT__rdata_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__depc_d;
        }
        if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mepc_en) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mepc_csr__DOT__rdata_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mepc_d;
        }
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcountinhibit_q 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcountinhibit_d;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_q 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_d;
        if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mstatus_en) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstatus_csr__DOT__rdata_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mstatus_d;
        }
        if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mie_en) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mie_csr__DOT__rdata_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mie_d;
        }
        if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dcsr_en) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dcsr_csr__DOT__rdata_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dcsr_d;
        }
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__priv_lvl_q 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__priv_lvl_d;
        if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__cpuctrlsts_part_we) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_cpuctrlsts_part_csr__DOT__rdata_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__cpuctrlsts_part_d;
        }
        if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__mult_en_internal) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__gen_mult_fast__DOT__mult_state_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__gen_mult_fast__DOT__mult_state_d;
        }
        if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__addr_update) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__addr_last_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__addr_last_d;
        }
        if ((2U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__1__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((4U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__2__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((8U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__3__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((0x10U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__4__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((0x20U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__5__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((0x40U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__6__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((0x80U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__7__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((0x100U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__8__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((0x200U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__9__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((0x400U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__10__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((0x800U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__11__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((0x1000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__12__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((0x2000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__13__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((0x4000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__14__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((0x8000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__15__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((0x10000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__16__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((0x20000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__17__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((0x40000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__18__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((0x80000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__19__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((0x100000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__20__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((0x200000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__21__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((0x400000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__22__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((0x800000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__23__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((0x1000000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__24__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((0x2000000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__25__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((0x4000000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__26__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((0x8000000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__27__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((0x10000000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__28__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((0x20000000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__29__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((0x40000000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__30__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        if ((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__we_a_dec 
             >> 0x1fU)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__31__KET____DOT__rf_reg_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_wdata_wb_ecc;
        }
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__ls_fsm_cs 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__ls_fsm_ns;
        if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_executing) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__id_fsm_q 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__id_fsm_d;
        }
        if ((((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_valid_id)) 
              & ((((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__new_debug_req) 
                   | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__new_irq)) 
                  | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__new_nmi)) 
                 | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__new_nmi_int))) 
             & (((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_valid)) 
                 | ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__new_debug_req) 
                    & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_debug_req)))) 
                | (((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__new_nmi) 
                    & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_nmi))) 
                   & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_debug_req)))))) {
            __Vdly__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_valid = 1U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_nmi = 0U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_nmi_int 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__irq_nm_int;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_mip 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mip;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_debug_req = 0U;
        }
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_irq_valid 
            = (((((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_valid_id)) 
                  & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__new_debug_req))) 
                 & (((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__new_irq) 
                     | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__new_nmi)) 
                    | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__new_nmi_int))) 
                & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ready_wb)) 
               & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_valid)));
        if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_valid_id_d) {
            __Vdly__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_valid = 0U;
        }
    } else {
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_halt__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_ixl__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_ic_scr_key_valid__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mcycle__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_rdata__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rmask__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_trap__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wdata__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rdata__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_intr__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_addr__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_rdata__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_rdata__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_wdata__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wmask__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_order__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi__v3 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v3 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v3 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req__v3 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_mode__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_addr__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_insn__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_addr__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_addr__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_addr__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_wdata__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mode__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_post_mip__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_rdata__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v10 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v10 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q__v1 = 1U;
        __VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q__v3 = 1U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_addr_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_rdata_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_wdata_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs1_data_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs1_addr_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs2_data_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs2_addr_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rd_addr_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rd_wdata_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_cause_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_sign_ext_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__op_numerator_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__div_by_zero_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__op_quotient_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_csr__DOT__rdata_q = 4U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_epc_csr__DOT__rdata_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_cause_csr__DOT__rdata_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_type_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__rdata_outstanding_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__branch_discard_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__div_counter_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__counter_q = 0ULL;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counter_q = 0ULL;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_offset_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtvec_csr__DOT__rdata_q = 1U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mcause_csr__DOT__rdata_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtval_csr__DOT__rdata_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mscratch_csr__DOT__rdata_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch0_csr__DOT__rdata_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch1_csr__DOT__rdata_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_depc_csr__DOT__rdata_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mepc_csr__DOT__rdata_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcountinhibit_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_we_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstatus_csr__DOT__rdata_q = 0x10U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mie_csr__DOT__rdata_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dcsr_csr__DOT__rdata_q = 0x40000003U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__priv_lvl_q = 3U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_cpuctrlsts_part_csr__DOT__rdata_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__gen_mult_fast__DOT__mult_state_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__addr_last_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__md_state_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__1__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__2__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__3__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__4__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__5__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__6__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__7__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__8__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__9__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__10__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__11__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__12__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__13__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__14__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__15__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__16__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__17__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__18__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__19__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__20__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__21__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__22__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__23__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__24__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__25__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__26__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__27__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__28__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__29__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__30__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__31__KET____DOT__rf_reg_q = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__ls_fsm_cs = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__id_fsm_q = 0U;
        __Vdly__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_valid = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_mip = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_nmi = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_nmi_int = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_debug_req = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_irq_valid = 0U;
    }
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_intr_q 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_intr_d));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_mis_bus_err_1_q 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_mis_bus_err_1_d));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_set_trap_pc_q 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_set_trap_pc_d));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_mis_2_en_q 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_mis_2_en_d));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__discard_req_q 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__discard_req_d));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_new_id_q 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_new_id_d));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__valid_req_q 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__valid_req_d));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__enter_debug_mode_prio_q 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__enter_debug_mode_prio_d));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__exc_req_q 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__exc_req_d));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__do_single_step_q 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__do_single_step_d));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__branch_jump_set_done_q 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__branch_jump_set_done_d));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__lsu_err_q 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__lsu_err_d));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__nmi_mode_q 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__nmi_mode_d));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__g_branch_set_flop__DOT__branch_set_raw_q 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__branch_set_raw_d));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__illegal_insn_q 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__illegal_insn_d));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__store_err_q 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__store_err_d));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__load_err_q 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__load_err_d));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_mode_q 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_mode_d));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__pmp_err_q 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__pmp_err_d));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__handle_misaligned_q 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__handle_misaligned_d));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_valid_id_q 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n) 
           && (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_valid_id_d));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_valid[0U] 
        = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_valid__v0;
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_halt__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_halt[0U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_halt__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_halt[0U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_ixl__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_ixl[0U] = 1U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_ixl__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_ixl[0U] = 1U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_ic_scr_key_valid__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_ic_scr_key_valid[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_ic_scr_key_valid__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_ic_scr_key_valid__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_ic_scr_key_valid[0U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mcycle__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mcycle[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mcycle__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mcycle__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mcycle[0U] = 0ULL;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_rdata__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_rdata[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_rdata__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_rdata__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_rdata[0U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rmask__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rmask[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rmask__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rmask__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rmask[0U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_trap__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_trap[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_trap__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_trap__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_trap[0U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wdata__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wdata[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wdata__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wdata__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wdata[0U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rdata__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rdata[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rdata__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rdata__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rdata[0U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_intr__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_intr[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_intr__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_intr__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_intr[0U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_addr__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_addr[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_addr__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_addr__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_addr[0U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_rdata__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_rdata[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_rdata__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_rdata__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_rdata[0U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_rdata__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_rdata[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_rdata__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_rdata__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_rdata[0U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_wdata__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_wdata[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_wdata__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_wdata__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_wdata[0U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wmask__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wmask[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wmask__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wmask__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wmask[0U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_order__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_order[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_order__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_order__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_order[0U] = 0ULL;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_mode__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_mode[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_mode__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_mode__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_mode[0U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_addr__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_addr[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_addr__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_addr__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_addr[0U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_insn__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_insn[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_insn__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_insn__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_insn[0U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_addr__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_addr[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_addr__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_addr__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_addr[0U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_addr__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_addr[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_addr__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_addr__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_addr[0U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_addr__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_addr[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_addr__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_addr__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_addr[0U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_wdata__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_wdata[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_wdata__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_wdata__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_wdata[0U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mode__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mode[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mode__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mode__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mode[0U] = 3U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_post_mip__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_post_mip[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_post_mip__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_post_mip__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_post_mip[0U] = 0U;
    }
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_irq_valid[0U] 
        = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_irq_valid__v0;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_irq_valid[1U] 
        = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_irq_valid__v1;
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi[0U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi__v2) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi[1U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi__v2;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi__v3) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi[1U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req[0U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req__v2) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req[1U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req__v2;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req__v3) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req[1U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int[0U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v2) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int[1U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v2;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int__v3) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int[1U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip[0U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v2) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip[1U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v2;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip__v3) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip[1U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_rdata__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_rdata[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_rdata__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_rdata__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_rdata[0U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters[0U][0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters[0U][1U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v1;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v2) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters[0U][2U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v2;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v3) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters[0U][3U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v3;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v4) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters[0U][4U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v4;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v5) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters[0U][5U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v5;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v6) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters[0U][6U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v6;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v7) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters[0U][7U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v7;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v8) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters[0U][8U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v8;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v9) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters[0U][9U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v9;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters__v10) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters[0U][0U] = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters[0U][1U] = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters[0U][2U] = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters[0U][3U] = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters[0U][4U] = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters[0U][5U] = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters[0U][6U] = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters[0U][7U] = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters[0U][8U] = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters[0U][9U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh[0U][0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh[0U][1U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v1;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v2) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh[0U][2U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v2;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v3) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh[0U][3U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v3;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v4) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh[0U][4U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v4;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v5) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh[0U][5U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v5;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v6) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh[0U][6U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v6;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v7) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh[0U][7U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v7;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v8) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh[0U][8U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v8;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v9) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh[0U][9U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v9;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh__v10) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh[0U][0U] = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh[0U][1U] = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh[0U][2U] = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh[0U][3U] = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh[0U][4U] = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh[0U][5U] = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh[0U][6U] = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh[0U][7U] = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh[0U][8U] = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh[0U][9U] = 0U;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q__v0) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q[0U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q__v0;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q__v1) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q[0U] = 0ULL;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q__v2) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q[1U] 
            = __VdlyVal__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q__v2;
    }
    if (__VdlySet__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q__v3) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q[1U] = 0ULL;
    }
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_valid 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_valid
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_valid 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_valid
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_halt 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_halt
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_halt 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_halt
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_halt 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_halt
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ixl 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_ixl
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ixl 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_ixl
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ixl 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_ixl
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_ic_scr_key_valid 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_ic_scr_key_valid
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_rvfi_ext_ic_scr_key_valid 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_ic_scr_key_valid
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_ic_scr_key_valid 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_ic_scr_key_valid
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_ic_scr_key_valid 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_ic_scr_key_valid
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mcycle 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mcycle
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_rvfi_ext_mcycle 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mcycle
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mcycle 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mcycle
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mcycle 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mcycle
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_rs3_rdata 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_rdata
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs3_rdata 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_rdata
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_mem_rmask 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rmask
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_rmask 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rmask
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_trap 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_trap
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_trap 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_trap
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_trap 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_trap
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_mem_wdata 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wdata
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_wdata 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wdata
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_mem_rdata 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rdata
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_rdata 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_rdata
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_intr 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_intr
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_intr 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_intr
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_intr 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_intr
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_mem_addr 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_addr
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_addr 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_addr
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_rs2_rdata 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_rdata
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs2_rdata 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_rdata
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_rs1_rdata 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_rdata
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs1_rdata 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_rdata
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_rd_wdata 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_wdata
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rd_wdata 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_wdata
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_mem_wmask 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wmask
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_wmask 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mem_wmask
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_order 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_order
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_order 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_order
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_order_d 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__dummy_instr_id_o)
            ? vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_order
           [0U] : (1ULL + vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_order
                   [0U]));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_order 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_order
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_debug_mode 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_mode
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_rvfi_ext_debug_mode 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_mode
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_debug_mode 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_mode
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_debug_mode 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_mode
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_rs3_addr 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_addr
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs3_addr 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs3_addr
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_insn 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_insn
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_insn 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_insn
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_rd_addr 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_addr
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rd_addr 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rd_addr
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_rs1_addr 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_addr
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs1_addr 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs1_addr
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_rs2_addr 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_addr
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rs2_addr 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_rs2_addr
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_pc_wdata 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_wdata
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_pc_wdata 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_wdata
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_pc_wdata 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_wdata
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_mode 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mode
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mode 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mode
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_mode 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_mode
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_post_mip = 0U;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_post_mip 
        = ((0xfffffff7U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_post_mip) 
           | (8U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_post_mip
                    [0U] >> 0xeU)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_post_mip 
        = ((0xffffff7fU & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_post_mip) 
           | (0x80U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_post_mip
                       [0U] >> 9U)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_post_mip 
        = ((0xfffff7ffU & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_post_mip) 
           | (0x800U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_post_mip
                        [0U] >> 4U)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_post_mip 
        = ((0x8000ffffU & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_post_mip) 
           | (0x7fff0000U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_post_mip
                             [0U] << 0x10U)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_irq_valid 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_irq_valid
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_rvfi_ext_irq_valid 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_irq_valid
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_irq_valid 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_irq_valid
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_irq_valid 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_irq_valid
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_nmi 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_rvfi_ext_nmi 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_nmi 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_nmi 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_debug_req 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_rvfi_ext_debug_req 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_debug_req 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_debug_req 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_debug_req
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_nmi_int 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_rvfi_ext_nmi_int 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_nmi_int 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_nmi_int 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_nmi_int
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_pre_mip = 0U;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_pre_mip 
        = ((0xfffffff7U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_pre_mip) 
           | (8U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip
                    [1U] >> 0xeU)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_pre_mip 
        = ((0xffffff7fU & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_pre_mip) 
           | (0x80U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip
                       [1U] >> 9U)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_pre_mip 
        = ((0xfffff7ffU & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_pre_mip) 
           | (0x800U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip
                        [1U] >> 4U)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_pre_mip 
        = ((0x8000ffffU & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_pre_mip) 
           | (0x7fff0000U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_pre_mip
                             [1U] << 0x10U)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_pc_rdata 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_rdata
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_pc_rdata 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_stage_pc_rdata
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcounters[0U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters
        [0U][0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcounters[1U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters
        [0U][1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcounters[2U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters
        [0U][2U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcounters[3U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters
        [0U][3U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcounters[4U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters
        [0U][4U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcounters[5U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters
        [0U][5U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcounters[6U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters
        [0U][6U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcounters[7U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters
        [0U][7U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcounters[8U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters
        [0U][8U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcounters[9U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcounters
        [0U][9U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcountersh[0U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh
        [0U][0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcountersh[1U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh
        [0U][1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcountersh[2U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh
        [0U][2U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcountersh[3U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh
        [0U][3U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcountersh[4U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh
        [0U][4U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcountersh[5U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh
        [0U][5U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcountersh[6U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh
        [0U][6U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcountersh[7U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh
        [0U][7U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcountersh[8U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh
        [0U][8U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcountersh[9U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_stage_mhpmcountersh
        [0U][9U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q_ex_o[0U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q_ex_o[1U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_new_id 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_new_id_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_new_id_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_new_id_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_instr_new_wb 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_new_id_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__debug_cause_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_cause_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_cause_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_cause_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__debug_cause 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_cause_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_csr__DOT__rd_data_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mstack_q 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_epc_csr__DOT__rd_data_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_epc_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mstack_epc_q 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_epc_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_cause_csr__DOT__rd_data_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_cause_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mstack_cause_q 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_cause_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__rdata_outstanding_rev 
        = ((2U & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__rdata_outstanding_q) 
                  << 1U)) | (1U & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__rdata_outstanding_q) 
                                   >> 1U)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__one_shift 
        = ((IData)(1U) << (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__div_counter_q));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__counter_val_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__counter_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__counter 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__counter_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__counter_upd 
        = (1ULL + vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__counter_q);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter[0U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__counter_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_raw 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counter_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counter_val_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counter_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counter 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counter_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counter_upd 
        = (1ULL + vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counter_q);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__unused_csr_mtvec 
        = (0xffU & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtvec_csr__DOT__rdata_q);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_mtvec_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtvec_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtvec_csr__DOT__rd_data_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtvec_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_mtvec 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtvec_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mtvec_q 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtvec_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mcause_csr__DOT__rd_data_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mcause_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcause_q 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mcause_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__crash_dump_mtval 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtval_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_mtval_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtval_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtval_csr__DOT__rd_data_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtval_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mtval_q 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtval_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mscratch_csr__DOT__rd_data_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mscratch_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mscratch_q 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mscratch_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch0_csr__DOT__rd_data_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch0_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dscratch0_q 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch0_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch1_csr__DOT__rd_data_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch1_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dscratch1_q 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch1_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_depc_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_depc_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_depc_csr__DOT__rd_data_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_depc_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_depc 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_depc_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__depc_q 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_depc_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_mepc_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mepc_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mepc_csr__DOT__rd_data_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mepc_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_mepc 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mepc_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mepc_q 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mepc_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcountinhibit 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcountinhibit_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter[2U] 
        = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counter_q 
           + (QData)((IData)(((~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcountinhibit_q) 
                                  >> 2U)) & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__perf_instr_ret_wb_spec_o)))));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT____VdfgRegularize_hb4cbc9db_0_19 
        = (IData)((2U == (6U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_q))));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT____VdfgRegularize_hb4cbc9db_0_14 
        = (IData)((1U == (3U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_q))));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__busy_o 
        = (3U & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_q) 
                 >> 1U));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstatus_csr__DOT__rd_data_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstatus_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mstack_d 
        = (7U & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstatus_csr__DOT__rdata_q) 
                 >> 2U));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mstatus_q 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstatus_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_mstatus_mie_o 
        = (1U & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstatus_csr__DOT__rdata_q) 
                 >> 5U));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_mstatus_tw_o 
        = (1U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstatus_csr__DOT__rdata_q));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__nmi_mode_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__nmi_mode_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__nmi_mode_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__nmi_mode_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__nmi_mode 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__nmi_mode_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__branch_set_raw 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__g_branch_set_flop__DOT__branch_set_raw_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__branch_set 
        = ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__branch_jump_set_done_q)) 
           & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__g_branch_set_flop__DOT__branch_set_raw_q));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mie_q 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mie_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mie_csr__DOT__rd_data_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mie_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dcsr_csr__DOT__rd_data_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dcsr_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dcsr_q 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dcsr_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__debug_ebreakm 
        = (1U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dcsr_csr__DOT__rdata_q 
                 >> 0xfU));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__debug_ebreaku 
        = (1U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dcsr_csr__DOT__rdata_q 
                 >> 0xcU));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__debug_single_step 
        = (1U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dcsr_csr__DOT__rdata_q 
                 >> 2U));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__priv_mode_id_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__priv_lvl_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__priv_mode_lsu_o 
        = (3U & ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstatus_csr__DOT__rdata_q))
                  ? ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstatus_csr__DOT__rdata_q) 
                     >> 2U) : (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__priv_lvl_q)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__priv_mode_id 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__priv_lvl_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_cpuctrlsts_part_csr__DOT__rd_data_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_cpuctrlsts_part_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__dummy_instr_en 
        = (1U & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_cpuctrlsts_part_csr__DOT__rdata_q) 
                 >> 2U));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__dummy_instr_mask 
        = (7U & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_cpuctrlsts_part_csr__DOT__rdata_q) 
                 >> 3U));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__cpuctrlsts_part_q 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_cpuctrlsts_part_csr__DOT__rdata_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__data_ind_timing 
        = (1U & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_cpuctrlsts_part_csr__DOT__rdata_q) 
                 >> 1U));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__debug_mode_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_mode_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_mode_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_mode_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__debug_mode 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_mode_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__sva_mul_fsm_idle 
        = (0U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__gen_mult_fast__DOT__mult_state_q));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__addr_last_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__addr_last_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_addr_last 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__addr_last_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__div_hold = 0U;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__div_valid = 0U;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[1U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__1__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[2U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__2__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[3U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__3__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[4U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__4__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[5U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__5__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[6U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__6__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[7U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__7__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[8U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__8__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[9U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__9__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[0xaU] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__10__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[0xbU] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__11__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[0xcU] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__12__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[0xdU] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__13__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[0xeU] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__14__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[0xfU] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__15__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[0x10U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__16__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[0x11U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__17__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[0x12U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__18__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[0x13U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__19__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[0x14U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__20__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[0x15U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__21__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[0x16U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__22__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[0x17U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__23__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[0x18U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__24__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[0x19U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__25__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[0x1aU] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__26__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[0x1bU] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__27__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[0x1cU] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__28__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[0x1dU] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__29__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[0x1eU] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__30__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__rf_reg[0x1fU] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__g_rf_flops__BRA__31__KET____DOT__rf_reg_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_ls_mis_pmp_err_1 
        = (((2U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__ls_fsm_cs)) 
            | (1U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__ls_fsm_cs))) 
           & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__pmp_err_q));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_busy 
        = (0U != (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__ls_fsm_cs));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__addr_incr_req_o = 0U;
    if ((4U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__ls_fsm_cs))) {
        if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__ls_fsm_cs) 
                      >> 1U)))) {
            if ((1U & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__ls_fsm_cs)))) {
                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__addr_incr_req_o = 1U;
            }
        }
    } else if ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__ls_fsm_cs))) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__addr_incr_req_o 
            = ((1U & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__ls_fsm_cs))) 
               || (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__handle_misaligned_q));
    }
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_valid_id_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_valid_id_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__id_wb_pending 
        = (1U & ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__ready_wb_o)) 
                 | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_valid_id_q)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_first_cycle 
        = ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__id_fsm_q)) 
           & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_valid_id_q));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_halt 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_halt;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_ixl 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ixl;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_trap 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_trap;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_intr 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_intr;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_order 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_order;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_pc_wdata 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_pc_wdata;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__rvfi_mode 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_mode;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_post_mip 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_post_mip;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_rvfi_ext_post_mip 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_post_mip;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_post_mip 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_post_mip;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_pre_mip 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_pre_mip;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_rvfi_ext_pre_mip 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_pre_mip;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_pre_mip 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_pre_mip;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_valid 
        = __Vdly__ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__captured_valid;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcounters[0U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcounters
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcounters[1U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcounters
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcounters[2U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcounters
        [2U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcounters[3U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcounters
        [3U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcounters[4U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcounters
        [4U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcounters[5U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcounters
        [5U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcounters[6U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcounters
        [6U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcounters[7U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcounters
        [7U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcounters[8U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcounters
        [8U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcounters[9U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcounters
        [9U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcountersh[0U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcountersh
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcountersh[1U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcountersh
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcountersh[2U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcountersh
        [2U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcountersh[3U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcountersh
        [3U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcountersh[4U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcountersh
        [4U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcountersh[5U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcountersh
        [5U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcountersh[6U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcountersh
        [6U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcountersh[7U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcountersh
        [7U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcountersh[8U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcountersh
        [8U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcountersh[9U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_ext_mhpmcountersh
        [9U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__imd_val_q_ex[0U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q_ex_o
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__imd_val_q_ex[1U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imd_val_q_ex_o
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__debug_cause_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__debug_cause;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_next 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counter_upd;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counter_val_upd_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counter_upd;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__csr_mtvec_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_mtvec;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mstack_cause_d 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcause_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__csr_depc_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_depc;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__csr_mepc_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_mepc;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mstack_epc_d 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mepc_q;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__lowest_free_entry 
        = (((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT____VdfgRegularize_hb4cbc9db_0_19) 
            << 2U) | (((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT____VdfgRegularize_hb4cbc9db_0_14) 
                       << 1U) | (1U & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_q)))));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_busy 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__busy_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_ready 
        = (1U & (~ (IData)((3U == ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__busy_o) 
                                   | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__rdata_outstanding_rev))))));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_csr__DOT__wr_data_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mstack_d;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_mstatus_mie 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_mstatus_mie_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__irq_enabled 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_mstatus_mie_o) 
           | (0U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__priv_lvl_q)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_mstatus_tw 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_mstatus_tw_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__nmi_mode_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__nmi_mode;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__branch_set_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__branch_set;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__debug_ebreakm_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__debug_ebreakm;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__debug_ebreakm_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__debug_ebreakm;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__debug_ebreaku_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__debug_ebreaku;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__debug_ebreaku_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__debug_ebreaku;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__ebreak_into_debug 
        = ((3U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__priv_lvl_q))
            ? (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__debug_ebreakm)
            : ((0U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__priv_lvl_q)) 
               & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__debug_ebreaku)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__debug_single_step_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__debug_single_step;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__debug_single_step_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__debug_single_step;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__fcov_all_debug_req 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_mode_q) 
           | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__debug_single_step));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__do_single_step_d 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_valid_id_q)
            ? ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_mode_q)) 
               & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__debug_single_step))
            : (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__do_single_step_q));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__priv_mode_lsu 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__priv_mode_lsu_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__g_no_pmp__DOT__unused_priv_lvl_ls 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__priv_mode_lsu_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__priv_mode_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__priv_mode_id;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__dummy_instr_en_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__dummy_instr_en;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_no_dummy_instr__DOT__unused_dummy_en 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__dummy_instr_en;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dummy_instr_en_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__dummy_instr_en;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__dummy_instr_mask_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__dummy_instr_mask;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_no_dummy_instr__DOT__unused_dummy_mask 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__dummy_instr_mask;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dummy_instr_mask_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__dummy_instr_mask;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__data_ind_timing_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__data_ind_timing;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__data_ind_timing_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__data_ind_timing;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__data_ind_timing_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__data_ind_timing;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__debug_mode_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__debug_mode;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__new_nmi_int 
        = (((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__irq_nm_int) 
            & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__nmi_mode))) 
           & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__debug_mode)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__unused_sva_mul_fsm_idle 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__sva_mul_fsm_idle;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__lsu_addr_last_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_addr_last;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__unused_fcov_ls_mis_pmp_err_1 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_ls_mis_pmp_err_1;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__busy_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_busy;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_addr_incr_req 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__addr_incr_req_o;
    if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_first_cycle) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__instr_first_cycle_i = 1U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_first_cycle_id_o = 1U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__data_req_allowed = 1U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_intr_d 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_set_trap_pc_q;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_first_cycle_id = 1U;
    } else {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__instr_first_cycle_i = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_first_cycle_id_o = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__data_req_allowed = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_intr_d 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_intr_q;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_first_cycle_id = 0U;
    }
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcounters[0U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcounters
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcounters[1U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcounters
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcounters[2U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcounters
        [2U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcounters[3U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcounters
        [3U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcounters[4U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcounters
        [4U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcounters[5U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcounters
        [5U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcounters[6U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcounters
        [6U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcounters[7U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcounters
        [7U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcounters[8U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcounters
        [8U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcounters[9U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcounters
        [9U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcountersh[0U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcountersh
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcountersh[1U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcountersh
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcountersh[2U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcountersh
        [2U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcountersh[3U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcountersh
        [3U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcountersh[4U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcountersh
        [4U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcountersh[5U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcountersh
        [5U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcountersh[6U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcountersh
        [6U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcountersh[7U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcountersh
        [7U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcountersh[8U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcountersh
        [8U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcountersh[9U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rvfi_ext_mhpmcountersh
        [9U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__unused_imd_val 
        = (3U & (IData)((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__imd_val_q_ex
                         [1U] >> 0x20U)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__imd_val_q_i[0U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__imd_val_q_ex
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__imd_val_q_i[1U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__imd_val_q_ex
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__imd_val_q_i[0U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__imd_val_q_ex
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__imd_val_q_i[1U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__imd_val_q_ex
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_imd_val_q[0U] 
        = (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__imd_val_q_ex
                  [0U]);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_imd_val_q[1U] 
        = (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__imd_val_q_ex
                  [1U]);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__alu_operand_a_o = 1ULL;
    if ((4U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__md_state_q))) {
        if ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__md_state_q))) {
            if ((1U & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__md_state_q)))) {
                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__div_hold 
                    = (1U & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__multdiv_ready_id)));
                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__div_valid = 1U;
            }
        }
        if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__md_state_q) 
                      >> 1U)))) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__alu_operand_a_o 
                = ((1U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__md_state_q))
                    ? 1ULL : (1ULL | ((QData)((IData)(
                                                      vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__imd_val_q_ex
                                                      [0U])) 
                                      << 1U)));
        }
    } else {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__alu_operand_a_o 
            = ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__md_state_q))
                ? ((1U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__md_state_q))
                    ? (1ULL | ((QData)((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__imd_val_q_ex
                                               [0U])) 
                               << 1U)) : 1ULL) : 1ULL);
    }
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__op_denominator_q 
        = (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__imd_val_q_ex
                  [1U]);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_cause_csr__DOT__wr_data_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mstack_cause_d;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_epc_csr__DOT__wr_data_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mstack_epc_d;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__csr_mstatus_mie_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_mstatus_mie;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__csr_mstatus_tw_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_mstatus_tw;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_ebreakm_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__debug_ebreakm_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_ebreaku_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__debug_ebreaku_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_single_step_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__debug_single_step_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__unused_fcov_all_debug_req 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__fcov_all_debug_req;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__fcov_debug_single_step_taken 
        = ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__do_single_step_q)) 
           & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__do_single_step_d));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__enter_debug_mode_prio_d 
        = ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_mode_q)) 
           & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__do_single_step_d));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__priv_mode_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__priv_mode_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__data_ind_timing_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__data_ind_timing_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__lsu_addr_last_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__lsu_addr_last_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__lsu_addr_incr_req_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_addr_incr_req;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_instr_first_cycle_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_first_cycle_id;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_perf_regs[0U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcounters
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_perf_regs[1U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcounters
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_perf_regs[2U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcounters
        [2U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_perf_regs[3U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcounters
        [3U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_perf_regs[4U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcounters
        [4U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_perf_regs[5U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcounters
        [5U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_perf_regs[6U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcounters
        [6U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_perf_regs[7U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcounters
        [7U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_perf_regs[8U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcounters
        [8U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_perf_regs[9U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcounters
        [9U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_perf_regsh[0U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcountersh
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_perf_regsh[1U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcountersh
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_perf_regsh[2U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcountersh
        [2U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_perf_regsh[3U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcountersh
        [3U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_perf_regsh[4U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcountersh
        [4U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_perf_regsh[5U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcountersh
        [5U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_perf_regsh[6U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcountersh
        [6U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_perf_regsh[7U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcountersh
        [7U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_perf_regsh[8U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcountersh
        [8U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__unused_perf_regsh[9U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__rvfi_ext_mhpmcountersh
        [9U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__imd_val_q_i[0U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_imd_val_q
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__imd_val_q_i[1U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_imd_val_q
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__g_no_alu_rvb__DOT__unused_imd_val_q[0U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_imd_val_q
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__g_no_alu_rvb__DOT__unused_imd_val_q[1U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_imd_val_q
        [1U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__multdiv_alu_operand_a 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__alu_operand_a_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__csr_mstatus_mie_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__csr_mstatus_mie_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__unused_fcov_debug_single_step_taken 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__fcov_debug_single_step_taken;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__enter_debug_mode 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__enter_debug_mode_prio_d) 
           | ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_mode_q)) 
              & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__trigger_match_o)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__instr_first_cycle_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_instr_first_cycle_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__alu_i__DOT__multdiv_operand_a_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__multdiv_alu_operand_a;
}

VL_INLINE_OPT void Vtop___024root___nba_sequent__TOP__3(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___nba_sequent__TOP__3\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Body
    if (VL_UNLIKELY((((((5U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__ctrl_fsm_cs)) 
                        & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_valid_id)) 
                       & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_fetch_err))) 
                      & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__illegal_insn_d))))) {
        VL_WRITEF_NX("%t: Illegal instruction (hart %0x) at PC 0x%x: 0x%x\n",0,
                     64,VL_TIME_UNITED_Q(1000),-9,32,
                     vlSelfRef.ibex_simple_system__DOT__u_top__DOT__hart_id_i,
                     32,vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__pc_id,
                     32,((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_is_compressed_id)
                          ? (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_rdata_c_id)
                          : vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_rdata_id));
    }
}

VL_INLINE_OPT void Vtop___024root___nba_sequent__TOP__4(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___nba_sequent__TOP__4\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Body
    if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fetch_addr_en) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fetch_addr_q 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fetch_addr_d;
    }
    if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__stored_addr_en) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__stored_addr_q 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__stored_addr_d;
    }
    if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__instr_addr_en) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__instr_addr_q 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__instr_addr_d;
    }
    if ((1U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__entry_en))) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__err_q 
            = ((6U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__err_q)) 
               | (1U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__err_d)));
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__rdata_q[0U] 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__rdata_d[0U];
    }
    if ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__entry_en))) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__err_q 
            = ((5U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__err_q)) 
               | (2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__err_d)));
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__rdata_q[1U] 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__rdata_d[1U];
    }
    if ((4U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__entry_en))) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__err_q 
            = ((3U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__err_q)) 
               | (4U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__err_d)));
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__rdata_q[2U] 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__rdata_d[2U];
    }
    if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_id_pipe_reg_we) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_fetch_err_plus2_o 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_err_plus2;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_c_id_o 
            = (0xffffU & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata);
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_fetch_err_o 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_err_out;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__pc_id_o 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__pc_if_o;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_is_compressed_id_o 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_is_compressed_out;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__illegal_c_insn_id_o 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__illegal_c_instr_out;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_alu_id_o 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_out;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_out;
    }
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__pc_if 
        = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__instr_addr_q 
           << 1U);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_fetch_err_plus2 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_fetch_err_plus2_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_rdata_c_id 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_c_id_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_fetch_err 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_fetch_err_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__g_bypass_wb__DOT__unused_pc_id 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__pc_id_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__pc_id 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__pc_id_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_is_compressed_id 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_is_compressed_id_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__illegal_c_insn_id 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__illegal_c_insn_id_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__unused_instr_alu 
        = ((0x3e0U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_alu_id_o 
                      >> 0xaU)) | (0x1fU & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_alu_id_o 
                                            >> 7U)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_rdata_alu_id 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_alu_id_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__instr_alu 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_alu_id_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT____VdfgRegularize_h50863dbe_2_6 
        = (((1U == (7U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_alu_id_o 
                          >> 0xcU))) << 1U) | (0U == 
                                               (7U 
                                                & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_alu_id_o 
                                                   >> 0xcU))));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__unused_csr_addr 
        = (7U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o 
                 >> 0x19U));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_insn_id 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_is_compressed_id_o)
            ? (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_c_id_o)
            : vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_rdata_id 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imm_b_type 
        = (((- (IData)((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o 
                        >> 0x1fU))) << 0xdU) | (((0x1000U 
                                                  & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o 
                                                     >> 0x13U)) 
                                                 | (0x800U 
                                                    & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o 
                                                       << 4U))) 
                                                | ((0x7e0U 
                                                    & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o 
                                                       >> 0x14U)) 
                                                   | (0x1eU 
                                                      & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o 
                                                         >> 7U)))));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imm_u_type 
        = (0xfffff000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imm_j_type 
        = (((- (IData)((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o 
                        >> 0x1fU))) << 0x14U) | (((0xff000U 
                                                   & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o) 
                                                  | (0x800U 
                                                     & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o 
                                                        >> 9U))) 
                                                 | (0x7feU 
                                                    & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o 
                                                       >> 0x14U))));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__instr_rs3 
        = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o 
           >> 0x1bU);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx 
        = (0x1fU & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o 
                    >> 0x14U));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__instr 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT____VdfgRegularize_h50863dbe_1_14 
        = (((2U == (3U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o 
                          >> 0xcU))) << 2U) | (((1U 
                                                 == 
                                                 (3U 
                                                  & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o 
                                                     >> 0xcU))) 
                                                << 1U) 
                                               | (0U 
                                                  == 
                                                  (3U 
                                                   & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o 
                                                      >> 0xcU)))));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT____VdfgRegularize_h50863dbe_1_9 
        = (((1U == (7U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o 
                          >> 0xcU))) << 1U) | (0U == 
                                               (7U 
                                                & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o 
                                                   >> 0xcU))));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT____VdfgRegularize_h50863dbe_1_30 
        = (((3U == (3U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o 
                          >> 0xcU))) << 2U) | (((2U 
                                                 == 
                                                 (3U 
                                                  & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o 
                                                     >> 0xcU))) 
                                                << 1U) 
                                               | (1U 
                                                  == 
                                                  (3U 
                                                   & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o 
                                                      >> 0xcU)))));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_waddr_wb 
        = (0x1fU & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o 
                    >> 7U));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr 
        = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o 
           >> 0x14U);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__instr_rs1 
        = (0x1fU & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o 
                    >> 0xfU));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pc_if_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__pc_if;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__pc_if_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__pc_if;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__fetch_addr 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__pc_if;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_addr 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__pc_if;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__addr_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__pc_if;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__out_addr_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__pc_if;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_fetch_err_plus2_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_fetch_err_plus2;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_rdata_c_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_rdata_c_id;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_fetch_err_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_fetch_err;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__pc_id_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__pc_id;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pc_id_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__pc_id;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__pc_id_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__pc_id;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__instr_is_compressed_id_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_is_compressed_id;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_is_compressed_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_is_compressed_id;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__illegal_c_insn_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__illegal_c_insn_id;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_rdata_alu_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_rdata_alu_id;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_rdata_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_rdata_id;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__imm_b_type_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imm_b_type;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__imm_u_type_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imm_u_type;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__imm_j_type_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imm_j_type;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_raddr_b_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_raddr_b_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__rf_raddr_b_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__instr_rs2 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_raddr_b 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_raddr_b 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_waddr_wb_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_waddr_wb;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_waddr_wb_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_waddr_wb;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_waddr_id_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_waddr_wb;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__gen_no_stall_mem__DOT__unused_rf_waddr_wb 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_waddr_wb;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__rf_waddr_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_waddr_wb;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__instr_rd 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_waddr_wb;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__rf_waddr_wb_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_waddr_wb;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_waddr_id 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_waddr_wb;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_rd_addr_wb 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_waddr_wb;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_waddr_wb 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_waddr_wb;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imm_s_type 
        = (((- (IData)((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o 
                        >> 0x1fU))) << 0xcU) | ((0xfe0U 
                                                 & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o 
                                                    >> 0x14U)) 
                                                | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_waddr_wb)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_addr_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__csr_addr_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__csr_addr_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_addr 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__no_flush_csr_addr 
        = ((0x340U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)) 
           | (0x341U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 0U;
    if ((0x800U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
        if ((0x400U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
            if ((0x200U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                if ((0x100U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    if ((0x80U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                    } else if ((0x40U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                    } else if ((0x20U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                    } else if ((0x10U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                        if ((8U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                        } else if ((4U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                            if ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                            }
                        } else if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                             >> 1U)))) {
                            if ((1U & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)))) {
                                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                            }
                        }
                    } else {
                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                    }
                } else {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                }
            } else {
                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
            }
        } else if ((0x200U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
            if ((0x100U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                if ((0x80U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    if ((0x40U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                    } else if ((0x20U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                    } else if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                         >> 4U)))) {
                        if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                      >> 3U)))) {
                            if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                          >> 2U)))) {
                                if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                              >> 1U)))) {
                                    if ((1U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                                    }
                                }
                            }
                        }
                    }
                } else if ((0x40U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                } else if ((0x20U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                } else if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                     >> 4U)))) {
                    if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                  >> 3U)))) {
                        if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                      >> 2U)))) {
                            if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                          >> 1U)))) {
                                if ((1U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                                }
                            }
                        }
                    }
                }
            } else {
                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
            }
        } else {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
        }
    } else if ((0x400U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
        if ((0x200U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
            if ((0x100U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                if ((0x80U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    if ((0x40U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                        if ((0x20U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                        } else if ((0x10U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                        } else if ((8U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                        } else if ((4U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                        } else if ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                        }
                    } else if ((0x20U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                        if ((0x10U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                            if ((8U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                            } else if ((4U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                            }
                        } else {
                            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                        }
                    } else {
                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                    }
                } else {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                }
            } else {
                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
            }
        } else {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
        }
    } else if ((0x200U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
        if ((0x100U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
            if ((0x80U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                if ((0x40U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                } else if ((0x20U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                  >> 4U)))) {
                        if ((8U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                        } else if ((4U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                        }
                    }
                } else {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                }
            } else if ((0x40U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                if ((0x20U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                } else if ((0x10U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                } else if ((8U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                } else if ((4U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    if ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                    } else if ((1U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                    }
                }
            } else if ((0x20U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                              >> 4U)))) {
                    if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                  >> 3U)))) {
                        if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                      >> 2U)))) {
                            if ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                if ((1U & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)))) {
                                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                                }
                            } else if ((1U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                            }
                        }
                    }
                }
            } else if ((0x10U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                if ((8U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    if ((4U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                    } else if ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                        if ((1U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                        }
                    } else {
                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                    }
                } else if ((4U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                } else if ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                } else if ((1U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                }
            } else if ((8U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                if ((4U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                } else if ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    if ((1U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                    }
                } else {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                }
            } else if ((4U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                if ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    if ((1U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
                    }
                }
            } else if ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
            }
        } else {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
        }
    } else {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
    }
    if (((0x3a0U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)) 
         | ((0x3a1U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)) 
            | ((0x3a2U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)) 
               | ((0x3a3U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)) 
                  | ((0x3b0U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)) 
                     | ((0x3b1U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)) 
                        | ((0x3b2U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)) 
                           | ((0x3b3U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)) 
                              | ((0x3b4U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)) 
                                 | ((0x3b5U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)) 
                                    | ((0x3b6U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)) 
                                       | ((0x3b7U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)) 
                                          | ((0x3b8U 
                                              == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)) 
                                             | ((0x3b9U 
                                                 == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)) 
                                                | ((0x3baU 
                                                    == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)) 
                                                   | ((0x3bbU 
                                                       == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)) 
                                                      | ((0x3bcU 
                                                          == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)) 
                                                         | ((0x3bdU 
                                                             == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)) 
                                                            | ((0x3beU 
                                                                == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)) 
                                                               | (0x3bfU 
                                                                  == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)))))))))))))))))))))) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__illegal_csr = 1U;
    }
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dbg_csr = 0U;
    if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                  >> 0xbU)))) {
        if ((0x400U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
            if ((0x200U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                if ((0x100U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    if ((0x80U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                        if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                      >> 6U)))) {
                            if ((0x20U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                if ((0x10U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                    if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                  >> 3U)))) {
                                        if ((1U & (~ 
                                                   ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                    >> 2U)))) {
                                            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dbg_csr = 1U;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imm_i_type 
        = (((- (IData)((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_rdata_id_o 
                        >> 0x1fU))) << 0xcU) | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT____VdfgRegularize_h50863dbe_1_29 
        = ((((0x105U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)) 
             << 4U) | (((0x7b2U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)) 
                        << 3U) | ((0x302U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)) 
                                  << 2U))) | (((1U 
                                                == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)) 
                                               << 1U) 
                                              | (0U 
                                                 == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__zimm_rs1_type_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__instr_rs1;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__instr_fetch_err_plus2_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_fetch_err_plus2_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__instr_compressed_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_rdata_c_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__instr_fetch_err_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_fetch_err_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__pc_id_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__pc_id_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__instr_is_compressed_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_is_compressed_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__illegal_c_insn_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__illegal_c_insn_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__instr_rdata_alu_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_rdata_alu_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__instr_rdata_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_rdata_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__instr_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_rdata_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__raddr_b_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_raddr_b;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__rf_waddr_id_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_waddr_id;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__waddr_a_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__rf_waddr_wb;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__imm_s_type_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imm_s_type;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__imm_i_type_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__imm_i_type;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__zimm_rs1_type 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__zimm_rs1_type_o;
}

VL_INLINE_OPT void Vtop___024root___nba_comb__TOP__0(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___nba_comb__TOP__0\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Body
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_valid 
        = ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__branch_discard_q)) 
           & (IData)(vlSelfRef.ibex_simple_system__DOT__u_ram__DOT__b_rvalid_o));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_load_resp_intg_err 
        = ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_we_q)) 
           & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT____VdfgRegularize_he001948a_0_3));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_store_resp_intg_err 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT____VdfgRegularize_he001948a_0_3) 
           & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_we_q));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_update = 0U;
    if ((4U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__ls_fsm_cs))) {
        if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__ls_fsm_cs) 
                      >> 1U)))) {
            if ((1U & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__ls_fsm_cs)))) {
                if (vlSelfRef.ibex_simple_system__DOT__host_rvalid
                    [0U]) {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_update 
                        = (1U & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_we_q)));
                }
            }
        }
    } else if ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__ls_fsm_cs))) {
        if ((1U & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__ls_fsm_cs)))) {
            if ((vlSelfRef.ibex_simple_system__DOT__host_rvalid
                 [0U] | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__pmp_err_q))) {
                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_update 
                    = (1U & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_we_q)));
            }
        }
    }
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_mis_rvalid_1 
        = (((2U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__ls_fsm_cs)) 
            | (4U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__ls_fsm_cs))) 
           & vlSelfRef.ibex_simple_system__DOT__host_rvalid
           [0U]);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_mis_rvalid_2 
        = ((0U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__ls_fsm_cs)) 
           & (vlSelfRef.ibex_simple_system__DOT__host_rvalid
              [0U] & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_mis_2_en_q)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_resp_valid 
        = ((vlSelfRef.ibex_simple_system__DOT__host_rvalid
            [0U] | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__pmp_err_q)) 
           & (0U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__ls_fsm_cs)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__rdata_d[0U] 
        = (IData)((((QData)((IData)(((4U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_q))
                                      ? vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__rdata_q[2U]
                                      : vlSelfRef.ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__b_rdata_o))) 
                    << 0x20U) | (QData)((IData)(((2U 
                                                  & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_q))
                                                  ? 
                                                 vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__rdata_q[1U]
                                                  : vlSelfRef.ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__b_rdata_o)))));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__rdata_d[1U] 
        = (IData)(((((QData)((IData)(((4U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_q))
                                       ? vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__rdata_q[2U]
                                       : vlSelfRef.ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__b_rdata_o))) 
                     << 0x20U) | (QData)((IData)(((2U 
                                                   & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_q))
                                                   ? 
                                                  vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__rdata_q[1U]
                                                   : vlSelfRef.ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__b_rdata_o)))) 
                   >> 0x20U));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__rdata_d[2U] 
        = vlSelfRef.ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__b_rdata_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__rdata 
        = ((1U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_q))
            ? vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__rdata_q[0U]
            : vlSelfRef.ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__b_rdata_o);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int = 0U;
    if ((0x800U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
        if ((0x400U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
            if ((0x200U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                if ((0x100U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                  >> 7U)))) {
                        if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                      >> 6U)))) {
                            if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                          >> 5U)))) {
                                if ((0x10U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                    if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                  >> 3U)))) {
                                        if ((4U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                            if ((1U 
                                                 & (~ 
                                                    ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                     >> 1U)))) {
                                                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int = 0U;
                                            }
                                        } else if (
                                                   (2U 
                                                    & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                                                = (
                                                   (1U 
                                                    & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                                    ? 0U
                                                    : 0x16U);
                                        } else if (
                                                   (1U 
                                                    & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int = 0U;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else if ((0x200U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
            if ((0x100U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                if ((0x80U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                  >> 6U)))) {
                        if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                      >> 5U)))) {
                            if ((0x10U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                                    = (IData)((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                                               [vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx] 
                                               >> 0x20U));
                            } else if ((8U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                                    = (IData)((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                                               [vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx] 
                                               >> 0x20U));
                            } else if ((4U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                                    = (IData)((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                                               [vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx] 
                                               >> 0x20U));
                            } else if ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                                    = (IData)((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                                               [vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx] 
                                               >> 0x20U));
                            } else if ((1U & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)))) {
                                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                                    = (IData)((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                                               [vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx] 
                                               >> 0x20U));
                            }
                        }
                    }
                } else if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                     >> 6U)))) {
                    if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                  >> 5U)))) {
                        if ((0x10U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                                = (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                                          [vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx]);
                        } else if ((8U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                                = (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                                          [vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx]);
                        } else if ((4U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                                = (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                                          [vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx]);
                        } else if ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                                = (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                                          [vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx]);
                        } else if ((1U & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)))) {
                            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                                = (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter
                                          [vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx]);
                        }
                    }
                }
            }
        }
    } else if ((0x400U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
        if ((0x200U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
            if ((0x100U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                if ((0x80U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    if ((0x40U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                        if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                      >> 5U)))) {
                            if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                          >> 4U)))) {
                                if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                              >> 3U)))) {
                                    if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                  >> 2U)))) {
                                        if ((1U & (~ 
                                                   ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                    >> 1U)))) {
                                            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                                                = (
                                                   (1U 
                                                    & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                                    ? 0U
                                                    : 
                                                   (((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__cpuctrlsts_ic_scr_key_valid_q) 
                                                     << 8U) 
                                                    | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__cpuctrlsts_part_q)));
                                        }
                                    }
                                }
                            }
                        }
                    } else if ((0x20U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                        if ((0x10U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                            if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                          >> 3U)))) {
                                if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                              >> 2U)))) {
                                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                                        = ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                            ? ((1U 
                                                & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                                ? vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dscratch1_q
                                                : vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dscratch0_q)
                                            : ((1U 
                                                & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                                ? vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__depc_q
                                                : vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dcsr_q));
                                }
                            }
                        } else if ((8U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                            if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                          >> 2U)))) {
                                if ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                    if ((1U & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)))) {
                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int = 0U;
                                    }
                                } else if ((1U & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)))) {
                                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int = 0U;
                                }
                            }
                        } else if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                             >> 2U)))) {
                            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                                = ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                    ? ((1U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                        ? 0U : vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__tmatch_value_rdata)
                                    : ((1U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                        ? vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__tmatch_control_rdata
                                        : vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__tselect_rdata));
                        }
                    }
                }
            }
        } else if ((0x100U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
            if ((0x80U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                              >> 6U)))) {
                    if ((0x20U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                        if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                      >> 4U)))) {
                            if ((8U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                              >> 2U)))) {
                                    if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                  >> 1U)))) {
                                        if ((1U & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)))) {
                                            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int = 0U;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    } else if ((0x200U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
        if ((0x100U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
            if ((0x80U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                              >> 6U)))) {
                    if ((0x20U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                        if ((0x10U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                                = ((8U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                    ? ((4U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                        ? ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                            ? ((1U 
                                                & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                                ? vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_addr_rdata
                                               [0xfU]
                                                : vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_addr_rdata
                                               [0xeU])
                                            : ((1U 
                                                & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                                ? vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_addr_rdata
                                               [0xdU]
                                                : vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_addr_rdata
                                               [0xcU]))
                                        : ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                            ? ((1U 
                                                & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                                ? vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_addr_rdata
                                               [0xbU]
                                                : vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_addr_rdata
                                               [0xaU])
                                            : ((1U 
                                                & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                                ? vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_addr_rdata
                                               [9U]
                                                : vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_addr_rdata
                                               [8U])))
                                    : ((4U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                        ? ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                            ? ((1U 
                                                & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                                ? vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_addr_rdata
                                               [7U]
                                                : vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_addr_rdata
                                               [6U])
                                            : ((1U 
                                                & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                                ? vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_addr_rdata
                                               [5U]
                                                : vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_addr_rdata
                                               [4U]))
                                        : ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                            ? ((1U 
                                                & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                                ? vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_addr_rdata
                                               [3U]
                                                : vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_addr_rdata
                                               [2U])
                                            : ((1U 
                                                & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                                ? vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_addr_rdata
                                               [1U]
                                                : vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_addr_rdata
                                               [0U]))));
                        } else if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                             >> 3U)))) {
                            if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                          >> 2U)))) {
                                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                                    = ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                        ? ((1U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                            ? (((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_cfg_rdata
                                                 [0xfU] 
                                                 << 0x18U) 
                                                | (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_cfg_rdata
                                                   [0xeU] 
                                                   << 0x10U)) 
                                               | ((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_cfg_rdata
                                                   [0xdU] 
                                                   << 8U) 
                                                  | vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_cfg_rdata
                                                  [0xcU]))
                                            : (((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_cfg_rdata
                                                 [0xbU] 
                                                 << 0x18U) 
                                                | (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_cfg_rdata
                                                   [0xaU] 
                                                   << 0x10U)) 
                                               | ((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_cfg_rdata
                                                   [9U] 
                                                   << 8U) 
                                                  | vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_cfg_rdata
                                                  [8U])))
                                        : ((1U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                            ? (((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_cfg_rdata
                                                 [7U] 
                                                 << 0x18U) 
                                                | (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_cfg_rdata
                                                   [6U] 
                                                   << 0x10U)) 
                                               | ((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_cfg_rdata
                                                   [5U] 
                                                   << 8U) 
                                                  | vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_cfg_rdata
                                                  [4U]))
                                            : (((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_cfg_rdata
                                                 [3U] 
                                                 << 0x18U) 
                                                | (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_cfg_rdata
                                                   [2U] 
                                                   << 0x10U)) 
                                               | ((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_cfg_rdata
                                                   [1U] 
                                                   << 8U) 
                                                  | vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__pmp_cfg_rdata
                                                  [0U]))));
                            }
                        }
                    }
                }
            } else if ((0x40U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                              >> 5U)))) {
                    if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                  >> 4U)))) {
                        if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                      >> 3U)))) {
                            if ((4U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                              >> 1U)))) {
                                    if ((1U & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)))) {
                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int = 0U;
                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                                            = (0xfffffff7U 
                                               & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int);
                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                                            = ((0xffffff7fU 
                                                & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int) 
                                               | ((IData)(vlSelfRef.ibex_simple_system__DOT__timer_irq) 
                                                  << 7U));
                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                                            = (0xfffff7ffU 
                                               & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int);
                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                                            = (0x8000ffffU 
                                               & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int);
                                    }
                                }
                            } else {
                                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                                    = ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                        ? ((1U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                            ? vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mtval_q
                                            : (((IData)(
                                                        (0U 
                                                         != 
                                                         (0x60U 
                                                          & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mcause_csr__DOT__rdata_q)))) 
                                                << 0x1fU) 
                                               | ((((0x40U 
                                                     & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mcause_csr__DOT__rdata_q))
                                                     ? 0x3ffffffU
                                                     : 0U) 
                                                   << 5U) 
                                                  | (0x1fU 
                                                     & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mcause_csr__DOT__rdata_q)))))
                                        : ((1U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))
                                            ? vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mepc_q
                                            : vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mscratch_q));
                            }
                        }
                    }
                }
            } else if ((0x20U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                if ((0x10U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmevent
                        [vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx];
                } else if ((8U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmevent
                        [vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx];
                } else if ((4U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmevent
                        [vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx];
                } else if ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    if ((1U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmevent
                            [vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx];
                    }
                } else if ((1U & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)))) {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcountinhibit;
                }
            } else if ((0x10U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                if ((8U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                  >> 2U)))) {
                        if ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                            if ((1U & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)))) {
                                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int = 0U;
                            }
                        }
                    }
                } else if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                     >> 2U)))) {
                    if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                  >> 1U)))) {
                        if ((1U & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)))) {
                            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int = 0U;
                        }
                    }
                }
            } else if ((8U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                              >> 2U)))) {
                    if ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                        if ((1U & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)))) {
                            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int = 0U;
                        }
                    }
                }
            } else if ((4U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                if ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    if ((1U & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)))) {
                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int = 0U;
                    }
                } else if ((1U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mtvec_q;
                } else {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int = 0U;
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                        = ((0xfffffff7U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int) 
                           | (8U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mie_csr__DOT__rdata_q 
                                    >> 0xeU)));
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                        = ((0xffffff7fU & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int) 
                           | (0x80U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mie_csr__DOT__rdata_q 
                                       >> 9U)));
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                        = ((0xfffff7ffU & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int) 
                           | (0x800U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mie_csr__DOT__rdata_q 
                                        >> 4U)));
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                        = ((0x8000ffffU & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int) 
                           | (0x7fff0000U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mie_csr__DOT__rdata_q 
                                             << 0x10U)));
                }
            } else if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                 >> 1U)))) {
                if ((1U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int = 0x40101104U;
                } else {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int = 0U;
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                        = ((0xfffffff7U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int) 
                           | ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_mstatus_mie_o) 
                              << 3U));
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                        = ((0xffffff7fU & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int) 
                           | (0x80U & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstatus_csr__DOT__rdata_q) 
                                       << 3U)));
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                        = ((0xffffe7ffU & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int) 
                           | (0x1800U & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstatus_csr__DOT__rdata_q) 
                                         << 9U)));
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                        = ((0xfffdffffU & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int) 
                           | (0x20000U & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstatus_csr__DOT__rdata_q) 
                                          << 0x10U)));
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int 
                        = ((0xffdfffffU & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int) 
                           | ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_mstatus_tw_o) 
                              << 0x15U));
                }
            }
        }
    }
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__in_valid_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_valid;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT____VdfgRegularize_hb4cbc9db_0_23 
        = ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_q)) 
           & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_valid));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT____VdfgRegularize_hb4cbc9db_0_20 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_valid) 
           & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT____VdfgRegularize_hb4cbc9db_0_19));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT____VdfgRegularize_hb4cbc9db_0_15 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_valid) 
           & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT____VdfgRegularize_hb4cbc9db_0_14));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid 
        = (1U & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_q) 
                 | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_valid)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_unaligned 
        = (1U & (((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_q) 
                  >> 1U) | ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_q) 
                            & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_valid))));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__lsu_load_resp_intg_err_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_load_resp_intg_err;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__load_resp_intg_err_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_load_resp_intg_err;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__lsu_store_resp_intg_err_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_store_resp_intg_err;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__store_resp_intg_err_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_store_resp_intg_err;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__mem_resp_intg_err 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_load_resp_intg_err) 
           | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_store_resp_intg_err));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__alert_major_bus_o 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_load_resp_intg_err) 
           | ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_intg_err) 
              | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_store_resp_intg_err)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_mis_2_en_d 
        = ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_mis_rvalid_2)) 
           & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_mis_rvalid_1) 
              | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_mis_2_en_q)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__lsu_resp_valid_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_resp_valid;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__lsu_resp_valid_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_resp_valid;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__lsu_resp_valid_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_resp_valid;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__rdata_unaligned 
        = ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_q))
            ? ((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__rdata_q[1U] 
                << 0x10U) | (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__rdata 
                             >> 0x10U)) : ((vlSelfRef.ibex_simple_system__DOT__u_ram__DOT__u_ram__DOT__gen_generic__DOT__u_impl_generic__DOT__b_rdata_o 
                                            << 0x10U) 
                                           | (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__rdata 
                                              >> 0x10U)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_rdata 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_int;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT____VdfgRegularize_hb4cbc9db_0_10 
        = (1U & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT____VdfgRegularize_hb4cbc9db_0_23) 
                 | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_q)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT____VdfgRegularize_hb4cbc9db_0_21 
        = (IData)((((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_q) 
                    >> 2U) | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT____VdfgRegularize_hb4cbc9db_0_20)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT____VdfgRegularize_hb4cbc9db_0_16 
        = (1U & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT____VdfgRegularize_hb4cbc9db_0_15) 
                 | ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_q) 
                    >> 1U)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__mem_resp_intg_err_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__mem_resp_intg_err;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__g_no_intg_irq_int__DOT__unused_mem_resp_intg_err_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__mem_resp_intg_err;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__core_alert_major_bus 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__alert_major_bus_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__alert_major_bus_o 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__alert_major_bus_o) 
           | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__lockstep_alert_major_bus));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__out_rdata_o 
        = ((1U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__instr_addr_q)
            ? vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__rdata_unaligned
            : vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__rdata);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__csr_rdata_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_rdata;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_pushed 
        = (((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT____VdfgRegularize_hb4cbc9db_0_21) 
            << 2U) | (((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT____VdfgRegularize_hb4cbc9db_0_16) 
                       << 1U) | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT____VdfgRegularize_hb4cbc9db_0_10)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__alert_major_bus_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__alert_major_bus_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__fetch_rdata 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__out_rdata_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__rdata_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__out_rdata_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_is_compressed_out 
        = (3U != (3U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__out_rdata_o));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__out_rdata_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_is_compressed 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_is_compressed_out;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__is_compressed_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_is_compressed_out;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__instr_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__instr_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__illegal_instr_o = 0U;
    if ((2U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)) {
        if ((1U & (~ vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata))) {
            if ((0x8000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)) {
                if ((0x4000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)) {
                    if ((1U & (~ (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                  >> 0xdU)))) {
                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__instr_o 
                            = (0x12023U | (((0xc000000U 
                                             & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                << 0x13U)) 
                                            | ((0x2000000U 
                                                & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                   << 0xdU)) 
                                               | (0x1f00000U 
                                                  & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                     << 0x12U)))) 
                                           | (0xe00U 
                                              & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)));
                    }
                    if ((0x2000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)) {
                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__illegal_instr_o = 1U;
                    }
                } else {
                    if ((1U & (~ (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                  >> 0xdU)))) {
                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__instr_o 
                            = ((0x1000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)
                                ? ((0U != (0x1fU & 
                                           (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                            >> 2U)))
                                    ? (0x33U | ((0x1f00000U 
                                                 & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                    << 0x12U)) 
                                                | ((0xf8000U 
                                                    & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                       << 8U)) 
                                                   | (0xf80U 
                                                      & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata))))
                                    : ((0U == (0x1fU 
                                               & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                  >> 7U)))
                                        ? 0x100073U
                                        : (0xe7U | 
                                           (0xf8000U 
                                            & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                               << 8U)))))
                                : ((0U != (0x1fU & 
                                           (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                            >> 2U)))
                                    ? (0x33U | ((0x1f00000U 
                                                 & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                    << 0x12U)) 
                                                | (0xf80U 
                                                   & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)))
                                    : (0x67U | (0xf8000U 
                                                & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                   << 8U)))));
                    }
                    if ((0x2000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)) {
                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__illegal_instr_o = 1U;
                    } else if ((1U & (~ (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                         >> 0xcU)))) {
                        if ((0U == (0x1fU & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                             >> 2U)))) {
                            if ((0U == (0x1fU & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                 >> 7U)))) {
                                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__illegal_instr_o = 1U;
                            }
                        }
                    }
                }
            } else if ((0x4000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)) {
                if ((1U & (~ (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                              >> 0xdU)))) {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__instr_o 
                        = (0x12003U | ((0xc000000U 
                                        & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                           << 0x18U)) 
                                       | ((0x2000000U 
                                           & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                              << 0xdU)) 
                                          | ((0x1c00000U 
                                              & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                 << 0x12U)) 
                                             | (0xf80U 
                                                & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)))));
                }
                if ((0x2000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)) {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__illegal_instr_o = 1U;
                } else if ((0U == (0x1fU & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                            >> 7U)))) {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__illegal_instr_o = 1U;
                }
            } else {
                if ((1U & (~ (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                              >> 0xdU)))) {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__instr_o 
                        = (0x1013U | ((0x1f00000U & 
                                       (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                        << 0x12U)) 
                                      | ((0xf8000U 
                                          & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                             << 8U)) 
                                         | (0xf80U 
                                            & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata))));
                }
                if ((0x2000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)) {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__illegal_instr_o = 1U;
                } else if ((0x1000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)) {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__illegal_instr_o = 1U;
                }
            }
        }
    } else if ((1U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)) {
        if ((0x8000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)) {
            if ((0x4000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)) {
                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__instr_o 
                    = (0x40063U | (((- (IData)((1U 
                                                & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                   >> 0xcU)))) 
                                    << 0x1cU) | ((0xc000000U 
                                                  & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                     << 0x15U)) 
                                                 | ((0x2000000U 
                                                     & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                        << 0x17U)) 
                                                    | ((0x38000U 
                                                        & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                           << 8U)) 
                                                       | (((0x1000U 
                                                            & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                               >> 1U)) 
                                                           | (0xc00U 
                                                              & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)) 
                                                          | ((0x300U 
                                                              & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                                 << 5U)) 
                                                             | (0x80U 
                                                                & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                                   >> 5U)))))))));
            } else if ((0x2000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)) {
                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__instr_o 
                    = (0x6fU | (((((0x80000000U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                   << 0x13U)) 
                                   | (0x40000000U & 
                                      (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                       << 0x16U))) 
                                  | ((0x30000000U & 
                                      (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                       << 0x13U)) | 
                                     ((0x8000000U & 
                                       (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                        << 0x15U)) 
                                      | (0x4000000U 
                                         & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                            << 0x13U))))) 
                                 | ((0x2000000U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                   << 0x17U)) 
                                    | ((0x1000000U 
                                        & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                           << 0xdU)) 
                                       | (0xe00000U 
                                          & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                             << 0x12U))))) 
                                | ((0x1ff000U & ((- (IData)(
                                                            (1U 
                                                             & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                                >> 0xcU)))) 
                                                 << 0xcU)) 
                                   | (0x80U & ((~ (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                   >> 0xfU)) 
                                               << 7U)))));
            } else if ((0x800U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)) {
                if ((0x400U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)) {
                    if ((1U & (~ (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                  >> 0xcU)))) {
                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__instr_o 
                            = ((0x40U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)
                                ? ((0x20U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)
                                    ? (0x847433U | 
                                       ((0x700000U 
                                         & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                            << 0x12U)) 
                                        | ((0x38000U 
                                            & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                               << 8U)) 
                                           | (0x380U 
                                              & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata))))
                                    : (0x846433U | 
                                       ((0x700000U 
                                         & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                            << 0x12U)) 
                                        | ((0x38000U 
                                            & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                               << 8U)) 
                                           | (0x380U 
                                              & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)))))
                                : ((0x20U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)
                                    ? (0x844433U | 
                                       ((0x700000U 
                                         & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                            << 0x12U)) 
                                        | ((0x38000U 
                                            & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                               << 8U)) 
                                           | (0x380U 
                                              & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata))))
                                    : (0x40840433U 
                                       | ((0x700000U 
                                           & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                              << 0x12U)) 
                                          | ((0x38000U 
                                              & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                 << 8U)) 
                                             | (0x380U 
                                                & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata))))));
                    }
                } else {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__instr_o 
                        = (0x47413U | (((((- (IData)(
                                                     (1U 
                                                      & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                         >> 0xcU)))) 
                                          << 0x1aU) 
                                         | (0x2000000U 
                                            & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                               << 0xdU))) 
                                        | (0x1f00000U 
                                           & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                              << 0x12U))) 
                                       | ((0x38000U 
                                           & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                              << 8U)) 
                                          | (0x380U 
                                             & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata))));
                }
            } else {
                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__instr_o 
                    = (0x45413U | ((0x40000000U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                   << 0x14U)) 
                                   | (((0x1f00000U 
                                        & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                           << 0x12U)) 
                                       | (0x38000U 
                                          & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                             << 8U))) 
                                      | (0x380U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata))));
            }
            if ((1U & (~ (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                          >> 0xeU)))) {
                if ((1U & (~ (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                              >> 0xdU)))) {
                    if ((0x800U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)) {
                        if ((0x400U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)) {
                            if ((0x1000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)) {
                                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__illegal_instr_o = 1U;
                            }
                        }
                    } else if ((0x1000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)) {
                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__illegal_instr_o = 1U;
                    }
                }
            }
        } else if ((0x4000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)) {
            if ((0x2000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)) {
                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__instr_o 
                    = (0x37U | (((- (IData)((1U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                   >> 0xcU)))) 
                                 << 0x11U) | ((0x1f000U 
                                               & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                  << 0xaU)) 
                                              | (0xf80U 
                                                 & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata))));
                if ((2U == (0x1fU & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                     >> 7U)))) {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__instr_o 
                        = (0x10113U | (((- (IData)(
                                                   (1U 
                                                    & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                       >> 0xcU)))) 
                                        << 0x1dU) | 
                                       (((0x18000000U 
                                          & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                             << 0x18U)) 
                                         | (0x4000000U 
                                            & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                               << 0x15U))) 
                                        | ((0x2000000U 
                                            & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                               << 0x17U)) 
                                           | (0x1000000U 
                                              & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                 << 0x12U))))));
                }
                if ((0U == ((0x20U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                      >> 7U)) | (0x1fU 
                                                 & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                    >> 2U))))) {
                    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__illegal_instr_o = 1U;
                }
            } else {
                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__instr_o 
                    = (0x13U | (((- (IData)((1U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                   >> 0xcU)))) 
                                 << 0x1aU) | ((0x2000000U 
                                               & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                  << 0xdU)) 
                                              | ((0x1f00000U 
                                                  & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                     << 0x12U)) 
                                                 | (0xf80U 
                                                    & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)))));
            }
        } else {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__instr_o 
                = ((0x2000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)
                    ? (0x6fU | (((((0x80000000U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                   << 0x13U)) 
                                   | (0x40000000U & 
                                      (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                       << 0x16U))) 
                                  | ((0x30000000U & 
                                      (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                       << 0x13U)) | 
                                     ((0x8000000U & 
                                       (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                        << 0x15U)) 
                                      | (0x4000000U 
                                         & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                            << 0x13U))))) 
                                 | ((0x2000000U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                   << 0x17U)) 
                                    | ((0x1000000U 
                                        & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                           << 0xdU)) 
                                       | (0xe00000U 
                                          & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                             << 0x12U))))) 
                                | ((0x1ff000U & ((- (IData)(
                                                            (1U 
                                                             & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                                >> 0xcU)))) 
                                                 << 0xcU)) 
                                   | (0x80U & ((~ (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                   >> 0xfU)) 
                                               << 7U)))))
                    : (0x13U | ((((- (IData)((1U & 
                                              (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                               >> 0xcU)))) 
                                  << 0x1aU) | ((0x2000000U 
                                                & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                   << 0xdU)) 
                                               | (0x1f00000U 
                                                  & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                     << 0x12U)))) 
                                | ((0xf8000U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                << 8U)) 
                                   | (0xf80U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)))));
        }
    } else if ((0x8000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)) {
        if ((0x4000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)) {
            if ((1U & (~ (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                          >> 0xdU)))) {
                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__instr_o 
                    = (0x842023U | ((((0x4000000U & 
                                       (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                        << 0x15U)) 
                                      | (0x2000000U 
                                         & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                            << 0xdU))) 
                                     | (0x700000U & 
                                        (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                         << 0x12U))) 
                                    | ((0x38000U & 
                                        (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                         << 8U)) | 
                                       ((0xc00U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata) 
                                        | (0x200U & 
                                           (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                            << 3U))))));
            }
            if ((0x2000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)) {
                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__illegal_instr_o = 1U;
            }
        } else {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__illegal_instr_o = 1U;
        }
    } else if ((0x4000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)) {
        if ((1U & (~ (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                      >> 0xdU)))) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__instr_o 
                = (0x42403U | ((0x4000000U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                              << 0x15U)) 
                               | ((0x3800000U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                 << 0xdU)) 
                                  | ((0x400000U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                   << 0x10U)) 
                                     | ((0x38000U & 
                                         (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                          << 8U)) | 
                                        (0x380U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                   << 5U)))))));
        }
        if ((0x2000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__illegal_instr_o = 1U;
        }
    } else {
        if ((1U & (~ (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                      >> 0xdU)))) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__instr_o 
                = (0x10413U | ((0x3c000000U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                               << 0x13U)) 
                               | ((0x3000000U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                 << 0xdU)) 
                                  | ((0x800000U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                                   << 0x12U)) 
                                     | ((0x400000U 
                                         & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                            << 0x10U)) 
                                        | (0x380U & 
                                           (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                            << 5U)))))));
        }
        if ((0x2000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata)) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__illegal_instr_o = 1U;
        } else if ((0U == (0xffU & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_rdata 
                                    >> 5U)))) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__illegal_instr_o = 1U;
        }
    }
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_out 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__instr_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_decompressed 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__instr_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__illegal_c_instr_out 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__illegal_instr_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__illegal_c_insn 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__illegal_instr_o;
}

VL_INLINE_OPT void Vtop___024root___nba_sequent__TOP__5(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___nba_sequent__TOP__5\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Body
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mip 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_timer__DOT__interrupt_q) 
           << 0x10U);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__cycle 
        = vlSelfRef.__Vdly__ibex_simple_system__DOT__u_top__DOT__u_ibex_tracer__DOT__cycle;
}

VL_INLINE_OPT void Vtop___024root___nba_sequent__TOP__7(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___nba_sequent__TOP__7\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Body
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__ctrl_fsm_cs 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__rst_sys_n)
            ? (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__ctrl_fsm_ns)
            : 0U);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_valid_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__instr_valid_id;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__instr_valid_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_valid_i;
}

VL_INLINE_OPT void Vtop___024root___nba_comb__TOP__1(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___nba_comb__TOP__1\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Body
    if (vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__host_sel_resp) {
        vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__host_rdata_o[0U] = 0U;
        vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__host_err_o[0U] = 0U;
    } else {
        vlSelfRef.ibex_simple_system__DOT__u_bus__DOT____Vlvbound_h6ad861f2__0 
            = ((2U >= (IData)(vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__device_sel_resp))
                ? vlSelfRef.ibex_simple_system__DOT__device_rdata
               [vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__device_sel_resp]
                : 0U);
        vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__host_rdata_o[0U] 
            = vlSelfRef.ibex_simple_system__DOT__u_bus__DOT____Vlvbound_h6ad861f2__0;
        vlSelfRef.ibex_simple_system__DOT__u_bus__DOT____Vlvbound_h984de552__0 
            = (((2U >= (IData)(vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__device_sel_resp)) 
                && vlSelfRef.ibex_simple_system__DOT__device_err
                [vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__device_sel_resp]) 
               | (IData)(vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__decode_err_resp));
        vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__host_err_o[0U] 
            = vlSelfRef.ibex_simple_system__DOT__u_bus__DOT____Vlvbound_h984de552__0;
    }
    vlSelfRef.ibex_simple_system__DOT__host_rdata[0U] 
        = vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__host_rdata_o
        [0U];
    vlSelfRef.ibex_simple_system__DOT__host_err[0U] 
        = vlSelfRef.ibex_simple_system__DOT__u_bus__DOT__host_err_o
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__data_rdata_i 
        = vlSelfRef.ibex_simple_system__DOT__host_rdata
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core 
        = vlSelfRef.ibex_simple_system__DOT__host_rdata
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__data_err_i 
        = vlSelfRef.ibex_simple_system__DOT__host_err
        [0U];
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__data_rdata_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__data_rdata_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_err_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__data_err_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_rdata_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__data_rdata_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__data_err_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_err_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_bus_err_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__data_err_i;
}

VL_INLINE_OPT void Vtop___024root___nba_comb__TOP__3(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___nba_comb__TOP__3\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Init
    CData/*0:0*/ __VdfgRegularize_hd87f99a1_2_0;
    __VdfgRegularize_hd87f99a1_2_0 = 0;
    // Body
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irqs 
        = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mip 
           & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mie_csr__DOT__rdata_q);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_or_pmp_err 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__lsu_err_q) 
           | (vlSelfRef.ibex_simple_system__DOT__host_err
              [0U] | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__pmp_err_q)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_mis_bus_err_1_d 
        = ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_mis_rvalid_2)) 
           & (((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_mis_rvalid_1) 
               & vlSelfRef.ibex_simple_system__DOT__host_err
               [0U]) | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_mis_bus_err_1_q)));
    if ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_offset_q))) {
        if ((1U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_offset_q))) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_w_ext 
                = ((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core 
                    << 8U) | (0xffU & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_q 
                                       >> 0x10U)));
            if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_sign_ext_q) {
                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_b_ext 
                    = (((- (IData)((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core 
                                    >> 0x1fU))) << 8U) 
                       | (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core 
                          >> 0x18U));
                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_h_ext 
                    = (((- (IData)((1U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core 
                                          >> 7U)))) 
                        << 0x10U) | ((0xff00U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core 
                                                 << 8U)) 
                                     | (0xffU & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_q 
                                                 >> 0x10U))));
            } else {
                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_b_ext 
                    = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core 
                       >> 0x18U);
                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_h_ext 
                    = ((0xff00U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core 
                                   << 8U)) | (0xffU 
                                              & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_q 
                                                 >> 0x10U)));
            }
        } else {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_w_ext 
                = ((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core 
                    << 0x10U) | (0xffffU & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_q 
                                            >> 8U)));
            if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_sign_ext_q) {
                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_b_ext 
                    = (((- (IData)((1U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core 
                                          >> 0x17U)))) 
                        << 8U) | (0xffU & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core 
                                           >> 0x10U)));
                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_h_ext 
                    = (((- (IData)((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core 
                                    >> 0x1fU))) << 0x10U) 
                       | (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core 
                          >> 0x10U));
            } else {
                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_b_ext 
                    = (0xffU & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core 
                                >> 0x10U));
                vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_h_ext 
                    = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core 
                       >> 0x10U);
            }
        }
    } else if ((1U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_offset_q))) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_w_ext 
            = ((vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core 
                << 0x18U) | vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_q);
        if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_sign_ext_q) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_b_ext 
                = (((- (IData)((1U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core 
                                      >> 0xfU)))) << 8U) 
                   | (0xffU & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core 
                               >> 8U)));
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_h_ext 
                = (((- (IData)((1U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core 
                                      >> 0x17U)))) 
                    << 0x10U) | (0xffffU & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core 
                                            >> 8U)));
        } else {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_b_ext 
                = (0xffU & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core 
                            >> 8U));
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_h_ext 
                = (0xffffU & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core 
                              >> 8U));
        }
    } else {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_w_ext 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core;
        if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_sign_ext_q) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_b_ext 
                = (((- (IData)((1U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core 
                                      >> 7U)))) << 8U) 
                   | (0xffU & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core));
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_h_ext 
                = (((- (IData)((1U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core 
                                      >> 0xfU)))) << 0x10U) 
                   | (0xffffU & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core));
        } else {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_b_ext 
                = (0xffU & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core);
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_h_ext 
                = (0xffffU & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__data_rdata_core);
        }
    }
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__aligned_is_compressed 
        = ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__err)) 
           & (3U != (3U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__rdata)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__unaligned_is_compressed 
        = ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__err)) 
           & (3U != (3U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__rdata 
                           >> 0x10U))));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__stall_mem 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_valid_id_q) 
           & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__data_req_o) 
              & ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_resp_valid)) 
                 | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_first_cycle))));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_wdata_int 
        = ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_op))
            ? ((1U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_op))
                ? ((~ vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_wdata) 
                   & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_o)
                : (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_wdata 
                   | vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_rdata_o))
            : vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_wdata);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__multicycle_done 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__data_req_o)
            ? (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_resp_valid)
            : (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_valid));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_wdata_id_o 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_wdata_sel)
            ? ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_wdata_sel)
                ? vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_rdata
                : vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__result_ex)
            : vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__result_ex);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__unused_irq_timer 
        = (1U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irqs 
                 >> 0x10U));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__irqs_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irqs;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__irqs_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irqs;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__mfip_id = 0U;
    if ((0x4000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irqs)) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__mfip_id = 0xeU;
    }
    if ((0x2000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irqs)) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__mfip_id = 0xdU;
    }
    if ((0x1000U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irqs)) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__mfip_id = 0xcU;
    }
    if ((0x800U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irqs)) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__mfip_id = 0xbU;
    }
    if ((0x400U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irqs)) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__mfip_id = 0xaU;
    }
    if ((0x200U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irqs)) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__mfip_id = 9U;
    }
    if ((0x100U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irqs)) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__mfip_id = 8U;
    }
    if ((0x80U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irqs)) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__mfip_id = 7U;
    }
    if ((0x40U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irqs)) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__mfip_id = 6U;
    }
    if ((0x20U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irqs)) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__mfip_id = 5U;
    }
    if ((0x10U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irqs)) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__mfip_id = 4U;
    }
    if ((8U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irqs)) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__mfip_id = 3U;
    }
    if ((4U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irqs)) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__mfip_id = 2U;
    }
    if ((2U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irqs)) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__mfip_id = 1U;
    }
    if ((1U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irqs)) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__mfip_id = 0U;
    }
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irq_pending_o 
        = (0U != vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irqs);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_we_lsu 
        = ((0U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__ls_fsm_cs)) 
           & ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_or_pmp_err)) 
              & (vlSelfRef.ibex_simple_system__DOT__host_rvalid
                 [0U] & ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_we_q)) 
                         & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_intg_err))))));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__load_err_d 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_or_pmp_err) 
           & ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_we_q)) 
              & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_resp_valid)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__store_err_d 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_or_pmp_err) 
           & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_we_q) 
              & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_resp_valid)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_rdata_ext 
        = ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_type_q))
            ? vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_b_ext
            : ((1U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_type_q))
                ? vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_h_ext
                : vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__rdata_w_ext));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__err_unaligned 
        = (1U & ((2U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_q))
                  ? (((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__unaligned_is_compressed)) 
                      & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__err_q) 
                         >> 1U)) | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__err_q))
                  : (((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_q) 
                      & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__err_q)) 
                     | ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_err) 
                        & ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_q)) 
                           | (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__unaligned_is_compressed)))))));
    if ((1U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__instr_addr_q)) {
        if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__unaligned_is_compressed) {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__addr_incr_two = 1U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__out_valid_o 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid;
        } else {
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__addr_incr_two = 0U;
            vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__out_valid_o 
                = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid_unaligned;
        }
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__out_err_o 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__err_unaligned;
    } else {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__addr_incr_two 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__aligned_is_compressed;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__out_valid_o 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__valid;
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__out_err_o 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__err;
    }
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mscratch_csr__DOT__wr_data_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_wdata_int;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch0_csr__DOT__wr_data_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_wdata_int;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch1_csr__DOT__wr_data_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_wdata_int;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__counter_val_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_wdata_int;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counter_val_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_wdata_int;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__cpuctrlsts_part_wdata_raw 
        = (0xffU & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_wdata_int);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__gen_no_dit__DOT__unused_dit 
        = (1U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_wdata_int 
                 >> 1U));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__gen_no_dummy__DOT__unused_dummy_mask 
        = (7U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_wdata_int 
                 >> 3U));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mie_d 
        = ((0x20000U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_wdata_int 
                        << 0xeU)) | ((0x10000U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_wdata_int 
                                                  << 9U)) 
                                     | ((0x8000U & 
                                         (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_wdata_int 
                                          << 4U)) | 
                                        (0x7fffU & 
                                         (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_wdata_int 
                                          >> 0x10U)))));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__gen_no_dummy__DOT__unused_dummy_en 
        = (1U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_wdata_int 
                 >> 2U));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__gen_no_icache__DOT__unused_icen 
        = (1U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_wdata_int);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__cpuctrlsts_part_wdata 
        = (0xc0U & vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_wdata_int);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__rf_wdata_wb_mux[0U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_wdata_id_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_wdata_id 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__rf_wdata_id_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__irqs_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__irqs_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__irq_pending 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irq_pending_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__irq_pending_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irq_pending_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__irq_pending_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irq_pending_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__clock_en 
        = (1U & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__core_busy_q) 
                 | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irq_pending_o)));
    __VdfgRegularize_hd87f99a1_2_0 = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__irq_pending_o) 
                                      & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__irq_enabled));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__rf_we_lsu_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_we_lsu;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_rdata_valid 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_we_lsu;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__lsu_rdata_valid_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_we_lsu;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_load_err_raw 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__load_err_d;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__load_err_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__load_err_d;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_load_err 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__load_err_d;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_store_err_raw 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__store_err_d;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__store_err_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__store_err_d;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_store_err 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__store_err_d;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_resp_err 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__load_err_d) 
           | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__store_err_d));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__lsu_rdata_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_rdata_ext;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__rf_wdata_wb_mux[1U] 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_rdata_ext;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_rdata_d 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_resp_valid)
            ? vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_rdata_ext
            : vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_mem_rdata_q);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_wdata_lsu 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__data_rdata_ext;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__instr_addr_next 
        = (0x7fffffffU & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__instr_addr_q 
                          + ((2U & ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__addr_incr_two)) 
                                    << 1U)) | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__addr_incr_two))));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__fetch_valid_raw 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__out_valid_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__valid_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__out_valid_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__fetch_valid 
        = ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__nt_branch_mispredict_o)) 
           & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__out_valid_o));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mie_csr__DOT__wr_data_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mie_d;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__rf_wdata_id_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_wdata_id;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__irq_pending_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__irq_pending_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__core_clock_gate_i__DOT__en_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__clock_en;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__core_sleep_o 
        = (1U & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__clock_en)));
    if ((1U & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__clk_sys)))) {
        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__core_clock_gate_i__DOT__en_latch 
            = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__clock_en;
    }
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__new_irq 
        = ((IData)(__VdfgRegularize_hd87f99a1_2_0) 
           & ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__nmi_mode_q)) 
              & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_mode_q))));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__handle_irq 
        = ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__debug_mode_q)) 
           & ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__debug_single_step)) 
              & ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__nmi_mode_q)) 
                 & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__irq_nm_int) 
                    | (IData)(__VdfgRegularize_hd87f99a1_2_0)))));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__lsu_load_err_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_load_err;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__lsu_store_err_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_store_err;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__lsu_resp_err_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_resp_err;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_ls_error_exception 
        = ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__pmp_err_q)) 
           & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_resp_err));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_ls_pmp_exception 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_resp_err) 
           & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__pmp_err_q));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__exc_req_lsu 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_resp_err;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__special_req_pc_change 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__mret_insn) 
           | ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__dret_insn) 
              | ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__exc_req_d) 
                 | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__lsu_resp_err))));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__rf_wdata_lsu_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rf_wdata_lsu;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_err_out 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__out_err_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__fetch_err 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__out_err_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_bus_err 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__out_err_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_err 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__out_err_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__err_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__out_err_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__if_instr_valid 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__fetch_valid;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__unused_valid 
        = ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__out_err_o)) 
           & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__fetch_valid));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__core_sleep_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__core_sleep_o;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__clk 
        = ((IData)(vlSelfRef.IO_CLK) & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__core_clock_gate_i__DOT__en_latch));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__load_err_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__lsu_load_err_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__store_err_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__lsu_store_err_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__unused_fcov_ls_error_exception 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_ls_error_exception;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__unused_fcov_ls_pmp_exception 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__fcov_ls_pmp_exception;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__rvfi_trap_id 
        = (((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__exc_req_d) 
            | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__exc_req_lsu)) 
           & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__ebrk_insn) 
                 & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__ebreak_into_debug))));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__valid_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__unused_valid;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__gen_regfile_ff__DOT__register_file_i__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__clk;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__core_clock_gate_i__DOT__clk_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__clk;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__gen_no_rs3_flop__DOT__unused_clk 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__clk;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__g_bypass_wb__DOT__unused_clk 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__clk;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__clk;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__load_store_unit_i__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__clk_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__wb_stage_i__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__clk_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__clk_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__clk_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__clk_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__clk_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__ex_block_i__DOT__clk_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__clk_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__clk_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__compressed_decoder_i__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__clk_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__clk_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstatus_csr__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__clk_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mepc_csr__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__clk_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mie_csr__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__clk_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mscratch_csr__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__clk_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mcause_csr__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__clk_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtval_csr__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__clk_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mtvec_csr__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__clk_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dcsr_csr__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__clk_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_depc_csr__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__clk_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch0_csr__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__clk_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch1_csr__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__clk_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_csr__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__clk_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_epc_csr__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__clk_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mstack_cause_csr__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__clk_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__clk_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__clk_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_cpuctrlsts_part_csr__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__clk_i;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fifo_i__DOT__clk_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__clk_i;
}

VL_INLINE_OPT void Vtop___024root___nba_comb__TOP__4(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___nba_comb__TOP__4\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Body
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_op_en 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__csr_access_o) 
           & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__instr_executing_spec) 
              & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__en_wb)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_op_en_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_op_en;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__csr_op_en_o 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_op_en;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__csr_pipe_flush 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_op_en) 
           & ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__no_flush_csr_addr)) 
              & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_wr)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_we_int 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_wr) 
           & ((~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__illegal_csr_insn_id)) 
              & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_op_en)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__fcov_csr_read_only 
        = ((0U == (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__csr_op_o)) 
           & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__decoder_i__DOT__csr_access_o) 
              & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_op_en) 
                 | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__illegal_insn_o))));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__fcov_csr_write 
        = (((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_wr) 
            & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_access)) 
           & ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_op_en) 
              | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__illegal_insn_id)));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__csr_pipe_flush_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__csr_pipe_flush;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__csr_pipe_flush 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__csr_pipe_flush) 
           & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__if_stage_i__DOT__instr_valid_id_q));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mscratch_en = 0U;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dscratch0_en = 0U;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dscratch1_en = 0U;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mie_en = 0U;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcountinhibit_we = 0U;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we = 0U;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we = 0U;
    if (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__csr_we_int) {
        if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                      >> 0xbU)))) {
            if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                          >> 0xaU)))) {
                if ((0x200U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    if ((0x100U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                        if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                      >> 7U)))) {
                            if ((0x40U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                              >> 5U)))) {
                                    if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                  >> 4U)))) {
                                        if ((1U & (~ 
                                                   ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                    >> 3U)))) {
                                            if ((1U 
                                                 & (~ 
                                                    ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                     >> 2U)))) {
                                                if (
                                                    (1U 
                                                     & (~ 
                                                        ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                         >> 1U)))) {
                                                    if (
                                                        (1U 
                                                         & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)))) {
                                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mscratch_en = 1U;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                          >> 6U)))) {
                                if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                              >> 5U)))) {
                                    if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                  >> 4U)))) {
                                        if ((1U & (~ 
                                                   ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                    >> 3U)))) {
                                            if ((4U 
                                                 & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                                if (
                                                    (1U 
                                                     & (~ 
                                                        ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                         >> 1U)))) {
                                                    if (
                                                        (1U 
                                                         & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)))) {
                                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mie_en = 1U;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                if ((0x20U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                    if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                  >> 4U)))) {
                                        if ((1U & (~ 
                                                   ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                    >> 3U)))) {
                                            if ((1U 
                                                 & (~ 
                                                    ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                     >> 2U)))) {
                                                if (
                                                    (1U 
                                                     & (~ 
                                                        ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                         >> 1U)))) {
                                                    if (
                                                        (1U 
                                                         & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)))) {
                                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcountinhibit_we = 1U;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if ((0x400U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                if ((0x200U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    if ((0x100U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                        if ((0x80U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                            if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                          >> 6U)))) {
                                if ((0x20U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                    if ((0x10U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                        if ((1U & (~ 
                                                   ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                    >> 3U)))) {
                                            if ((1U 
                                                 & (~ 
                                                    ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                                     >> 2U)))) {
                                                if (
                                                    (2U 
                                                     & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                                    if (
                                                        (1U 
                                                         & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)))) {
                                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dscratch0_en = 1U;
                                                    }
                                                    if (
                                                        (1U 
                                                         & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dscratch1_en = 1U;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if ((0x800U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
            if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                          >> 0xaU)))) {
                if ((0x200U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                    if ((0x100U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                        if ((0x80U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                            if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                          >> 6U)))) {
                                if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                              >> 5U)))) {
                                    if ((0x10U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we 
                                            = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we 
                                               | (0xffffffffULL 
                                                  & ((IData)(1U) 
                                                     << (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx))));
                                    } else if ((8U 
                                                & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we 
                                            = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we 
                                               | (0xffffffffULL 
                                                  & ((IData)(1U) 
                                                     << (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx))));
                                    } else if ((4U 
                                                & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we 
                                            = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we 
                                               | (0xffffffffULL 
                                                  & ((IData)(1U) 
                                                     << (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx))));
                                    } else if ((2U 
                                                & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we 
                                            = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we 
                                               | (0xffffffffULL 
                                                  & ((IData)(1U) 
                                                     << (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx))));
                                    } else if ((1U 
                                                & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)))) {
                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we 
                                            = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we 
                                               | (0xffffffffULL 
                                                  & ((IData)(1U) 
                                                     << (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx))));
                                    }
                                }
                            }
                        }
                        if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                      >> 7U)))) {
                            if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                          >> 6U)))) {
                                if ((1U & (~ ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr) 
                                              >> 5U)))) {
                                    if ((0x10U & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we 
                                            = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we 
                                               | (0xffffffffULL 
                                                  & ((IData)(1U) 
                                                     << (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx))));
                                    } else if ((8U 
                                                & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we 
                                            = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we 
                                               | (0xffffffffULL 
                                                  & ((IData)(1U) 
                                                     << (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx))));
                                    } else if ((4U 
                                                & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we 
                                            = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we 
                                               | (0xffffffffULL 
                                                  & ((IData)(1U) 
                                                     << (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx))));
                                    } else if ((2U 
                                                & (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr))) {
                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we 
                                            = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we 
                                               | (0xffffffffULL 
                                                  & ((IData)(1U) 
                                                     << (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx))));
                                    } else if ((1U 
                                                & (~ (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__csr_addr)))) {
                                        vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we 
                                            = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we 
                                               | (0xffffffffULL 
                                                  & ((IData)(1U) 
                                                     << (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_idx))));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__unused_fcov_csr_read_only 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__fcov_csr_read_only;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__unused_fcov_csr_write 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__fcov_csr_write;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__special_req_flush_only 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__wfi_insn) 
           | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__csr_pipe_flush));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mscratch_csr__DOT__wr_en_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mscratch_en;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch0_csr__DOT__wr_en_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dscratch0_en;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_dscratch1_csr__DOT__wr_en_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__dscratch1_en;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__u_mie_csr__DOT__wr_en_i 
        = vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mie_en;
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__counterh_we_i 
        = (1U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we 
                 >> 0U));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counterh_we_i 
        = (1U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we 
                 >> 2U));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__unused_mhpmcounterh_we_1 
        = (1U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we 
                 >> 1U));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__g_mcountinhibit_reduced__DOT__unused_mhphcounterh_we 
        = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounterh_we 
           >> 3U);
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcycle_counter_i__DOT__counter_we_i 
        = (1U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we 
                 >> 0U));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__minstret_counter_i__DOT__counter_we_i 
        = (1U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we 
                 >> 2U));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__unused_mhpmcounter_we_1 
        = (1U & (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we 
                 >> 1U));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__g_mcountinhibit_reduced__DOT__unused_mhphcounter_we 
        = (vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mhpmcounter_we 
           >> 3U);
}

VL_INLINE_OPT void Vtop___024root___nba_comb__TOP__6(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___nba_comb__TOP__6\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Body
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcountinhibit_d 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcountinhibit_we)
            ? (((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__gen_no_dummy__DOT__unused_dummy_en) 
                << 2U) | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__gen_no_icache__DOT__unused_icen))
            : (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__cs_registers_i__DOT__mcountinhibit_q));
    vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__special_req 
        = ((IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__special_req_pc_change) 
           | (IData)(vlSelfRef.ibex_simple_system__DOT__u_top__DOT__u_ibex_top__DOT__u_ibex_core__DOT__id_stage_i__DOT__controller_i__DOT__special_req_flush_only));
}

void Vtop___024root___eval_triggers__act(Vtop___024root* vlSelf);

bool Vtop___024root___eval_phase__act(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___eval_phase__act\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Init
    VlTriggerVec<8> __VpreTriggered;
    CData/*0:0*/ __VactExecute;
    // Body
    Vtop___024root___eval_triggers__act(vlSelf);
    __VactExecute = vlSelfRef.__VactTriggered.any();
    if (__VactExecute) {
        __VpreTriggered.andNot(vlSelfRef.__VactTriggered, vlSelfRef.__VnbaTriggered);
        vlSelfRef.__VnbaTriggered.thisOr(vlSelfRef.__VactTriggered);
        Vtop___024root___eval_act(vlSelf);
    }
    return (__VactExecute);
}

bool Vtop___024root___eval_phase__nba(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___eval_phase__nba\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Init
    CData/*0:0*/ __VnbaExecute;
    // Body
    __VnbaExecute = vlSelfRef.__VnbaTriggered.any();
    if (__VnbaExecute) {
        Vtop___024root___eval_nba(vlSelf);
        vlSelfRef.__VnbaTriggered.clear();
    }
    return (__VnbaExecute);
}

#ifdef VL_DEBUG
VL_ATTR_COLD void Vtop___024root___dump_triggers__ico(Vtop___024root* vlSelf);
#endif  // VL_DEBUG
#ifdef VL_DEBUG
VL_ATTR_COLD void Vtop___024root___dump_triggers__nba(Vtop___024root* vlSelf);
#endif  // VL_DEBUG
#ifdef VL_DEBUG
VL_ATTR_COLD void Vtop___024root___dump_triggers__act(Vtop___024root* vlSelf);
#endif  // VL_DEBUG

void Vtop___024root___eval(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___eval\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Init
    IData/*31:0*/ __VicoIterCount;
    CData/*0:0*/ __VicoContinue;
    IData/*31:0*/ __VnbaIterCount;
    CData/*0:0*/ __VnbaContinue;
    // Body
    __VicoIterCount = 0U;
    vlSelfRef.__VicoFirstIteration = 1U;
    __VicoContinue = 1U;
    while (__VicoContinue) {
        if (VL_UNLIKELY(((0x64U < __VicoIterCount)))) {
#ifdef VL_DEBUG
            Vtop___024root___dump_triggers__ico(vlSelf);
#endif
            VL_FATAL_MT("../ibex/examples/simple_system/rtl/ibex_simple_system.sv", 33, "", "Input combinational region did not converge.");
        }
        __VicoIterCount = ((IData)(1U) + __VicoIterCount);
        __VicoContinue = 0U;
        if (Vtop___024root___eval_phase__ico(vlSelf)) {
            __VicoContinue = 1U;
        }
        vlSelfRef.__VicoFirstIteration = 0U;
    }
    __VnbaIterCount = 0U;
    __VnbaContinue = 1U;
    while (__VnbaContinue) {
        if (VL_UNLIKELY(((0x64U < __VnbaIterCount)))) {
#ifdef VL_DEBUG
            Vtop___024root___dump_triggers__nba(vlSelf);
#endif
            VL_FATAL_MT("../ibex/examples/simple_system/rtl/ibex_simple_system.sv", 33, "", "NBA region did not converge.");
        }
        __VnbaIterCount = ((IData)(1U) + __VnbaIterCount);
        __VnbaContinue = 0U;
        vlSelfRef.__VactIterCount = 0U;
        vlSelfRef.__VactContinue = 1U;
        while (vlSelfRef.__VactContinue) {
            if (VL_UNLIKELY(((0x64U < vlSelfRef.__VactIterCount)))) {
#ifdef VL_DEBUG
                Vtop___024root___dump_triggers__act(vlSelf);
#endif
                VL_FATAL_MT("../ibex/examples/simple_system/rtl/ibex_simple_system.sv", 33, "", "Active region did not converge.");
            }
            vlSelfRef.__VactIterCount = ((IData)(1U) 
                                         + vlSelfRef.__VactIterCount);
            vlSelfRef.__VactContinue = 0U;
            if (Vtop___024root___eval_phase__act(vlSelf)) {
                vlSelfRef.__VactContinue = 1U;
            }
        }
        if (Vtop___024root___eval_phase__nba(vlSelf)) {
            __VnbaContinue = 1U;
        }
    }
}

#ifdef VL_DEBUG
void Vtop___024root___eval_debug_assertions(Vtop___024root* vlSelf) {
    VL_DEBUG_IF(VL_DBG_MSGF("+    Vtop___024root___eval_debug_assertions\n"); );
    Vtop__Syms* const __restrict vlSymsp VL_ATTR_UNUSED = vlSelf->vlSymsp;
    auto& vlSelfRef = std::ref(*vlSelf).get();
    // Body
    if (VL_UNLIKELY(((vlSelfRef.IO_CLK & 0xfeU)))) {
        Verilated::overWidthError("IO_CLK");}
    if (VL_UNLIKELY(((vlSelfRef.IO_RST_N & 0xfeU)))) {
        Verilated::overWidthError("IO_RST_N");}
}
#endif  // VL_DEBUG
