TOPLEVEL_LANG = verilog
TOPLEVEL = ibex_top_tracing
MODULE = top
SIM = verilator

# Define Ibex base path for cleaner references
IBEX_BASE = ../submodules/ibex

INCLUDE_DIRS = \
    -I$(IBEX_BASE)/vendor/lowrisc_ip/ip/prim/rtl \
    -I$(IBEX_BASE)/vendor/lowrisc_ip/dv/sv/dv_utils \
    -I$(IBEX_BASE)/rtl \
    -I$(IBEX_BASE)/shared/rtl \
    -I$(IBEX_BASE)/shared/rtl/sim \
    -I$(IBEX_BASE)/dv/uvm/core_ibex/common/prim \
    -I$(IBEX_BASE)/vendor/lowrisc_ip/ip/prim_generic/rtl

VERILOG_SOURCES = \
    $(IBEX_BASE)/rtl/ibex_pkg.sv \
    $(IBEX_BASE)/vendor/lowrisc_ip/ip/prim/rtl/prim_cipher_pkg.sv \
    $(IBEX_BASE)/vendor/lowrisc_ip/ip/prim/rtl/prim_count_pkg.sv \
    $(IBEX_BASE)/vendor/lowrisc_ip/ip/prim/rtl/prim_mubi_pkg.sv \
    $(IBEX_BASE)/vendor/lowrisc_ip/ip/prim/rtl/prim_util_pkg.sv \
    $(IBEX_BASE)/vendor/lowrisc_ip/ip/prim/rtl/prim_ram_1p_pkg.sv \
    $(IBEX_BASE)/vendor/lowrisc_ip/ip/prim/rtl/prim_secded_pkg.sv \
    $(IBEX_BASE)/rtl/ibex_tracer_pkg.sv \
    $(IBEX_BASE)/rtl/ibex_top_tracing.sv \
    $(IBEX_BASE)/vendor/lowrisc_ip/ip/prim/rtl/prim_ram_2p_pkg.sv \
    $(IBEX_BASE)/vendor/lowrisc_ip/dv/sv/dv_utils/dv_fcov_macros.svh \
    $(IBEX_BASE)/vendor/lowrisc_ip/ip/prim/rtl/prim_assert.sv \
    $(IBEX_BASE)/vendor/lowrisc_ip/ip/prim_generic/rtl/prim_generic_buf.sv \
    $(IBEX_BASE)/vendor/lowrisc_ip/ip/prim_generic/rtl/prim_generic_ram_2p.sv \
    $(IBEX_BASE)/vendor/lowrisc_ip/ip/prim/rtl/prim_ram_2p_adv.sv \
    $(IBEX_BASE)/shared/rtl/bus.sv \
    $(IBEX_BASE)/shared/rtl/timer.sv \
    $(IBEX_BASE)/shared/rtl/sim/simulator_ctrl.sv \
    $(IBEX_BASE)/rtl/ibex_decoder.sv \
    $(IBEX_BASE)/rtl/ibex_controller.sv \
    $(IBEX_BASE)/rtl/ibex_register_file_ff.sv \
    $(IBEX_BASE)/rtl/ibex_compressed_decoder.sv \
    $(IBEX_BASE)/rtl/ibex_cs_registers.sv \
    $(IBEX_BASE)/rtl/ibex_ex_block.sv \
    $(IBEX_BASE)/rtl/ibex_fetch_fifo.sv \
    $(IBEX_BASE)/rtl/ibex_multdiv_fast.sv \
    $(IBEX_BASE)/rtl/ibex_id_stage.sv \
    $(IBEX_BASE)/rtl/ibex_wb_stage.sv \
    $(IBEX_BASE)/rtl/ibex_core.sv \
    $(IBEX_BASE)/rtl/ibex_top.sv \
    $(IBEX_BASE)/vendor/lowrisc_ip/ip/prim/rtl/prim_clock_gating_sync.sv \
    $(IBEX_BASE)/vendor/lowrisc_ip/ip/prim/rtl/prim_clock_gp_mux2.sv \
    $(IBEX_BASE)/vendor/lowrisc_ip/ip/prim/rtl/prim_intr_hw.sv \
    $(IBEX_BASE)/vendor/lowrisc_ip/ip/prim/rtl/prim_lfsr.sv \
    $(IBEX_BASE)/vendor/lowrisc_ip/ip/prim/rtl/prim_secded_22_16_dec.sv \
    $(IBEX_BASE)/dv/uvm/core_ibex/common/prim/prim_pkg.sv \

VERILATOR_ARGS = \
    --trace \
    --trace-structs \
    --timing \
    --trace-underscore \
    --timescale 1ns/1ps \
    --assert \
    -Wno-fatal \
    -Wno-UNOPTFLAT \
    -Wno-WIDTH \
    -Wno-CASEINCOMPLETE \
    -Wno-UNSIGNED \
    -Wno-INITIALDLY \
    --language 1800-2017 \
    $(INCLUDE_DIRS)

# Enable RVFI interface
COMPILE_ARGS += -DRVFI
export COMPILE_ARGS

ifeq ($(MAKECMDGOALS),)
ifndef ELF_PATH
$(error You must specify ELF_PATH, e.g. 'make ELF_PATH=./my_test.o')
endif
endif
export ELF_PATH

# # PLUSARGS ?= +ELF_PATH=./ibex_load_instr_test_0.o
PLUSARGS ?= +ELF_PATH=$(ELF_PATH)

EXTRA_ARGS += $(VERILATOR_ARGS)
SIM_ARGS = $(EXTRA_ARGS) $(PLUSARGS)
export EXTRA_ARGS

include $(shell cocotb-config --makefiles)/Makefile.sim
