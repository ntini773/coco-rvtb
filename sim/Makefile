# Top-level design language
TOPLEVEL_LANG = verilog

# Top-level module
TOPLEVEL = ibex_simple_system

# Name of the cocotb test module (without .py extension)
MODULE = test_ibex_simple_system
# MODULE=test_loading

# Simulator
SIM = verilator

INCLUDE_DIRS = \
    -I../ibex/vendor/lowrisc_ip/ip/prim/rtl \
    -I../ibex/vendor/lowrisc_ip/dv/sv/dv_utils \
    -I../ibex/rtl \
    -I../ibex/examples/simple_system/rtl \
    -I../ibex/syn/rtl \
    -I../ibex/dv/uvm/core_ibex/common/prim \
    -I../ibex/lowrisc_ip/ip/prim_generic/rtl \
    -I../ibex/shared/rtl \
    -I../ibex/shared/rtl/sim \
    -I../ibex/examples/sw/simple_system/hello_test 


# Verilog source files - packages must come first
# VERILOG_SOURCES = \
#     ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_cipher_pkg.sv \
#     ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_count_pkg.sv \
#     ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_mubi_pkg.sv \
#     ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_util_pkg.sv \
#     ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_ram_1p_pkg.sv \
#     ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_secded_pkg.sv \
#     ../ibex/rtl/ibex_pkg.sv \
#     ../ibex/rtl/ibex_tracer_pkg.sv \
#     ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_ram_2p_pkg.sv \
#     ../ibex/vendor/lowrisc_ip/dv/sv/dv_utils/dv_fcov_macros.svh \
#     ../ibex/rtl/ibex_decoder.sv \
#     ../ibex/rtl/ibex_controller.sv \
#     ../ibex/rtl/ibex_register_file_ff.sv \
#     ../ibex/rtl/ibex_compressed_decoder.sv \
#     ../ibex/rtl/ibex_cs_registers.sv \
#     ../ibex/rtl/ibex_ex_block.sv \
#     ../ibex/rtl/ibex_fetch_fifo.sv \
#     ../ibex/rtl/ibex_multdiv_fast.sv \
#     ../ibex/rtl/ibex_id_stage.sv \
#     ../ibex/rtl/ibex_wb_stage.sv \
#     ../ibex/rtl/ibex_core.sv \
#     ../ibex/rtl/ibex_top.sv \
#     ../ibex/rtl/ibex_top_tracing.sv \
#     ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_clock_gating_sync.sv \
#     ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_clock_gp_mux2.sv \
#     ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_intr_hw.sv \
#     ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_lfsr.sv \
#     ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_assert.sv \
#     ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_secded_22_16_dec.sv \
#     ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_ram_1p_adv.sv \
#     ../ibex/vendor/lowrisc_ip/ip/prim_generic/rtl/prim_generic_ram_2p.sv \
#     ../ibex/vendor/lowrisc_ip/ip/prim_generic/rtl/prim_generic_buf.sv \
#     ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_ram_2p_adv.sv \
#     ../ibex/examples/simple_system/rtl/ibex_simple_system.sv \

VERILOG_SOURCES = \
    ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_cipher_pkg.sv \
    ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_count_pkg.sv \
    ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_mubi_pkg.sv \
    ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_util_pkg.sv \
    ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_ram_1p_pkg.sv \
    ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_secded_pkg.sv \
    ../ibex/rtl/ibex_pkg.sv \
    ../ibex/rtl/ibex_tracer_pkg.sv \
    ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_ram_2p_pkg.sv \
    ../ibex/vendor/lowrisc_ip/dv/sv/dv_utils/dv_fcov_macros.svh \
    ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_assert.sv \
    ../ibex/vendor/lowrisc_ip/ip/prim_generic/rtl/prim_generic_buf.sv \
    ../ibex/dv/uvm/core_ibex/common/prim/prim_buf.sv \
    ../ibex/vendor/lowrisc_ip/ip/prim_generic/rtl/prim_generic_ram_2p.sv \
    ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_ram_2p_adv.sv \
    ../ibex/shared/rtl/bus.sv \
    ../ibex/shared/rtl/ram_2p.sv \
    ../ibex/shared/rtl/timer.sv \
    ../ibex/shared/rtl/sim/simulator_ctrl.sv \
    ../ibex/rtl/ibex_decoder.sv \
    ../ibex/rtl/ibex_controller.sv \
    ../ibex/rtl/ibex_register_file_ff.sv \
    ../ibex/rtl/ibex_compressed_decoder.sv \
    ../ibex/rtl/ibex_cs_registers.sv \
    ../ibex/rtl/ibex_ex_block.sv \
    ../ibex/rtl/ibex_fetch_fifo.sv \
    ../ibex/rtl/ibex_multdiv_fast.sv \
    ../ibex/rtl/ibex_id_stage.sv \
    ../ibex/rtl/ibex_wb_stage.sv \
    ../ibex/rtl/ibex_core.sv \
    ../ibex/rtl/ibex_top.sv \
    ../ibex/rtl/ibex_top_tracing.sv \
    ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_clock_gating_sync.sv \
    ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_clock_gp_mux2.sv \
    ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_intr_hw.sv \
    ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_lfsr.sv \
    ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_secded_22_16_dec.sv \
    ../ibex/examples/simple_system/rtl/ibex_simple_system.sv \
    ../ibex/dv/uvm/core_ibex/common/prim/prim_pkg.sv \
    ../ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_ram_2p.sv \


VMEM_FILE = $(PWD)/../ibex/examples/sw/simple_system/hello_test/hello_test.vmem

# # Verilator arguments
# VERILATOR_ARGS = --trace-fst --trace-structs --timing --assert \
#     -Wno-fatal -Wno-UNOPTFLAT -Wno-WIDTH -Wno-CASEINCOMPLETE -Wno-UNSIGNED -Wno-INITIALDLY

# enable --trace and --trace-structs for waveform generation
VERILATOR_ARGS = \
    --trace-fst \
    --trace-structs \
    --timing \
    --assert \
    -Wno-fatal \
    -Wno-UNOPTFLAT \
    -Wno-WIDTH \
    -Wno-CASEINCOMPLETE \
    -Wno-UNSIGNED \
    -Wno-INITIALDLY \
    --language 1800-2017 \
    -GSRAMInitFile=\"$(VMEM_FILE)\" \
    $(INCLUDE_DIRS)

# # Disable DV coverage to avoid issues with dv_fcov_macros.svh
# VERILATOR_COMPILE_ARGS += -DIBEX_NO_DV_COV

# # Compile-time macro definitions
# COMPILE_ARGS = +define+RVFI
# # Pass arguments to cocotb
# # EXTRA_SIM_ARGS = VERILATOR_ARGS="$(VERILATOR_ARGS)" COMPILE_ARGS="$(COMPILE_ARGS)"
# EXTRA_ARGS += $(VERILATOR_ARGS) $(COMPILE_ARGS)


# Verilator specific arguments
COMPILE_ARGS +=  -DRVFI
export COMPILE_ARGS
EXTRA_ARGS += $(VERILATOR_ARGS)
SIM_ARGS = $(EXTRA_ARGS)

# Export compilation arguments to cocotb
export EXTRA_ARGS

# Include cocotb makefiles
include $(shell cocotb-config --makefiles)/Makefile.sim
