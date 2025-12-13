import cocotb
import pyuvm
class RVFI_Interface(metaclass=pyuvm.Singleton):
    def __init__(self):
        self.dut = cocotb.top
        self.clk = cocotb.top.clk_i
        self.rst = cocotb.top.rst_ni
        
        # Instruction Metadata - 8 signals
        self.valid = cocotb.top.rvfi_valid
        self.order = cocotb.top.rvfi_order
        self.insn = cocotb.top.rvfi_insn
        self.trap = cocotb.top.rvfi_trap
        self.halt = cocotb.top.rvfi_halt
        self.intr = cocotb.top.rvfi_intr
        self.mode = cocotb.top.rvfi_mode
        self.ixl = cocotb.top.rvfi_ixl

        # Memory Access - 5 signals
        self.mem_addr = cocotb.top.rvfi_mem_addr
        self.mem_rdata = cocotb.top.rvfi_mem_rdata
        self.mem_rmask = cocotb.top.rvfi_mem_rmask
        self.mem_wdata = cocotb.top.rvfi_mem_wdata
        self.mem_wmask = cocotb.top.rvfi_mem_wmask

        # Program Counter - 2 signals
        self.pc_rdata = cocotb.top.rvfi_pc_rdata
        self.pc_wdata = cocotb.top.rvfi_pc_wdata

        # Integer Reg Read/ Write - 6 signals 
        self.rs1_addr = cocotb.top.rvfi_rs1_addr
        self.rs1_rdata = cocotb.top.rvfi_rs1_rdata

        self.rs2_addr = cocotb.top.rvfi_rs2_addr
        self.rs2_rdata = cocotb.top.rvfi_rs2_rdata

        self.rd_addr = cocotb.top.rvfi_rd_addr
        self.rd_wdata = cocotb.top.rvfi_rd_wdata