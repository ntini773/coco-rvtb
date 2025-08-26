import pyuvm
from pyuvm import *

class rvfi_seq_item(uvm_sequence_item):
    def __init__(self, name="rvfi_seq_item"):
        super().__init__(name)
        self.valid = 0
        self.order = 0
        self.insn = 0
        self.trap = 0
        self.halt = 0
        self.intr = 0
        self.mode = 0
        self.ixl = 0
        self.mem_addr = 0
        self.mem_rdata = 0
        self.mem_rmask = 0
        self.mem_wdata = 0
        self.mem_wmask = 0
        self.pc_rdata = 0
        self.pc_wdata = 0
        self.rs1_addr = 0
        self.rs1_rdata = 0
        self.rs2_addr = 0
        self.rs2_rdata = 0
        self.rd_addr = 0
        self.rd_wdata = 0
        
