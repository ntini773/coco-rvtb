import cocotb
import pyuvm
from pyuvm import *

class mem_seq_item(uvm_sequence_item):
    def __init__(self, name="mem_seq_item"):
        super().__init__(name)
        # Instruction  Details
        
        # Requests
        self.instr_req = 0
        self.instr_addr = 0
        # Responses
        self.instr_rvalid = 0
        self.instr_rdata = 0
        self.instr_rdata_intg = 0
        self.instr_err = 0

        # Data Details
        # Requests
        self.data_req = 0
        self.data_addr = 0
        self.data_we = 0
        self.data_be = 0
        self.data_wdata = 0
        self.data_wdata_intg = 0
        # Responses
        self.data_rvalid = 0
        self.data_rdata = 0
        self.data_rdata_intg = 0
        self.data_err = 0