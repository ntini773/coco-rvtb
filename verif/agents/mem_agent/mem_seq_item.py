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
    
    # def __str__(self):
    #     return (f"Instr Req: {self.instr_req}, "
    #             f"Instr Addr: {self.instr_addr:#x}, "
    #             f"Instr Rvalid: {self.instr_rvalid}, "
    #             f"Instr Rdata: {self.instr_rdata:#x}, "
    #             f"Data Req: {self.data_req}, "
    #             f"Data Addr: {self.data_addr:#x}, "
    #             # f"Data We: {self.data_we}, "
    #             # f"Data Be: {self.data_be}, "
    #             # f"Data Wdata: {self.data_wdata}, "
    #             f"Data Rvalid: {self.data_rvalid}, "
    #             f"Data Rdata: {self.data_rdata:#x}")
