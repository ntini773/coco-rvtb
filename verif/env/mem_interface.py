import cocotb
import pyuvm
class Mem_Interface(metaclass=pyuvm.Singleton):
    def __init__(self):
        self.dut = cocotb.top
        self.clk = cocotb.top.clk_i
        self.rst = cocotb.top.rst_ni

        # Instruction Interface - 7 signals
        self.instr_req_o = cocotb.top.instr_req_o
        self.instr_addr_o = cocotb.top.instr_addr_o

        self.instr_gnt_i = cocotb.top.instr_gnt_i
        self.instr_rvalid_i = cocotb.top.instr_rvalid_i
        self.instr_rdata_i = cocotb.top.instr_rdata_i
        self.instr_rdata_intg_i = cocotb.top.instr_rdata_intg_i
        self.instr_err_i = cocotb.top.instr_err_i

        # Data Interface - 11 signals
        self.data_req_o = cocotb.top.data_req_o
        self.data_addr_o = cocotb.top.data_addr_o
        self.data_we_o = cocotb.top.data_we_o
        self.data_be_o = cocotb.top.data_be_o
        self.data_wdata_o = cocotb.top.data_wdata_o
        self.data_wdata_intg_o = cocotb.top.data_wdata_intg_o
        
        self.data_gnt_i = cocotb.top.data_gnt_i
        self.data_rvalid_i = cocotb.top.data_rvalid_i
        self.data_rdata_i = cocotb.top.data_rdata_i
        self.data_rdata_intg_i = cocotb.top.data_rdata_intg_i
        self.data_err_i = cocotb.top.data_err_i
    
