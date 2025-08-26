import cocotb
import pyuvm
from cocotb.triggers import RisingEdge
from pyuvm import *
from pathlib import Path
import sys
sys.path.insert(0,str(Path("../../env").resolve()))
# print(sys.path)

# import rvfi_if

# a= rvfi_if.Dummy()

from .rvfi_seq_item import rvfi_seq_item

class rvfi_monitor(uvm_monitor):
    def build_phase(self):
        # super().build_phase() doesn't exist because uvm_monitor doesn't have build_phase
        # making a port to send collected items to scoreboard
        self.item_collected_port = uvm_analysis_port("item_collected_port", self)
        # get interface from ConfigDB , it raises error automatically if not found
        self.rvfi = ConfigDB().get(self,"","rvfi_if")

    async def run_phase(self):
        cnt=0
        while True:

            while self.rvfi.valid.value == 0:
                await RisingEdge(self.rvfi.clk)

            item = rvfi_seq_item("rvfi_packet") 
            item.valid = self.rvfi.valid.value.integer
            item.order = self.rvfi.order.value.integer
            item.insn = self.rvfi.insn.value.integer
            item.trap = self.rvfi.trap.value.integer
            item.halt = self.rvfi.halt.value.integer
            item.intr = self.rvfi.intr.value.integer
            item.mode = self.rvfi.mode.value.integer
            item.ixl = self.rvfi.ixl.value.integer

            item.mem_addr = self.rvfi.mem_addr.value.integer
            item.mem_rdata = self.rvfi.mem_rdata.value.integer
            item.mem_rmask = self.rvfi.mem_rmask.value.integer
            item.mem_wdata = self.rvfi.mem_wdata.value.integer
            item.mem_wmask = self.rvfi.mem_wmask.value.integer

            item.pc_rdata = self.rvfi.pc_rdata.value.integer
            item.pc_wdata = self.rvfi.pc_wdata.value.integer

            item.rs1_addr = self.rvfi.rs1_addr.value.integer
            item.rs1_rdata = self.rvfi.rs1_rdata.value.integer
            item.rs2_addr = self.rvfi.rs2_addr.value.integer
            item.rs2_rdata = self.rvfi.rs2_rdata.value.integer
            item.rd_addr = self.rvfi.rd_addr.value.integer
            item.rd_wdata = self.rvfi.rd_wdata.value.integer
            
            self.item_collected_port.write(item)
            # self.logger.info(f"Captured RVFI signals")
            await RisingEdge(self.rvfi.clk)

