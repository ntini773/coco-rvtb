
# Spike agent has the monitors to track the RVFI interface and send to Scoreboard
from pyuvm import *
from cocotb.triggers import Timer,Combine,RisingEdge,FallingEdge
from .rvfi_monitor import rvfi_monitor

class rvfi_agent(uvm_agent):
    def build_phase(self):
        super().build_phase()
        self.monitor=rvfi_monitor.create("rvfi_monitor", self)
    
