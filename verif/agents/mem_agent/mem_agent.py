import cocotb
import pyuvm
from pyuvm import *

from .mem_monitor import mem_monitor
from .mem_driver import mem_driver
from .mem_sequencer import mem_sequencer

class Mem_agent(uvm_agent):

    def build_phase(self):
        self.driver = mem_driver.create("driver", self)
        self.monitor = mem_monitor.create("monitor", self)
        self.sequencer = mem_sequencer.create("sequencer", self)
        ConfigDB().set(None, "*", "mem_sequencer", self.sequencer)

    def connect_phase(self):
        self.monitor.addr_ph_port.connect(self.sequencer.addr_port.analysis_export)
        self.driver.seq_item_port.connect(self.sequencer.seq_item_export)
    
    def reset(self):
        self.sequencer.reset()