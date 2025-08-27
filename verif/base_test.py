import os
from pathlib import Path
import sys
import cocotb
import pyuvm
from pyuvm import *
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge , ClockCycles , ReadWrite

sys.path.insert(0,str(Path("./utils").resolve()))
sys.path.insert(0,str(Path("./env").resolve()))
from env.environment import environment
from env.rvfi_interface import RVFI_Interface
from env.mem_interface import Mem_Interface
from agents.mem_agent.mem_seq_lib import mem_seq
import os

# @pyuvm.test()
class BaseTest(uvm_test):

    def build_phase(self):
    
        try:
            self.elf_path = cocotb.plusargs["ELF_PATH"]
        except Exception as e:
            self.logger.error(f"Error retrieving ELF_PATH from plusargs: {e}")

        self.logger.info(f"Using ELF file: {self.elf_path}")
        
        # Set interfaces into ConfigDB
        self.rvfi_if = RVFI_Interface()
        self.mem_if = Mem_Interface()
        self.keep_running = True
        # ConfigDB().is_tracing=True  # Use to get trace of ConfigDB
        ConfigDB().set(self, "*", "rvfi_if",self.rvfi_if)
        ConfigDB().set(self, "*", "mem_if",self.mem_if)
        ConfigDB().set(None,"*","keep_running",self.keep_running)

        # Build the environment using UVM Factory
        self.env = environment.create("env", self)



    def end_of_elaboration_phase(self):
        self.mem_seq = mem_seq.create("mem_seq")
        
    async def run_phase(self):
        self.raise_objection()
        # Start Clock
        clock = Clock(cocotb.top.clk_i, 1, units="ns")
        cocotb.start_soon(clock.start())

        self.logger.info(f"Base Test Started...!")

        # Setup DUT Internal signals and preload
        cocotb.top.test_en_i.value = 0
        cocotb.top.ram_cfg_i.value = 0
        cocotb.top.hart_id_i.value = 0
        cocotb.top.fetch_enable_i.value = 0
        cocotb.top.rst_ni.value = 1
        cocotb.top.boot_addr_i.value = 0x80000000
        await ReadWrite()

        await ClockCycles(cocotb.top.clk_i, 5)

        cocotb.top.rst_ni.value = 0
        # Preload in memory model

        self.preload_memory(self.elf_path)

        await ClockCycles(cocotb.top.clk_i, 5) # Set the reset for 5 clocks

        cocotb.top.fetch_enable_i.value = 1
        cocotb.top.rst_ni.value = 1

        # Immediately after reset is deasserted
        await self.mem_seq.start(self.env.mem_agent.sequencer)

        self.drop_objection()

    def preload_memory(self, elf_path):
        self.mem_model=ConfigDB().get(None, "", "memory_model")
        self.mem_model.preload_memory(elf_path)

