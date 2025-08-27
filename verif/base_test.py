import os
from pathlib import Path
import sys
import cocotb
import pyuvm
from pyuvm import *
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge , ClockCycles , ReadWrite

# print(sys.path)
sys.path.insert(0,str(Path("./utils").resolve()))
sys.path.insert(0,str(Path("./env").resolve()))
# print(sys.path)
from env.environment import environment
from env.rvfi_interface import RVFI_Interface
from env.mem_interface import Mem_Interface
from agents.mem_agent.mem_seq_lib import mem_seq
import os

# @pyuvm.test()
class BaseTest(uvm_test):

    def build_phase(self):
        # Configure UVM to fail test on any error
        ConfigDB().set(None, "*", "uvm_max_errors", 1)
        
        # Get ELF path from ConfigDB
        # self.elf_path = os.environ.get(key="ELF_PATH", default="./ibex_load_instr_test_0.o")
        # try:
        #     print(ConfigDB())
        #     self.elf_path = ConfigDB().get(None,"", "elf_path")
        # except Exception as e:
        #     self.logger.error(f"Error retrieving ELF_PATH from ConfigDB: {e}")
    
        try:
            self.elf_path = cocotb.plusargs["ELF_PATH"]
        except Exception as e:
            self.logger.error(f"Error retrieving ELF_PATH from plusargs: {e}")
            # self.elf_path = "./ibex_load_instr_test_0.o"  # default

        self.logger.info(f"Using ELF file: {self.elf_path}")
        
        # Set interfaces into ConfigDB
        self.rvfi_if = RVFI_Interface()
        self.mem_if = Mem_Interface()
        self.keep_running = True
        # ConfigDB().is_tracing=True  
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
        # TODO: Preload in memory model and in Hammer

        # mem_model.preload_memory("../top_tracing_simulation/ibex_arithmetic_basic_test_0.o")
        # mem_model.dump_memory("check_memory.txt")
        self.preload_memory(self.elf_path)

        await ClockCycles(cocotb.top.clk_i, 5) # Set the reset for 5 clocks

        cocotb.top.fetch_enable_i.value = 1
        cocotb.top.rst_ni.value = 1

        # Started Requesting Instructions
        # print(f"Req={cocotb.top.instr_req_o.value}, Addr={cocotb.top.instr_addr_o.value.integer:#x}")
        # await ClockCycles(cocotb.top.clk_i, 2)
        await self.mem_seq.start(self.env.mem_agent.sequencer)

        # Check if any UVM errors occurred
        # error_count = uvm_root().get_error_count()
        # if error_count > 0:
        #     uvm_fatal("BASE_TEST", f"Test failed with {error_count} UVM errors")

        # await ClockCycles(cocotb.top.clk_i, 100)

        self.drop_objection()

    def preload_memory(self, elf_path):
        self.mem_model=ConfigDB().get(None, "", "memory_model")
        # self.mem_model.preload_memory("./ibex_load_instr_test_0.o")
        self.mem_model.preload_memory(elf_path)

