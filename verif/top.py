import pyuvm 
import cocotb
from pyuvm import *
from cocotb.triggers import ClockCycles 
from cocotb.clock import Clock
from tb_top import BaseTest
import os
@cocotb.test()
async def top(_):
    # elf_path = os.environ.get("ELF_PATH", "./ibex_load_instr_test_0.o")
    # ConfigDB().is_tracing=True
    # # # Store in ConfigDB for the test to access
    # ConfigDB().set(None, "*", "elf_path", elf_path)

    # await uvm_root().run_test("BaseTest",keep_singletons=True)
    await uvm_root().run_test("BaseTest")



#   TypeError: BaseTest.__init__() takes 2 positional arguments but 3 were given