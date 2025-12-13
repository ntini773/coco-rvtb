import pyuvm 
import cocotb
from pyuvm import *
from cocotb.triggers import ClockCycles 
from cocotb.clock import Clock
from base_test import BaseTest
import os
@cocotb.test()
async def top(_):
    # If any ConfigDB set / get is used before this , ConfigDB gets cleared up
    await uvm_root().run_test("BaseTest")

    # If we really want the ConfigDB to be used before test
    # await uvm_root().run_test("BaseTest", keep_singletons=True)

# To RUN this test 
# make ELF_PATH=elf_files/<any_elf_file> LOG_PATH=<log_path>(optional)