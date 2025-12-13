import cocotb
import pyuvm
from pyuvm import *
from .mem_seq_item import mem_seq_item
from .mem_sequencer import mem_sequencer
from cocotb.triggers import ClockCycles , Timer
from cocotb.clock import Clock
class mem_seq(uvm_sequence):
    def __init__(self, name="mem_seq"):
        super().__init__(name)

    async def body(self):
        self.mem= ConfigDB().get(None, "", "memory_model")
        self.sequencer = ConfigDB().get(None, "", "mem_sequencer")
        while True:
            if not  ConfigDB().get(None,"","keep_running"):
                return
            self.mem_req_item = await self.sequencer.addr_port.get()
            ir = self.mem_req_item.instr_req
            ia = self.mem_req_item.instr_addr
            dr = self.mem_req_item.data_req
            da = self.mem_req_item.data_addr
            if self.mem_req_item.instr_req:
                addr = self.mem_req_item.instr_addr
                try:
                    instruction=self.mem.read(addr, size=4)
                    self.mem_req_item.instr_err=0
                except Exception as e:
                    instruction=0
                    self.mem_req_item.instr_err=1
                self.mem_req_item.instr_rvalid=1
                self.mem_req_item.instr_rdata =instruction
            if self.mem_req_item.data_req:
                addr=self.mem_req_item.data_addr
                write_enable=self.mem_req_item.data_we
                byte_enable = self.mem_req_item.data_be
                write_data = self.mem_req_item.data_wdata
                if write_enable:
                    try:
                        for i in range(4):
                            if byte_enable[i]:
                                byte = (write_data >> (8 * i)) & 0xFF
                                self.mem.write(addr + i, byte, 1)
                        self.mem_req_item.data_err=0
                        self.mem_req_item.data_rvalid=1
                    except Exception as e:
                        self.mem_req_item.data_err=0
                        self.mem_req_item.data_rvalid=1
                else :
                    try :
                        read_data = 0
                        for i in range(4):
                            if byte_enable[i]:
                                byte = self.mem.read(addr + i, 1)
                                read_data |= (byte << (8 * i))
                        self.mem_req_item.data_rdata=read_data
                        self.mem_req_item.data_err=0
                        self.mem_req_item.data_rvalid=1
                    except Exception as e:
                        read_data=0
                        self.mem_req_item.data_rdata=read_data
                        self.mem_req_item.data_err=1
                        self.mem_req_item.data_rvalid=1
            await self.start_item(self.mem_req_item)
            await self.finish_item(self.mem_req_item)
            if self.mem.read(0x80002000,4)==1:
                await Timer(5, units='ns')
                return

                