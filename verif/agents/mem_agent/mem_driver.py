import cocotb 
import pyuvm
from pyuvm import *
from cocotb.utils import get_sim_time
from cocotb.triggers import RisingEdge, ReadWrite ,First , FallingEdge , Combine , ClockCycles
from .mem_seq_item import mem_seq_item

class mem_driver(uvm_driver):
    def __init__(self, name, parent):
        super().__init__(name, parent)
    
    def build_phase(self):
        self.mem_if = ConfigDB().get(self, "", "mem_if")
        self.rdata_queue = UVMQueue()

    async def run_phase(self):
        await self.reset_signals()

        # Wait for reset to be released initially
        while self.mem_if.rst == 0:
            await RisingEdge(self.mem_if.clk)
        
        # Main driver loop
        while True:
            # Start the main driver tasks
            send_grant_task = cocotb.start_soon(self.send_grant())
            get_and_drive_task = cocotb.start_soon(self.get_and_drive())
            wait_for_reset_task = cocotb.start_soon(self.wait_for_reset())

            # Wait for reset to happen
            triggered = await wait_for_reset_task

            # Reset detected - kill other tasks
            send_grant_task.kill()
            get_and_drive_task.kill()
            
            # Handle reset
            await self.handle_reset()
            # Loop will restart tasks after reset is handled

        # await self.handle_reset()

    async def reset_signals(self):
        # Instruction Mem
        self.mem_if.instr_rvalid_i.value = 0
        self.mem_if.instr_gnt_i.value = 0
        self.mem_if.instr_rdata_i.value = 0
        self.mem_if.instr_rdata_intg_i.value = 0
        self.mem_if.instr_err_i.value = 0

        # Data Mem
        self.mem_if.data_rvalid_i.value = 0
        self.mem_if.data_gnt_i.value = 0
        self.mem_if.data_rdata_i.value = 0
        self.mem_if.data_rdata_intg_i.value = 0
        self.mem_if.data_err_i.value = 0
        await ReadWrite()

    async def wait_for_reset(self):
        await FallingEdge(self.mem_if.rst)

    async def handle_reset(self):
        while not self.rdata_queue.empty():
            tr = self.rdata_queue.peek_nowait()

        #TODO: Clear seq_item_port
        # while True:
        #     try:
                # req = await self.seq_item_port.get_next_item() # Issue is mayn't reset on time
        #         if req is not None:
        #             self.seq_item_port.item_done()
        #         else:
        #             break
        #     except :
        #         break

        await self.reset_signals()
        while self.mem_if.rst.value == 0:
            await RisingEdge(self.mem_if.clk)
    
    async def send_grant(self):
        while True:
            # if self.mem_if.rst.value == 0:
            #     # In reset - clear grants
            #     self.mem_if.data_gnt_i.value = 0
            #     self.mem_if.instr_gnt_i.value = 0
            #     # await ReadWrite()
            #     await RisingEdge(self.mem_if.clk)
            self.mem_if.data_gnt_i.value = 0
            self.mem_if.instr_gnt_i.value = 0

            if self.mem_if.data_req_o.value or self.mem_if.instr_req_o.value:
                if self.mem_if.rst.value == 1:
                    if self.mem_if.data_req_o.value:
                        self.mem_if.data_gnt_i.value = 1
                    if self.mem_if.instr_req_o.value:
                        self.mem_if.instr_gnt_i.value = 1
                    # self.logger.critical(f"Sending grant for addr={self.mem_if.instr_addr_o.value.integer:#x}, ir={self.mem_if.instr_req_o.value}, dr={self.mem_if.data_req_o.value} at {get_sim_time(units='ns')}")

            # else:
            #     self.mem_if.data_gnt_i.value = 0
            #     self.mem_if.instr_gnt_i.value = 0
            # self.logger.info(f"Data Request: {self.mem_if.data_req_o.value}, Instr Request: {self.mem_if.instr_req_o.value}")   
            await ReadWrite()
            await RisingEdge(self.mem_if.clk)
            await ReadWrite()
            # await RisingEdge(self.mem_if.clk)

    async def get_and_drive(self):
        while self.mem_if.rst.value == 0:
            await RisingEdge(self.mem_if.clk)

        a = cocotb.start_soon(self.get_from_sequencer())
        b = cocotb.start_soon(self.send_read_data())
        
        c = await Combine(a, b)
        c.kill()

    async def get_from_sequencer(self):
        while True:
            req = await self.seq_item_port.get_next_item()
            if self.mem_if.rst.value:
                self.rdata_queue.put_nowait(req)
            self.seq_item_port.item_done()

    async def send_read_data(self):
        item_received = mem_seq_item("item_received")
        while True:
            self.mem_if.instr_rvalid_i.value = 0
            self.mem_if.instr_err_i.value = 0
            self.mem_if.instr_rdata_i.value = 0
            self.mem_if.instr_rdata_intg_i.value = 0

            self.mem_if.data_rvalid_i.value = 0
            self.mem_if.data_err_i.value = 0
            self.mem_if.data_rdata_i.value = 0
            self.mem_if.data_rdata_intg_i.value = 0
            await ReadWrite()
            # try:
            #     item_received = self.rdata_queue.get_nowait()
            # except:
            #     item_received = None
            #     # await RisingEdge(self.mem_if.clk)
            #     # continue
            item_received=await self.rdata_queue.get()

            await RisingEdge(self.mem_if.clk)

            if self.mem_if.rst.value == 0 :
                continue


            if item_received is not None:
                # self.logger.info(f"Item received: Addr={item_received.instr_addr:#x} , Data={item_received.instr_rdata:#x}")
                if item_received.instr_req:
                    self.mem_if.instr_rvalid_i.value = item_received.instr_rvalid
                    self.mem_if.instr_rdata_i.value = item_received.instr_rdata
                    self.mem_if.instr_err_i.value = item_received.instr_err
                    # self.logger.critical(f"Sending instruction read data of addr={item_received.instr_addr:#x}")

                if item_received.data_req:
                    self.mem_if.data_rvalid_i.value = item_received.data_rvalid
                    self.mem_if.data_err_i.value = item_received.data_err
                    if item_received.data_we == 0:
                        self.mem_if.data_rdata_i.value = item_received.data_rdata

            await ReadWrite()
            await RisingEdge(self.mem_if.clk)

                    


