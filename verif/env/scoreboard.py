import pyuvm 
from pyuvm import *
from pathlib import Path
import os, time, sys
import cocotb
from cocotb.triggers import Timer, RisingEdge, FallingEdge,First

# Import the co-simulation solution
from hammer_cosim import HammerCoSim
from queue import Queue

class scoreboard(uvm_scoreboard):
    
    def build_phase(self):
        
        # FIFO for RVFI packets
        self.rvfi_port = uvm_tlm_analysis_fifo("rvfi_port", self)
        self.rvfi_export = self.rvfi_port.analysis_export
        self.log_queue = Queue(maxsize=5)
        
        # Get ELF path
        elf_raw = cocotb.plusargs.get("ELF_PATH")
        if not elf_raw:
            raise RuntimeError("Pass +ELF_PATH=/path/to/prog.elf")
        
        self.elf_path = str(Path(elf_raw).expanduser().resolve())
        
        # Set up memory addresses to watch
        #TODO : Change this to a variable To-host address
        self.memory_watch_addresses = [
            0x80002000  # Your target memory location
        ]
        
        # # Initialize co-simulation
        # self.hammer_cosim = HammerCoSim(
        #     self.elf_path,
        #     memory_watch_addresses=self.memory_watch_addresses
        # )
        
        # self.current_step = 1
        # self.cosim_ready = False
    
    # def start_of_simulation_phase(self):
    #     """Initialize co-simulation"""
    #     self.logger.info("Starting Hammer co-simulation...")

    #     result = self.hammer_cosim.start_cosimulation()
        
    #     if result["success"]:
    #         self.cosim_ready = True
    #         self.logger.info("Hammer co-simulation ready and waiting!")
            
    #         # Query initial PC
    #         pc_result = self.hammer_cosim.query_pc()
    #         if pc_result["success"]:
    #             self.logger.info(f"Initial PC: {pc_result['pc_hex']}")
            
    #     else:
    #         self.logger.error(f"Co-simulation failed: {result['message']}")
    #         raise RuntimeError("Hammer co-simulation initialization failed")
    
    async def run_phase(self):
        """Main verification loop with co-simulation"""
        while True:
            # if not self.cosim_ready:
            #     self.logger.error("Co-simulation not ready")
            #     return
            
            self.logger.info("Starting co-simulation verification...")
            
            # Main loop: wait for RVFI packets, then step Hammer
            crs = cocotb.start_soon(self.collect_rvfi_and_spike())
            wfr= cocotb.start_soon(self.wait_for_reset())
            triggered=await wfr
            crs.kill()

            await self.handle_reset()

        
        

    async def collect_rvfi_and_spike(self):
        while True:
            try:
                # === WAIT FOR RVFI PACKET FROM DUT ===
                self.logger.info("Waiting for RVFI packet from FIFO...")
                
                # This blocks until FIFO has data
                rvfi_packet = await self.rvfi_port.get()
                
                # self.logger.info(f"Received RVFI packet: {rvfi_packet}")
                
                # === NOW STEP HAMMER (synchronized!) ===
                self.logger.info(f"Stepping Hammer (step {self.current_step})...")
                
                step_result = self.hammer_cosim.step_instruction(0)
                # print("HIII")    
                
                if step_result["success"]:
                    hammer_data = step_result["data"]
                    
                    # === COMPARE RVFI vs HAMMER ===
                    await self.compare_rvfi_hammer(rvfi_packet, hammer_data)
                    
                    self.current_step += 1
                else:
                    self.logger.error(f"Hammer step failed: {step_result}")
                    break
                    
            except Exception as e:
                self.logger.error(f"Co-simulation error: {e}")
                break
    async def compare_rvfi_hammer(self, rvfi_packet, hammer_data):
        """Print both RVFI packet and Hammer data side by side"""
        
        '''
        When we receive an RVFI packet and Spike packet ,we compare the following.
        -rvfi.pc_rdata and spike['pc']
        -rvfi.insn and spike['insn']

        # For Register Writes
            1. If the register_log_writes has a gpr , 
                rvfi.rd_addr and spike['rd_addr']
                rvfi.rd_wdata and spike['rd_wdata']
            2. If it has a csr ,
                Skip this for now and log it
        # For Memory Reads(check if it happened based on hammer["memory_reads"]'s size >0)
            rvfi.mem_addr and spike['mem_addr']
            The catch is that in the memory_read_logs , spike doesn't mention the value present at that memory address ,we need to check if as it will be eventually written into a GPR

        # For Memory_Writes(check if it happened based on hammer["memory_writes"]'s size >0)
            rvfi.mem_addr and spike['mem_addr']
            rvfi.mem_wdata ANDed with rvfi.mem_wmask and hammer["memory_writes"]["value"]
        '''
        step_num = hammer_data["hart_id"]
        # self.logger.info(f"═══════════ STEP {step_num} SIGNALS ═══════════")
        mismatch = False
        # Print RVFI signals
        self.logger.info("🔵 RVFI SIGNALS:")

        # If rvfi_packet has specific attributes, print them individually
        # if hasattr(rvfi_packet, '__dict__'):
        #     for attr, value in rvfi_packet.__dict__.items():
        #         if not attr.startswith('_'):
        #             self.logger.info(f"  rvfi_{attr}: {value}")
        # self.logger.info(f"Order:{rvfi_packet.order}, PC:{rvfi_packet.pc_rdata:#x}, Insn Hex:{rvfi_packet.insn:#x}")
        
        # If it's a dict-like object
        # elif hasattr(rvfi_packet, 'items'):
        #     for key, value in rvfi_packet.items():
        #         self.logger.info(f"  rvfi_{key}: {value}")
        
        # Print Hammer signals
        self.logger.info("🟡 HAMMER SIGNALS:")
        if mismatch == True:
            #TODO: RAISE ERROR and Print the Queue
            pass
        # Compare PC
        if hammer_data['pc'] != rvfi_packet.pc_rdata:
            mismatch = True

        # Compare instruction hex
        if hammer_data['instruction_hex'] != rvfi_packet.insn:
            mismatch = True
        

        # # If a mismatch is detected, handle error and prevent further comparison
        # if mismatch:
        #     self.logger.error("RVFI/Hammer mismatch detected! Entering error handling.")
        #     # Optionally, log the last few packets for debugging
        #     self.log_queue.put({
        #     "step": step_num,
        #     "rvfi": rvfi_packet,
        #     "hammer": hammer_data
        #     })
        #     # Print the contents of the log queue
        #     while not self.log_queue.empty():
        #     entry = self.log_queue.get()
        #     self.logger.error(f"Step {entry['step']} RVFI: {entry['rvfi']}, Hammer: {entry['hammer']}")
        #     # Raise an exception or stop the test
        #     raise RuntimeError("Co-simulation mismatch detected. Stopping verification.")
        self.logger.info(f"  PC: {hammer_data['pc_hex']} -> {hammer_data['pc_after_step_hex']}")
        # self.logger.info(f"  Instruction: {hammer_data['instruction_string']}")
        self.logger.info(f"  Instruction Hex: {hammer_data['instruction_hex']:#x}")
        
        # Register writes
        reg_writes = []
        if hammer_data["register_writes"]:
            self.logger.info("  Register writes:")
            for rw in hammer_data["register_writes"]:
                reg_writes.append((rw['register'], rw['value_hex']))
                if rw['register'][0] == 'c':  # CSR Writes
                    self.logger.info(f"  CSR Write: {rw['register']} = {rw['value_hex']}")
                else:
                    self.logger.info(f"{rw['register']} = {rw['value_hex']}")
                    # Need to check reg addr with rvfi
                    if int(rw['register'][1:]) != rvfi_packet.rd_addr:
                        mismatch = True
                    if rw['value'] != rvfi_packet.rd_wdata:
                        mismatch = True

            self.logger.info(f"Rd:x{rvfi_packet.rd_addr} = {rvfi_packet.rd_wdata:#x}")

        # Memory reads
        if hammer_data["memory_reads"]:
            self.logger.info("  Memory reads:")
            for mr in hammer_data["memory_reads"]:
                self.logger.info(f"[{mr['address_hex']}] = {mr['value']} (size: {mr['size']})")
                self.logger.info(f"RVFI READ ADDR:{rvfi_packet.mem_addr:#x}")
                # assert mr['address'] == rvfi_packet.mem_addr
                if mr['address'] != rvfi_packet.mem_addr:
                    mismatch = True
        
        # Memory writes
        if hammer_data["memory_writes"]:
            self.logger.info("  Memory writes:")
            for mw in hammer_data["memory_writes"]:
                self.logger.info(f"[{mw['address_hex']}] = {mw['value_hex']} (size: {mw['size']})")
                if mw['address'] != rvfi_packet.mem_addr:
                    mismatch = True
                if mw['value'] != self.apply_mask(rvfi_packet.mem_wdata, rvfi_packet.mem_wmask):
                    mismatch = True
        if mismatch:
            raise RuntimeError("RVFI/Hammer mismatch detected! Stopping verification.")
        else:
            #TODO: Push into a Queue
            pass

        
        self.logger.info("═══════════════════════════════════════════════")
        
        await Timer(1, 'ns')  # Small delay
    
    def final_phase(self):
        """Cleanup co-simulation"""
        if self.hammer_cosim:
            self.logger.info("Shutting down Hammer co-simulation...")
            self.hammer_cosim.shutdown()
            self.logger.info(f"Total steps processed: {self.current_step-1}")
    
    async def wait_for_reset(self):
        await FallingEdge(cocotb.top.rst_ni)
        
    async def handle_reset(self):
        await RisingEdge(cocotb.top.rst_ni)
        self.logger.info("Handling reset - reinitializing co-simulation...")
        self.hammer_cosim = HammerCoSim(
            self.elf_path,
            memory_watch_addresses=self.memory_watch_addresses
        )
        
        self.current_step = 1
        self.cosim_ready = False
        result = self.hammer_cosim.start_cosimulation()
        
        if result["success"]:
            self.cosim_ready = True
            self.logger.info("Hammer co-simulation ready and waiting!")
            
            # Query initial PC
            pc_result = self.hammer_cosim.query_pc()
            if pc_result["success"]:
                self.logger.info(f"Hammer Initial PC: {pc_result['pc_hex']}")
            
        else:
            self.logger.error(f"Co-simulation failed: {result['message']}")
            raise RuntimeError("Hammer co-simulation initialization failed")
        
    def apply_mask(self,wdata, wmask, xlen=32):
        """
        Mask off bytes of wdata according to wmask.
        Each bit of wmask corresponds to one byte of wdata.
        """
        lanes = xlen // 8
        masked_val = 0
        for lane in range(lanes):
            if (wmask >> lane) & 1:
                # keep this byte
                byte_val = (wdata >> (8*lane)) & 0xFF
                masked_val |= (byte_val << (8*lane))
        return masked_val