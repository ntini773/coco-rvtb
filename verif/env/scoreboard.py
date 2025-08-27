import pyuvm 
from pyuvm import *
from pathlib import Path
import os, time, sys
import cocotb
from cocotb.triggers import Timer, RisingEdge, FallingEdge,First

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
        
        # Setup log file if LOG_PATH is provided
        log_path_raw = cocotb.plusargs.get("LOG_PATH")
        if log_path_raw:
            self.log_file_path = str(Path(log_path_raw).expanduser().resolve())
            self.log_file = open(self.log_file_path, 'w')
            self.enable_logging = True
        else:
            self.log_file = None
            self.enable_logging = False
        
        # Set up memory addresses to watch
        #TODO : Change this to a variable To-host address
        self.memory_watch_addresses = [
            0x80002000  # Your target memory location
        ]
        
    
    def log_message(self, level, message):
        """Log message to both CLI and file if enabled"""
        # Log to CLI using the appropriate logger level
        if level == "info":
            self.logger.info(message)
        elif level == "error":
            self.logger.error(message)
        elif level == "warning":
            self.logger.warning(message)
        elif level == "debug":
            self.logger.debug(message)
        
        # Log to file if enabled
        if self.enable_logging and self.log_file:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            self.log_file.write(f"[{timestamp}] [{level.upper()}] {message}\n")
            self.log_file.flush()  # Ensure immediate write
    
    async def run_phase(self):
        """Main verification loop with co-simulation"""
        while True:
            
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
                
                # This blocks until FIFO has data
                rvfi_packet = await self.rvfi_port.get()
                
                
                # === NOW STEP HAMMER (synchronized!) ===
                
                step_result = self.hammer_cosim.step_instruction(0)
                
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
        """Compare both RVFI packet and Hammer data side by side"""
        
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
        mismatch = False

        # Compare PC
        if hammer_data['pc'] != rvfi_packet.pc_rdata:
            mismatch = True

        # Compare instruction hex
        if hammer_data['instruction_hex'] != rvfi_packet.insn:
            mismatch = True
        
        # Register writes
        reg_writes = {}
        if hammer_data["register_writes"]:
            for rw in hammer_data["register_writes"]: 
                if rw['register'].startswith('x'):  # GPR Writes eg:x30
                    reg_writes[rw['register']] = rw['value_hex']
                    if int(rw['register'][1:]) != rvfi_packet.rd_addr:
                        mismatch = True
                    if rw['value'] != rvfi_packet.rd_wdata:
                        mismatch = True
                elif rw['register'].startswith('c'):  # CSR Writes eg:c786
                    reg_writes[rw['register']] = rw['value_hex']

        # Memory reads
        mem_reads=[]
        if hammer_data["memory_reads"]:
            for mr in hammer_data["memory_reads"]:
                mem_reads.append(mr['address_hex'])
                if mr['address'] != rvfi_packet.mem_addr:
                    mismatch = True
        
        # Memory writes
        mem_writes = []
        if hammer_data["memory_writes"]:
            for mw in hammer_data["memory_writes"]:
                if mw['address'] != rvfi_packet.mem_addr:
                    mismatch = True
                if mw['value'] != self.apply_mask(rvfi_packet.mem_wdata, rvfi_packet.mem_wmask):
                    mismatch = True
                mem_writes.append({
                        "addr": mw['address'],
                    "addr_hex": mw['address_hex'],
                    "value": mw['value'],
                    "value_hex": mw['value_hex'],
                    "size": mw['size']
                })
        if not mismatch:
            log_parts = [
                f"{rvfi_packet.pc_rdata:#x}",
                f"{rvfi_packet.insn:#010x}",  # 0x-prefixed, zero-padded to 10 chars
                f"  {rvfi_packet.mode}  ",
                f"{hammer_data['instruction_string']:<25}"
            ]
            # Add Register writes to log 
            reg_list=[]
            if reg_writes:
                for reg, val in reg_writes.items():
                    reg_list.append(f"{reg}:{val}")
                log_parts.append(f"[{', '.join(reg_list):<13}]")
            # Add Memory reads to logs
            if mem_reads:
                for mr in mem_reads:
                    log_parts.append(f"MEMRead: A@[{mr}]")
            if mem_writes:
                for mw in mem_writes:
                    log_parts.append(f"MEMWrites: [{mw['value_hex']}] , A@[{mw['addr_hex']}] ")
            log_string = ", ".join(log_parts)

            # Add to queue ONLY if no mismatch
            if self.log_queue.full():
                self.log_queue.get()  # Remove oldest
            queue_entry = f"Step {self.current_step}: {log_string}"
            self.log_queue.put(queue_entry)
            if self.enable_logging:
                self.log_message("info", f"Step {self.current_step:<4}:{log_string}")
                if rvfi_packet.trap:
                    # Use ANSI escape codes for colored output (yellow for trap)
                    # Print colored output to CLI, plain text to log file
                    self.logger.info(f"\033[93mStep {self.current_step:<4}:TRAP DETECTED\033[0m")
                    if self.enable_logging:
                        if self.log_file:
                            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                            self.log_file.write(f"[{timestamp}] [INFO] Step {self.current_step:<4}:TRAP DETECTED\n")
                            self.log_file.flush()

        else:
            # Dump entire queue and log each entry
            self.log_message("error", f"LAST {self.log_queue.qsize()} INSTRUCTIONS:")
            while not self.log_queue.empty():
                log = self.log_queue.get()
                self.log_message("error", f"PREVIOUS STEP: {log}")

            self.log_message("error", "🔴 MISMATCH DETECTED!")
            self.log_message("error", "="*100)
            self.log_message("error", f"STEP {self.current_step} COMPARISON")
            self.log_message("error", "="*100)

            # Show basic comparison
            self.log_message("error", f"PC: RVFI={rvfi_packet.pc_rdata:#x} | Hammer={hammer_data['pc_hex']}")
            self.log_message("error", f"INSN: RVFI={rvfi_packet.insn:#x} | Hammer={hammer_data['instruction_hex_str']}")
            self.log_message("error", f"INSN_STR: {hammer_data['instruction_string']}")
            self.log_message("error", "")

            # Show register writes comparison
            self.log_message("error", "REGISTER WRITES:")
            rvfi_reg_str = f"x{rvfi_packet.rd_addr}:{rvfi_packet.rd_wdata:#x}"

            hammer_reg_parts = []
            for reg, val in reg_writes.items():
                hammer_reg_parts.append(f"{reg} : {val}")
            hammer_reg_str = f"[{', '.join(hammer_reg_parts)}]" if hammer_reg_parts else "NONE"

            self.log_message("error", f"  RVFI: {rvfi_reg_str}")
            self.log_message("error", f"  Hammer: {hammer_reg_str}")
            self.log_message("error", "")

            self.log_message("error", "MEMORY READS:")
            rvfi_read_str =f"A@[{rvfi_packet.mem_addr:#x}]" if rvfi_packet.mem_addr != 0 else "NONE"
            hammer_read_parts = [f"A@[{mr}]" for mr in mem_reads]
            hammer_read_str = f"[{', '.join(hammer_read_parts)}]" if hammer_read_parts else "NONE"
            self.log_message("error", f"  RVFI: {rvfi_read_str}")
            self.log_message("error", f"  Hammer: {hammer_read_str}")
            self.log_message("error", "")

            self.log_message("error", "MEMORY WRITES:")
            rvfi_write_str = f"[{self.apply_mask(rvfi_packet.mem_wdata, rvfi_packet.mem_wmask):#x}], @A[{rvfi_packet.mem_addr:#x}]" if rvfi_packet.mem_wmask != 0 else "NONE"
            hammer_write_parts = [f"{mw['value_hex']}@A[{mw['addr_hex']}]" for mw in mem_writes]
            hammer_write_str = f"[{', '.join(hammer_write_parts)}]" if hammer_write_parts else "NONE"
            self.log_message("error", f"  RVFI: {rvfi_write_str}")
            self.log_message("error", f"  Hammer: {hammer_write_str}")
            self.log_message("error", "")

            keep_running =ConfigDB().get(None,"","keep_running")
            keep_running = False
            ConfigDB().set(None,"*","keep_running",keep_running)
            
            
            raise RuntimeError("RVFI/Hammer mismatch detected! Stopping verification.")
        
        
        await Timer(1, 'ns')  # Small delay
    
    def final_phase(self):
        """Cleanup co-simulation"""
        if self.hammer_cosim:
            self.logger.info("Shutting down Hammer co-simulation...")
            self.hammer_cosim.shutdown()
            self.logger.info(f"Total steps processed: {self.current_step}")
        
        # Close log file if it was opened
        if self.enable_logging and self.log_file:
            self.log_file.close()
            self.logger.info(f"Log file closed: {self.log_file_path}")
    
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
        if self.enable_logging:
            self.log_message("info", "="*80)
            self.log_message("info", f"{'STEP':<12} {'PC':<8} {'INSTRUCTION':<12} {'MODE':<6} {'INSTRUCTION STRING':<25} OPERATIONS")
            self.log_message("info", "="*80)
        
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