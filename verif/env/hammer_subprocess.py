import sys
import os
import json
import signal
from zipfile import Path

def main():
    if len(sys.argv) != 6:
        print(json.dumps({"success": False, "error": "Usage: hammer_subprocess.py <elf_path> <memory_watch_addresses_json>"}), flush=True)
        sys.exit(1)
    

    elf_path = sys.argv[1]
    memory_watch_addresses = json.loads(sys.argv[2])
    isa = sys.argv[3]
    privilege_levels = sys.argv[4]
    start_pc_str = sys.argv[5]
    
    # Parse start_pc (can be None, hex string, or decimal)
    if start_pc_str.lower() == "none" or start_pc_str == "":
        start_pc = None
    elif start_pc_str.startswith("0x"):
        start_pc = int(start_pc_str, 16)
    else:
        start_pc = int(start_pc_str) if start_pc_str.isdigit() else None
        
    # Handle clean shutdown
    def signal_handler(signum, frame):
        print("HAMMER_SUBPROCESS: Shutting down...")
        sys.exit(0)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    # Add Hammer to path and ensure we import the right module

    # Simple path to hammer - assuming we're running from verif directory
    hammer_path = os.path.join(os.getcwd(), '..', 'submodules', 'hammer', 'builddir')
    hammer_path = os.path.abspath(hammer_path)  # Normalize the path
    # hammer_path = '/home/coco-rvtb/submodules/hammer/builddir'
    if hammer_path not in sys.path:
        sys.path.insert(0, hammer_path) 

    # Remove any conflicting paths that might have hammer.py
    sys.path = [p for p in sys.path if not p.endswith('/verif')]

    try:
        import hammer
        
        # Create memory configuration
        mem_cfg = hammer.mem_cfg_t(hammer.DramBase, 256 * 1024 * 1024)
        
        # Verify ELF file
        if not os.path.exists(elf_path):
            raise FileNotFoundError(f"ELF file not found: {elf_path}")
        
        print("HAMMER_READY", flush=True)
        
        # Create Hammer instance
        sim = hammer.Hammer(
            isa,                # ISA
            privilege_levels,   # privilege levels
            "",                 # vector arch
            [0],                # hart ids
            [mem_cfg],          # memory layout
            elf_path,           # ELF path
            start_pc            # start_pc
        )
        # TO ENSURE SPIKE MOVES TO THE START ADDRESS
        for i in range(5):
            sim.single_step(0)
        
        print("HAMMER_INITIALIZED", flush=True)
        
        # Main command loop - wait for commands from parent
        while True:
            try:
                # Wait for command from parent process
                command_line = sys.stdin.readline()
                
                if not command_line.strip():
                    continue
                    
                try:
                    command = json.loads(command_line.strip())
                except json.JSONDecodeError:
                    print(json.dumps({"success": False, "error": "Invalid JSON command"}), flush=True)
                    continue
                
                cmd_type = command.get("type", "")
                
                if cmd_type == "step":
                    # Execute single step and return comprehensive data
                    hart = 0
                    
                    # Get pre-step data
                    pc = sim.get_PC(0) & 0xFFFFFFFF
                    step_data = {}
                    step_data["hart_id"] = command.get("hart_id", 0)
                    step_data["pc"] = pc
                    step_data["pc_hex"] = f"0x{pc:08x}"
                    
                    # Get instruction data
                    try:
                        insn_hex = sim.get_insn_hex(0, pc)
                        step_data["instruction_hex"] = insn_hex
                        step_data["instruction_hex_str"] = f"0x{insn_hex:08x}"
                    except:
                        step_data["instruction_hex"] = None
                        step_data["instruction_hex_str"] = "N/A"
                    
                    try:
                        insn_str = sim.get_insn_string(0, pc)
                        step_data["instruction_string"] = insn_str
                    except:
                        step_data["instruction_string"] = "N/A"
                    
                    # Get register addresses
                    try:
                        step_data["rs1_addr"] = sim.get_rs1_addr(0, pc)
                    except:
                        step_data["rs1_addr"] = None
                        
                    try:
                        step_data["rs2_addr"] = sim.get_rs2_addr(0, pc)
                    except:
                        step_data["rs2_addr"] = None
                        
                    try:
                        step_data["rs3_addr"] = sim.get_rs3_addr(0, pc)
                    except:
                        step_data["rs3_addr"] = None
                        
                    try:
                        step_data["rd_addr"] = sim.get_rd_addr(0, pc)
                    except:
                        step_data["rd_addr"] = None
                    
                    # Get CSR data
                    try:
                        csr_addr = sim.get_csr_addr(0, pc)
                        step_data["csr_addr"] = csr_addr
                        
                        if csr_addr is not None:
                            csr_val = sim.get_csr(0, csr_addr)
                            step_data["csr_value"] = csr_val
                            step_data["csr_value_hex"] = f"0x{csr_val:08x}" if csr_val is not None else "N/A"
                        else:
                            step_data["csr_value"] = None
                            step_data["csr_value_hex"] = "N/A"
                    except:
                        step_data["csr_addr"] = None
                        step_data["csr_value"] = None
                        step_data["csr_value_hex"] = "N/A"
                    
                    # === EXECUTE THE STEP ===
                    sim.single_step(0)
                    
                    # Get post-step data
                    try:
                        pc_after = sim.get_PC(0) & 0xFFFFFFFF
                        step_data["pc_after_step"] = pc_after
                        step_data["pc_after_step_hex"] = f"0x{pc_after:08x}"
                    except:
                        step_data["pc_after_step"] = None
                        step_data["pc_after_step_hex"] = "N/A"
                    
                    # Get register writes
                    try:
                        reg_writes = sim.get_log_reg_writes(0)
                        if reg_writes:
                            step_data["register_writes"] = []
                            for reg, value in reg_writes:
                                step_data["register_writes"].append({
                                    "register": reg,
                                    "value": value,
                                    "value_hex": f"0x{value:08x}"
                                })
                        else:
                            step_data["register_writes"] = []
                    except:
                        step_data["register_writes"] = []
                    
                    # Get memory reads
                    try:
                        mem_reads = sim.get_log_mem_reads(0)
                        if mem_reads:
                            step_data["memory_reads"] = []
                            for addr, value, size in mem_reads:
                                addr_masked = addr & 0xFFFFFFFF
                                step_data["memory_reads"].append({
                                    "address": addr_masked,
                                    "address_hex": f"0x{addr_masked:08x}",
                                    "value": value,
                                    "value_hex": f"0x{value:08x}",
                                    "size": size
                                })
                        else:
                            step_data["memory_reads"] = []
                    except:
                        step_data["memory_reads"] = []
                    
                    # Get memory writes
                    try:
                        mem_writes = sim.get_log_mem_writes(0)
                        if mem_writes:
                            step_data["memory_writes"] = []
                            for addr, value, size in mem_writes:
                                addr_masked = addr & 0xFFFFFFFF
                                # Read the 4-byte value at the written address
                                try:
                                    mem_contents = sim.get_memory_at_VA(0, addr_masked, 4, 4)
                                    mem_value = mem_contents[0] if mem_contents else None
                                except:
                                    mem_value = None
                                step_data["memory_writes"].append({
                                    "address": addr_masked,
                                    "address_hex": f"0x{addr_masked:08x}",
                                    "value": value,
                                    "value_hex": f"0x{value:08x}",
                                    "size": size,
                                    "memory_content" : mem_value
                                })
                        else:
                            step_data["memory_writes"] = []
                    except:
                        step_data["memory_writes"] = []
                    
                    # Get memory contents at watch addresses
                    step_data["memory_contents"] = {}
                    
                    for watch_addr in memory_watch_addresses:
                        try:
                            mem_contents = sim.get_memory_at_VA(0, watch_addr, 4, 1)
                            if mem_contents is not None:
                                value = 0
                                for i, byte_val in enumerate(mem_contents):
                                    value |= (byte_val << (i * 8))
                                step_data["memory_contents"][f"0x{watch_addr:08x}"] = {
                                    "value": value,
                                    "value_hex": f"0x{value:08x}",
                                    "bytes": list(mem_contents)
                                }
                            else:
                                step_data["memory_contents"][f"0x{watch_addr:08x}"] = {
                                    "value": None,
                                    "value_hex": "N/A",
                                    "bytes": []
                                }
                        except:
                            step_data["memory_contents"][f"0x{watch_addr:08x}"] = {
                                "value": None,
                                "value_hex": "N/A",
                                "bytes": []
                            }
                    
                    # Return results
                    result = {
                        "success": True,
                        "type": "step_result",
                        "data": step_data
                    }
                    
                    print(json.dumps(result), flush=True)
                    
                elif cmd_type == "query_pc":
                    # Just return current PC without stepping
                    pc = sim.get_PC(0) & 0xFFFFFFFF
                    result = {
                        "success": True,
                        "type": "query_result",
                        "pc": pc,
                        "pc_hex": f"0x{pc:08x}"
                    }
                    print(json.dumps(result), flush=True)
                    
                elif cmd_type == "shutdown":
                    print(json.dumps({"success": True, "message": "Shutting down"}), flush=True)
                    break
                    
                else:
                    print(json.dumps({"success": False, "error": f"Unknown command type: {cmd_type}"}), flush=True)
                    
            except EOFError:
                # Parent process closed, exit gracefully
                break
            except Exception as e:
                print(json.dumps({"success": False, "error": str(e)}), flush=True)

    except Exception as e:
        print(json.dumps({"success": False, "error": f"Hammer initialization failed: {str(e)}"}), flush=True)
        sys.exit(1)

if __name__ == "__main__":
    main()