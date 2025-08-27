import subprocess
import sys
import os
import json
import time
from pathlib import Path

class HammerCoSim:
    """Simplified Hammer co-simulation without threading - synchronous communication"""

    def __init__(self, elf_path, memory_watch_addresses=None,isa="RV32IMC",privilege_levels="msu",start_pc=None):
        self.elf_path = str(Path(elf_path).expanduser().resolve())
        self.memory_watch_addresses = memory_watch_addresses or []
        self.isa = isa
        self.privilege_levels = privilege_levels
        self.start_pc = start_pc
        self.process = None
        self.is_running = False
        
    def start_cosimulation(self):
        """Start the Hammer subprocess and establish communication"""
        
        # Path to the Hammer subprocess script
        script_path = Path(__file__).parent / "hammer_subprocess.py"
        # Convert start_pc to string
        start_pc_str = "none" if self.start_pc is None else str(self.start_pc)
        # Start subprocess with pipes for bidirectional communication
        self.process = subprocess.Popen(
            [
                sys.executable, 
                str(script_path), 
                self.elf_path, 
                json.dumps(self.memory_watch_addresses),
                self.isa,
                self.privilege_levels,
                start_pc_str
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=0,  # Unbuffered
            cwd=os.getcwd()
        )
        
        self.is_running = True
        
        # Wait for initialization synchronously
        try:
            # Read HAMMER_READY
            ready_line = self.process.stdout.readline().strip()
            if ready_line != "HAMMER_READY":
                stderr_output = self.process.stderr.read()
                return {"success": False, "message": f"Expected HAMMER_READY, got: {ready_line}. Stderr: {stderr_output}"}
            
            # Read HAMMER_INITIALIZED
            init_line = self.process.stdout.readline().strip()
            if init_line != "HAMMER_INITIALIZED":
                stderr_output = self.process.stderr.read()
                return {"success": False, "message": f"Expected HAMMER_INITIALIZED, got: {init_line}. Stderr: {stderr_output}"}
            
            return {"success": True, "message": "Hammer co-simulation ready"}
            
        except Exception as e:
            stderr_output = self.process.stderr.read() if self.process.stderr else "No stderr"
            return {"success": False, "message": f"Hammer startup error: {e}. Stderr: {stderr_output}"}
    
    def send_command(self, command, timeout=5):
        """Send command to Hammer subprocess and wait for response synchronously"""
        if not self.is_running or not self.process:
            return {"success": False, "error": "Co-simulation not running"}
        
        try:
            # Send command
            command_json = json.dumps(command) + "\n"
            self.process.stdin.write(command_json)
            self.process.stdin.flush()
            
            # Read response synchronously
            response_line = self.process.stdout.readline().strip()
            if not response_line:
                return {"success": False, "error": "No response from subprocess"}
            
            # Parse JSON response
            try:
                response = json.loads(response_line)
                return response
            except json.JSONDecodeError:
                return {"success": False, "error": f"Invalid JSON response: {response_line}"}
            
        except Exception as e:
            return {"success": False, "error": f"Command error: {e}"}
    
    def step_instruction(self, hart_id=0):
        """Execute single instruction step and get comprehensive data"""
        command = {
            "type": "step",
            "hart_id": hart_id
        }
        return self.send_command(command)
    
    def query_pc(self):
        """Get current PC to be executed without stepping"""
        command = {"type": "query_pc"}
        return self.send_command(command)
    
    def shutdown(self):
        """Shutdown the co-simulation"""
        if self.is_running:
            self.is_running = False
            
            if self.process:
                try:
                    # Try graceful shutdown first
                    shutdown_cmd = {"type": "shutdown"}
                    self.send_command(shutdown_cmd)
                except:
                    pass
                
                # Force termination if needed
                try:
                    self.process.terminate()
                    self.process.wait(timeout=5)
                except:
                    self.process.kill()
                    self.process.wait()
    
    def __del__(self):
        self.shutdown()

# Example usage
def test_cosimulation():
    """Test the co-simulation"""
    
    watch_addresses = [0x80002000, 0x8000bc48]
    
    # Start co-simulation
    cosim = HammerCoSim(
        "../elf_files/ibex_load_instr_test_0.o",
        memory_watch_addresses=watch_addresses,
        isa="RV32IMC",              # Custom ISA
        privilege_levels="msu",      # Custom privilege levels
        start_pc=0x80000000         # Custom start PC
    )
    
    result = cosim.start_cosimulation()
    print(f"Startup: {result}")
    
    if result["success"]:
        try:
            # Query current PC
            pc_result = cosim.query_pc()
            print(f"Current PC: {pc_result}")
            
            # Execute a few steps
            for step in range(3):
                print(f"\n=== Executing step {step} ===")
                
                step_result = cosim.step_instruction(step)
                
                if step_result["success"]:
                    data = step_result["data"]
                    print(f"PC: {data['pc_hex']} -> {data['pc_after_step_hex']}")
                    print(f"Instruction: {data['instruction_string']}")
                    
                    if data["register_writes"]:
                        print("Register writes:")
                        for rw in data["register_writes"]:
                            print(f"{rw['register']} = {rw['value_hex']}")
                    
                    if data["memory_writes"]:
                        print("Memory writes:")
                        for mw in data["memory_writes"]:
                            print(f"[{mw['address_hex']}] = {mw['value_hex']}")
                else:
                    print(f"Step failed: {step_result}")
                    
        finally:
            cosim.shutdown()

if __name__ == "__main__":
    test_cosimulation()