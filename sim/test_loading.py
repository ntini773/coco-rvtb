import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, Timer

async def write_mem(dut, addr, data):
    """Helper function to write to RAM"""
    word_addr = (addr - 0x100000) >> 2  # Adjust for RAM base address
    await RisingEdge(dut.IO_CLK)
    dut.u_ram.u_ram.mem[word_addr].value = data

async def write_ascii(dut, char):
    """Helper function to write ASCII character to output"""
    await RisingEdge(dut.IO_CLK)
    dut.u_simulator_ctrl.ctrl_data.value = ord(char)

@cocotb.test()
async def basic_run_test(dut):
    """
    Test Ibex simple system with:
    - Memory initialization
    - ASCII output
    - Basic program execution
    """
    # Start clock
    clock = Clock(dut.IO_CLK, 10, units="ns")
    cocotb.start_soon(clock.start())

    # Apply reset
    dut.IO_RST_N.value = 0
    dut._log.info("Applying reset...")
    await Timer(100, units="ns")
    dut.IO_RST_N.value = 1
    dut._log.info("Released reset.")

    # Simple program to write "Hello" to ASCII output
    # li x1, 0x20000      # ASCII output address
    # li x2, 0x48         # 'H'
    # sb x2, 0(x1)       # Store byte
    instructions = [
        0x20000037,      # lui x0, 0x20000
        0x04800093,      # li x1, 72 ('H')
        0x00100023,      # sb x1, 0(x0)
    ]

    # Write program to memory starting at reset vector
    base_addr = 0x100080  # Reset vector
    for i, instr in enumerate(instructions):
        await write_mem(dut, base_addr + i*4, instr)
        dut._log.info(f"Writing instruction 0x{instr:08x} to address 0x{base_addr + i*4:08x}")

    # Monitor execution
    for cycle in range(100):
        await RisingEdge(dut.IO_CLK)
        
        # Check ASCII output
        if hasattr(dut.u_simulator_ctrl, "ctrl_data"):
            ascii_val = dut.u_simulator_ctrl.ctrl_data.value
            if ascii_val != 0:
                dut._log.info(f"ASCII Output: '{chr(ascii_val)}'")

    dut._log.info("Test completed.")