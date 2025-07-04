import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, Timer

@cocotb.test()
async def basic_run_test(dut):
    """
    Basic smoke test for ibex_simple_system.
    - Drives clock
    - Applies reset
    - Lets the design run for a few cycles
    """

    # Start clock (assuming clk name is IO_CLK)
    clock = Clock(dut.IO_CLK, 10, units="ns")  # 100 MHz
    cocotb.start_soon(clock.start())

    # Apply reset (active-low)
    dut.IO_RST_N.value = 0
    dut._log.info("Applying reset...")
    await Timer(100, units="ns")
    dut.IO_RST_N.value = 1
    dut._log.info("Released reset.")

    # Wait for a few cycles to let the CPU do something
    for cycle in range(100):
        await RisingEdge(dut.IO_CLK)
        # print(hasattr(dut, "IO_UART_TX"))
        if hasattr(dut, "IO_UART_TX"):
            uart_bit = dut.IO_UART_TX.value
            dut._log.info(f"Cycle {cycle}: UART_TX = {uart_bit}")

    dut._log.info("Basic Ibex simple system test completed.")
