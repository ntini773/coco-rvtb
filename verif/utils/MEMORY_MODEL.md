
# Memory Model and Testbench

This directory contains a Python-based memory model and a simple testbench for simulating and verifying memory operations, including support for loading ELF, HEX, and VMEM files.

## Memory Model (`memory_model.py`)

### Features
- **Configurable RAM base and size** (default: 0x80000000, 1MB)
- **Peripheral register emulation** (ASCII output, halt, RISC-V timer registers)
- **Byte-addressable memory**
- **Read and write operations** with support for 1, 2, or 4 bytes
- **Memory preloading** from ELF, Intel HEX, or VMEM files
- **Memory dump** to file or string for inspection

#### Peripheral Map
| Address    | Description                       |
|------------|-----------------------------------|
| 0x20000    | ASCII Out (write char to log)     |
| 0x20008    | Simulator Halt (write 1 to halt)  |
| 0x30000    | RISC-V timer mtime (low)          |
| 0x30004    | RISC-V timer mtimeh (high)        |
| 0x30008    | RISC-V timer mtimecmp (low)       |
| 0x3000C    | RISC-V timer mtimecmph (high)     |
| 0x80000000 | RAM base (default, 1MB)           |

### Usage
- **Read:** `read(addr, size=4)`
- **Write:** `write(addr, value, size=4)`
- **Preload memory:** `preload_memory(file_path)`
- **Dump memory:** `dump_memory(filename=None, start_addr=None, size=None)`

## Testbench (`test_memory.py`)

A simple unittest-based testbench that demonstrates how to use the memory model:
- Preloads an ELF file into memory
- Writes a value to memory
- Dumps memory contents to a file
- Reads back and prints memory contents

### How to Run the Testbench

1. **Install dependencies:**
   ```bash
   pip install pyelftools intelhex
   ```

2. **Prepare an ELF/HEX/VMEM file:**
   - Place your ELF file (e.g., `ibex_arithmetic_basic_test_0.o`) in an `elf_files/` directory relative to the test script, or update the path in `test_memory.py`.

3. **Run the testbench: From the root of the repository, use the following commands:**
   ```bash
   cd verif/utils
   python3 test_memory.py
   ```

4. **Check output:**
   - Memory dump will be written to `check_memory.txt`.
   - Console output will show memory contents before and after preload.

## Notes
- Currently, only ELF file loading is tested. HEX and VMEM support are present but not fully tested and are under development.
- The memory model is generic and can be extended for more peripherals or custom memory maps.
- For more advanced use, see the docstrings in `memory_model.py`.
