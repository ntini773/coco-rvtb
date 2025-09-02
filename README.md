# COCO-RVTB

![Diagram](docs/coco_rvtb.png)

## Project Summary:
This project aims to provide a generic testbench that allows easy integration with design for functional verification. The testbench uses RVFI interface to gather data packets from the DUT, that will then be compared against Spike packet.

## Workflow
An example worklow could be the following:
1. Preload IMEM and DMEM on Spike and DUT
2. Kick-off execution on DUT and Spike
3. As soon as DUT commits one instruction, i.e. RVFI asserts valid, update spike to execute one instruction.
4. Compare packets
5. Stop execution in case of mismatch

## Challenges
1. Preloading memories:
    - If we use elf, we need to read the text section and the data section and load them in their respective memories
    - If we use binary format we need to generate bins for both memories
2. Implement a bus protocol
    - We need an interconnect to interface DUT and the memories
    - To support Ibex we will implement its bus protocol
3. Connect DUT with the TB interconnect
    - To map the DUT signals with our bus implementation, we can use a yaml file, which will contain the name of the DUT's interface signal names.
    - The TB will use signal names from yaml to connect the two ends (DUT and TB)

## Proof of concept
The inital implementation will contain an Ibex core as DUT. The testbench will implement a bus interface that will connect the memories with Ibex and capture the data of retired instructions through its RVFI interface and compare it with Spike data packet.

Further implementations will support multiple bus protocols that will support most of the open-source RISC-V cores.

## Getting Started

### Prerequisites
- Python 3.8 or higher
- Verilator (for SystemVerilog simulation) - Required for running full simulations
- Git (for submodule management)
- Build tools for compiling submodules (gcc, make, cmake)

### Installation

1. **Clone the repository with submodules:**
   ```bash
   git clone --recursive https://github.com/ntini773/coco-rvtb.git
   cd coco-rvtb
   ```

   If you already cloned without submodules, initialize them:
   ```bash
   git submodule update --init --recursive
   ```

2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

### Building

The project uses cocotb with Verilator for simulation. 

**Note:** Full simulation requires Verilator to be installed. Install Verilator following the [official installation guide](https://verilator.org/guide/latest/install.html).

**For Hammer co-simulation:** Build the Hammer submodule:
```bash
cd submodules/hammer
# Follow Hammer-specific build instructions
```

**Running simulations:** Build and run from the verification directory:

```bash
cd verif
make ELF_PATH=./elf_files/ibex_load_instr_test_0.o
```

### Usage

#### Running Simulations
To run a simulation with a specific ELF file:
```bash
cd verif
make ELF_PATH=./elf_files/ibex_arithmetic_basic_test_0.o
```

Optional: Specify a log file:
```bash
make ELF_PATH=./elf_files/ibex_load_instr_test_0.o LOG_PATH=./simulation.log
```

#### Example Files

**Memory Model Test:**
Test the memory model functionality:

```bash
cd verif/utils
python3 test_memory.py
```

This example demonstrates:
- Loading ELF files into memory model
- Reading and writing memory locations
- Memory dumping functionality

**Hammer Co-simulation Example:**
The `hammer_cosim.py` file demonstrates how to use the Hammer RISC-V ISA simulator for co-simulation:

```bash
cd verif/env
python3 hammer_cosim.py
```

*Note: This example requires the Hammer submodule to be built. The Hammer simulator must be compiled before running this example.*

This example demonstrates:
- Initializing a Hammer co-simulation with an ELF file
- Executing instruction steps
- Displaying PC values, instruction strings, and register/memory writes
- Querying processor state
- Synchronous communication with the Hammer subprocess

**Available Test ELF Files:**
- `ibex_arithmetic_basic_test_0.o` - Basic arithmetic operations test
- `ibex_load_instr_test_0.o` - Load instruction test  
- `ibex_rand_instr_test_0.o` - Random instruction test
- Additional test files in `verif/elf_files/`

### Requirements Details
The project depends on these Python packages (see `requirements.txt`):
- `cocotb==1.9.2` - Python-based verification framework
- `find_libpython==0.4.1` - Library path detection
- `intelhex==2.3.0` - Intel HEX file format support
- `pybind11==3.0.1` - Python C++ bindings
- `pyelftools==0.32` - ELF file parsing
- `pyuvm==3.0.0` - Universal Verification Methodology for Python
