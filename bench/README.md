# coco-rvtb Benchmark Suite

Self-contained benchmarks for the Python-based RISC-V testbench workflow.
All scripts run exclusively with the ELF files in `verif/elf_files/` 

---

## Prerequisites

- `Installed requirements.txt` with `hammer` importable
- `~/riscv/bin/spike` available (built from the `submodules/riscv-isa-sim` checkout)
- Run from the repository root

```bash
cd /home/nitin/coco-rvtb
```

---

## Running

### Full suite (recommended)

```bash
 python3 bench/run_all.py
```

Produces:
- `bench/results/report.md` — human-readable tables + ASCII bar charts
- `bench/results/results.json` — structured machine-readable data

### Individual benchmarks

```bash
# 1. Spike CLI vs Hammer Python API
python3 bench/01_spike_vs_hammer.py

# 2. Hammer direct import vs JSON subprocess IPC overhead
python3 bench/02_direct_vs_subprocess.py

# 3. Serial vs Parallel ELF processing (pytest-style workload)
python3 bench/03_serial_vs_parallel.py

# 4. ELF loading: Python pyelftools vs Hammer C++ loader
python3 bench/04_elf_load_bench.py
```

---

## What Each Benchmark Measures

| Script | Question answered |
|--------|-------------------|
| `01_spike_vs_hammer.py` | How fast is Hammer Python API vs raw Spike CLI for stepping through ELF programs? Measures instructions/sec and startup overhead. |
| `02_direct_vs_subprocess.py` | What is the per-step latency cost of the JSON-pipe subprocess layer used by `HammerCoSim`? Direct call vs IPC overhead (µs/step). |
| `03_serial_vs_parallel.py` | How much can `ProcessPoolExecutor` parallelize running multiple ELF tests? Speedup and efficiency across 1/2/4/N-core configs. |
| `04_elf_load_bench.py` | How fast does each ELF load? Python `MemoryModel` (pyelftools) vs Hammer C++ Spike loader (MB/s). |

---

## Design Notes

- **No existing files modified.** All benchmark code lives in `bench/` only.
- **All 7 ELF files** in `verif/elf_files/` are picked up automatically via `glob("*.o")`.
- Each script is self-contained and independently runnable.
- `run_all.py` imports each script as a module and calls its `main()`.
- Parallel benchmark (03) uses `ProcessPoolExecutor` with process isolation —
  each worker gets its own Hammer/Spike instance, with no shared state.

---

## Directory Layout

```
bench/
├── 01_spike_vs_hammer.py        # Spike CLI vs Hammer Python
├── 02_direct_vs_subprocess.py   # Direct Hammer vs CoSim subprocess IPC
├── 03_serial_vs_parallel.py     # Serial vs parallel ELF workloads
├── 04_elf_load_bench.py         # ELF load throughput comparison
├── run_all.py                   # Orchestrator + report writer
├── README.md                    # This file
└── results/                     # Created automatically by run_all.py
    ├── report.md
    └── results.json
```
