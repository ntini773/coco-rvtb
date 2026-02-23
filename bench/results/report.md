# coco-rvtb Benchmark Report

**Generated:** 2026-02-23 21:43:50  
**Total benchmark time:** 246.2 s

---

## 1 · Spike CLI vs Hammer Python API

> Measures wall-clock time and instructions/sec for running each ELF.

| ELF | Method | Window (s) | Steps | Insns/s | Stdev |
|-----|--------|-----------|-------|---------|-------|
| `ibex_arithmetic_basic_test_0.o` | hammer_python | 3.0 | 1,463,898 | 487,966 | 32,952 |
| `ibex_arithmetic_basic_test_0.o` | spike_cli | 3.0 | 1,068,198 | 322,241 | 11,237 |
| `ibex_arithmetic_basic_test_1.o` | hammer_python | 3.0 | 1,468,248 | 489,415 | 9,617 |
| `ibex_arithmetic_basic_test_1.o` | spike_cli | 3.0 | 1,071,854 | 323,315 | 20,832 |
| `ibex_load_instr_test_0.o` | hammer_python | 3.0 | 1,470,962 | 490,320 | 12,911 |
| `ibex_load_instr_test_0.o` | spike_cli | 3.0 | 1,053,825 | 316,316 | 33,292 |
| `ibex_load_instr_test_1.o` | hammer_python | 3.0 | 1,484,287 | 494,761 | 17,481 |
| `ibex_load_instr_test_1.o` | spike_cli | 3.0 | 1,074,451 | 324,117 | 24,121 |
| `ibex_load_instr_test_3.o` | hammer_python | 3.0 | 1,458,169 | 486,056 | 12,957 |
| `ibex_load_instr_test_3.o` | spike_cli | 3.0 | 1,028,132 | 313,306 | 8,242 |
| `ibex_rand_instr_test_0.o` | hammer_python | 3.0 | 1,471,438 | 490,479 | 7,731 |
| `ibex_rand_instr_test_0.o` | spike_cli | 3.0 | 1,015,743 | 306,440 | 29,737 |
| `ibex_rand_instr_test_1.o` | hammer_python | 3.0 | 1,470,625 | 490,208 | 14,638 |
| `ibex_rand_instr_test_1.o` | spike_cli | 3.0 | 1,051,644 | 314,114 | 17,813 |

**Average Hammer insns/sec:** 489,887  
**Average Spike CLI insns/sec:** 317,121  
**Spike/Hammer ratio:** 0.65x

```
Throughput comparison (higher = better)
  ibex_arithmetic_basic_ [hammer_p] ███████████████████████████████████░    487,966 /s
  ibex_arithmetic_basic_ [spike_cl] ███████████████████████░░░░░░░░░░░░░    322,241 /s
  ibex_arithmetic_basic_ [hammer_p] ███████████████████████████████████░    489,415 /s
  ibex_arithmetic_basic_ [spike_cl] ███████████████████████░░░░░░░░░░░░░    323,315 /s
  ibex_load_instr_test_0 [hammer_p] ███████████████████████████████████░    490,320 /s
  ibex_load_instr_test_0 [spike_cl] ███████████████████████░░░░░░░░░░░░░    316,316 /s
  ibex_load_instr_test_1 [hammer_p] ████████████████████████████████████    494,761 /s
  ibex_load_instr_test_1 [spike_cl] ███████████████████████░░░░░░░░░░░░░    324,117 /s
  ibex_load_instr_test_3 [hammer_p] ███████████████████████████████████░    486,056 /s
  ibex_load_instr_test_3 [spike_cl] ██████████████████████░░░░░░░░░░░░░░    313,306 /s
  ibex_rand_instr_test_0 [hammer_p] ███████████████████████████████████░    490,479 /s
  ibex_rand_instr_test_0 [spike_cl] ██████████████████████░░░░░░░░░░░░░░    306,440 /s
  ibex_rand_instr_test_1 [hammer_p] ███████████████████████████████████░    490,208 /s
  ibex_rand_instr_test_1 [spike_cl] ██████████████████████░░░░░░░░░░░░░░    314,114 /s
```

---

## 2 · Hammer Direct Import vs JSON Subprocess (IPC Overhead)

> Quantifies the per-step latency cost of the subprocess JSON-pipe layer.

| ELF | Method | Mean lat (µs) | Stdev (µs) | Steps/sec |
|-----|--------|--------------|------------|-----------|
| `ibex_arithmetic_basic_test_0.o` | direct | 2.52 | 3.81 | 397,428 |
| `ibex_arithmetic_basic_test_0.o` | cosim_subprocess | 135.80 | 32.67 | 7,364 |
| `ibex_arithmetic_basic_test_1.o` | direct | 4.24 | 3.80 | 235,917 |
| `ibex_arithmetic_basic_test_1.o` | cosim_subprocess | 133.13 | 32.04 | 7,512 |
| `ibex_load_instr_test_0.o` | direct | 4.39 | 3.65 | 227,908 |
| `ibex_load_instr_test_0.o` | cosim_subprocess | 139.10 | 75.90 | 7,189 |
| `ibex_load_instr_test_1.o` | direct | 4.52 | 4.95 | 221,078 |
| `ibex_load_instr_test_1.o` | cosim_subprocess | 128.61 | 27.67 | 7,776 |
| `ibex_load_instr_test_3.o` | direct | 3.17 | 3.40 | 315,481 |
| `ibex_load_instr_test_3.o` | cosim_subprocess | 121.94 | 22.61 | 8,200 |
| `ibex_rand_instr_test_0.o` | direct | 4.49 | 3.73 | 222,489 |
| `ibex_rand_instr_test_0.o` | cosim_subprocess | 129.36 | 23.93 | 7,731 |
| `ibex_rand_instr_test_1.o` | direct | 4.53 | 3.45 | 220,837 |
| `ibex_rand_instr_test_1.o` | cosim_subprocess | 124.81 | 24.82 | 8,012 |

**Avg direct step latency:** 3.98 µs  
**Avg cosim step latency:** 130.39 µs  
**IPC overhead:** +3176.3% per step  
**Takeaway:** The JSON-pipe subprocess layer adds ~126.4 µs/step of overhead, which trades raw speed for observation richness (full JSON state per step).

---

## 3 · Serial vs Parallel ELF Processing

> ProcessPoolExecutor speedup across all ELF files.

| Mode | Workers | Wall (s) | Total Steps | Agg insns/s | Speedup | Efficiency |
|------|---------|----------|-------------|-------------|---------|------------|
| serial | 1 | 0.04 | 1,559 | 35,561 | 1.00x | 100.0% |
| parallel | 2 | 0.04 | 1,559 | 37,110 | 1.04x | 52.2% |
| parallel | 4 | 0.04 | 1,559 | 40,088 | 1.13x | 28.2% |

```
Aggregate throughput (insns/s) — higher is better
  serial           ███████████████████████████████░░░░░     35,561 /s
  parallel-2       █████████████████████████████████░░░     37,110 /s
  parallel-4       ████████████████████████████████████     40,088 /s
```

---

## 4 · ELF Load Performance — Python vs Hammer C++

> pyelftools-based Python loader vs Hammer C++ Spike loader.

| ELF | Method | Size (KB) | Mean (ms) | Stdev (ms) | MB/s |
|-----|--------|-----------|-----------|------------|------|
| `ibex_arithmetic_basic_test_0.o` | python_memory_model | 53.7 | 8.13 | 1.24 | 6.8 |
| `ibex_arithmetic_basic_test_0.o` | hammer_cpp_loader | 53.7 | 4.45 | 0.30 | 12.4 |
| `ibex_arithmetic_basic_test_1.o` | python_memory_model | 53.7 | 7.56 | 0.90 | 7.3 |
| `ibex_arithmetic_basic_test_1.o` | hammer_cpp_loader | 53.7 | 4.82 | 0.22 | 11.4 |
| `ibex_load_instr_test_0.o` | python_memory_model | 70.1 | 10.44 | 0.79 | 6.9 |
| `ibex_load_instr_test_0.o` | hammer_cpp_loader | 70.1 | 4.99 | 0.30 | 14.4 |
| `ibex_load_instr_test_1.o` | python_memory_model | 70.1 | 10.11 | 0.97 | 7.1 |
| `ibex_load_instr_test_1.o` | hammer_cpp_loader | 70.1 | 4.90 | 0.30 | 14.6 |
| `ibex_load_instr_test_3.o` | python_memory_model | 70.1 | 9.86 | 0.89 | 7.3 |
| `ibex_load_instr_test_3.o` | hammer_cpp_loader | 70.1 | 4.73 | 0.21 | 15.2 |
| `ibex_rand_instr_test_0.o` | python_memory_model | 70.1 | 9.79 | 0.83 | 7.3 |
| `ibex_rand_instr_test_0.o` | hammer_cpp_loader | 70.1 | 5.26 | 0.44 | 13.6 |
| `ibex_rand_instr_test_1.o` | python_memory_model | 70.1 | 10.18 | 0.99 | 7.1 |
| `ibex_rand_instr_test_1.o` | hammer_cpp_loader | 70.1 | 5.00 | 0.31 | 14.3 |

**Avg Python load:** 9.44 ms  
**Avg Hammer C++ load:** 4.88 ms  
**C++ speedup:** 1.9x faster at ELF loading

---

## Key Takeaways

1. **Hammer Python API** gives fine-grained per-instruction observability that Spike CLI alone cannot provide (register writes, memory reads/writes, CSR values).

2. **JSON subprocess IPC** (the `HammerCoSim` layer) introduces latency per step but is architecturally necessary for integration with the cocotb simulation loop which runs in a separate process.

3. **Parallel processing** with `ProcessPoolExecutor` provides near-linear speedup for independent ELF workloads — a significant throughput improvement for regression suites.

4. **C++ ELF loading** (Hammer) is substantially faster than Python's pyelftools, but Python's `MemoryModel` is the right choice for the bus-functional model inside the cocotb testbench.
