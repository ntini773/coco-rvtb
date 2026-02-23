#!/usr/bin/env python3
"""
run_all.py – Master orchestrator for all coco-rvtb benchmarks
==============================================================
Runs all 4 benchmarks sequentially, collects results, and writes:
  bench/results/report.md   – human-readable markdown report with tables & charts
  bench/results/results.json – machine-readable JSON

Usage:
    conda run -n gsoc python3 bench/run_all.py

Individual scripts can also be run on their own:
    conda run -n gsoc python3 bench/01_spike_vs_hammer.py
    conda run -n gsoc python3 bench/02_direct_vs_subprocess.py
    conda run -n gsoc python3 bench/03_serial_vs_parallel.py
    conda run -n gsoc python3 bench/04_elf_load_bench.py
"""

import sys
import time
import json
import datetime
import statistics
import traceback
from pathlib import Path

REPO_ROOT   = Path(__file__).resolve().parent.parent
BENCH_DIR   = Path(__file__).resolve().parent
RESULTS_DIR = BENCH_DIR / "results"
RESULTS_DIR.mkdir(exist_ok=True)

# Add hammer to path for sub-imports
HAMMER_DIR = REPO_ROOT / "submodules" / "hammer" / "builddir"
if str(HAMMER_DIR) not in sys.path:
    sys.path.insert(0, str(HAMMER_DIR))


# ── Import benchmark modules ───────────────────────────────────────────────
sys.path.insert(0, str(BENCH_DIR))
import importlib

def load_bench(name):
    return importlib.import_module(name)


# ── ASCII bar ──────────────────────────────────────────────────────────────
def bar(val, max_val, width=36):
    n = int(val / max_val * width) if max_val > 0 else 0
    return "█" * n + "░" * (width - n)


# ── Markdown report builder ────────────────────────────────────────────────
def build_report(all_data: dict, run_time_sec: float) -> str:
    now  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []
    A = lines.append

    A("# coco-rvtb Benchmark Report")
    A(f"\n**Generated:** {now}  ")
    A(f"**Total benchmark time:** {run_time_sec:.1f} s\n")

    A("---\n")

    # ── Bench 1 ────────────────────────────────────────────────────────────
    A("## 1 · Spike CLI vs Hammer Python API\n")
    A("> Measures wall-clock time and instructions/sec for running each ELF.\n")
    b1 = all_data.get("bench1", [])
    if b1:
        hammer_r = [r for r in b1 if r["method"] == "hammer_python"]
        spike_r  = [r for r in b1 if r["method"] == "spike_cli"]

        A("| ELF | Method | Window (s) | Steps | Insns/s | Stdev |")
        A("|-----|--------|-----------|-------|---------|-------|")
        for r in b1:
            A(f"| `{r['elf']}` | {r['method']} | {r.get('window_sec', r.get('wall_sec_mean', 0)):.1f} | "
              f"{r['steps']:,} | {r['insns_per_sec']:,.0f} | {r.get('stdev_insns', 0):,.0f} |")

        avg_h = statistics.mean(r["insns_per_sec"] for r in hammer_r) if hammer_r else 0
        avg_s = statistics.mean(r["insns_per_sec"] for r in spike_r if r["insns_per_sec"]) if spike_r else 0
        A(f"\n**Average Hammer insns/sec:** {avg_h:,.0f}  ")
        A(f"**Average Spike CLI insns/sec:** {avg_s:,.0f}  ")
        if avg_h > 0:
            A(f"**Spike/Hammer ratio:** {avg_s/avg_h:.2f}x\n")

        # ASCII throughput bar
        A("```")
        A("Throughput comparison (higher = better)")
        all_ips = [r["insns_per_sec"] for r in b1 if r["insns_per_sec"]]
        mx = max(all_ips) if all_ips else 1
        for r in b1:
            tag = f"{r['elf'][:22]:22} [{r['method'][:8]:8}]"
            A(f"  {tag} {bar(r['insns_per_sec'], mx)} {r['insns_per_sec']:>10,.0f} /s")
        A("```\n")
    else:
        A("_Benchmark 1 did not produce results._\n")

    A("---\n")

    # ── Bench 2 ────────────────────────────────────────────────────────────
    A("## 2 · Hammer Direct Import vs JSON Subprocess (IPC Overhead)\n")
    A("> Quantifies the per-step latency cost of the subprocess JSON-pipe layer.\n")
    b2 = all_data.get("bench2", [])
    if b2:
        A("| ELF | Method | Mean lat (µs) | Stdev (µs) | Steps/sec |")
        A("|-----|--------|--------------|------------|-----------|")
        for r in b2:
            A(f"| `{r['elf']}` | {r['method']} | {r['mean_latency_us']:.2f} | "
              f"{r['stdev_latency_us']:.2f} | {r['throughput_steps_sec']:,.0f} |")

        direct_r = [r for r in b2 if r["method"] == "direct"]
        cosim_r  = [r for r in b2 if r["method"] == "cosim_subprocess"]
        if direct_r and cosim_r:
            avg_direct = statistics.mean(r["mean_latency_us"] for r in direct_r)
            avg_cosim  = statistics.mean(r["mean_latency_us"] for r in cosim_r)
            overhead   = (avg_cosim - avg_direct) / avg_direct * 100 if avg_direct > 0 else 0
            A(f"\n**Avg direct step latency:** {avg_direct:.2f} µs  ")
            A(f"**Avg cosim step latency:** {avg_cosim:.2f} µs  ")
            A(f"**IPC overhead:** {overhead:+.1f}% per step  ")
            A(f"**Takeaway:** The JSON-pipe subprocess layer adds ~{avg_cosim-avg_direct:.1f} µs/step "
              f"of overhead, which trades raw speed for observation richness (full JSON state per step).\n")
    else:
        A("_Benchmark 2 did not produce results._\n")

    A("---\n")

    # ── Bench 3 ────────────────────────────────────────────────────────────
    A("## 3 · Serial vs Parallel ELF Processing\n")
    A("> ProcessPoolExecutor speedup across all ELF files.\n")
    b3 = all_data.get("bench3", [])
    if b3:
        serial = next((r for r in b3 if r["workers"] == 1), None)
        A("| Mode | Workers | Wall (s) | Total Steps | Agg insns/s | Speedup | Efficiency |")
        A("|------|---------|----------|-------------|-------------|---------|------------|")
        for r in b3:
            speedup    = serial["wall_sec"] / r["wall_sec"] if serial and r["wall_sec"] > 0 else 1
            efficiency = speedup / r["workers"] * 100
            A(f"| {r['mode']} | {r['workers']} | {r['wall_sec']:.2f} | "
              f"{r['total_steps']:,} | {r['aggregate_insns_per_sec']:,.0f} | "
              f"{speedup:.2f}x | {efficiency:.1f}% |")

        A("\n```")
        A("Aggregate throughput (insns/s) — higher is better")
        mx = max(r["aggregate_insns_per_sec"] for r in b3) or 1
        for r in b3:
            tag = f"{'serial' if r['workers']==1 else 'parallel-'+str(r['workers']):16}"
            A(f"  {tag} {bar(r['aggregate_insns_per_sec'], mx)} {r['aggregate_insns_per_sec']:>10,.0f} /s")
        A("```\n")
    else:
        A("_Benchmark 3 did not produce results._\n")

    A("---\n")

    # ── Bench 4 ────────────────────────────────────────────────────────────
    A("## 4 · ELF Load Performance — Python vs Hammer C++\n")
    A("> pyelftools-based Python loader vs Hammer C++ Spike loader.\n")
    b4 = all_data.get("bench4", [])
    if b4:
        A("| ELF | Method | Size (KB) | Mean (ms) | Stdev (ms) | MB/s |")
        A("|-----|--------|-----------|-----------|------------|------|")
        for r in b4:
            A(f"| `{r['elf']}` | {r['method']} | {r['file_size_bytes']/1024:.1f} | "
              f"{r['mean_ms']:.2f} | {r['stdev_ms']:.2f} | {r['throughput_mbs']:.1f} |")

        py_r  = [r for r in b4 if r["method"] == "python_memory_model"]
        cpp_r = [r for r in b4 if r["method"] == "hammer_cpp_loader"]
        if py_r and cpp_r:
            avg_py  = statistics.mean(r["mean_ms"] for r in py_r)
            avg_cpp = statistics.mean(r["mean_ms"] for r in cpp_r)
            speedup = avg_py / avg_cpp if avg_cpp > 0 else 0
            A(f"\n**Avg Python load:** {avg_py:.2f} ms  ")
            A(f"**Avg Hammer C++ load:** {avg_cpp:.2f} ms  ")
            A(f"**C++ speedup:** {speedup:.1f}x faster at ELF loading\n")
    else:
        A("_Benchmark 4 did not produce results._\n")

    A("---\n")
    A("## Key Takeaways\n")
    A("1. **Hammer Python API** gives fine-grained per-instruction observability "
      "that Spike CLI alone cannot provide (register writes, memory reads/writes, CSR values).\n")
    A("2. **JSON subprocess IPC** (the `HammerCoSim` layer) introduces latency per step "
      "but is architecturally necessary for integration with the cocotb simulation loop "
      "which runs in a separate process.\n")
    A("3. **Parallel processing** with `ProcessPoolExecutor` provides near-linear speedup "
      "for independent ELF workloads — a significant throughput improvement for regression suites.\n")
    A("4. **C++ ELF loading** (Hammer) is substantially faster than Python's pyelftools, "
      "but Python's `MemoryModel` is the right choice for the bus-functional model "
      "inside the cocotb testbench.\n")

    return "\n".join(lines)


# ── Runner ─────────────────────────────────────────────────────────────────
def run_benchmark(name: str, module_name: str, label: str) -> tuple:
    print(f"\n{'─'*70}")
    print(f"  Running {label}…")
    print(f"{'─'*70}")
    t0 = time.perf_counter()
    try:
        mod = load_bench(module_name)
        results = mod.main()
        elapsed = time.perf_counter() - t0
        print(f"\n  ✓ {label} completed in {elapsed:.1f}s")
        return results, elapsed, None
    except Exception as e:
        elapsed = time.perf_counter() - t0
        tb = traceback.format_exc()
        print(f"\n  ✗ {label} FAILED: {e}")
        print(tb)
        return None, elapsed, str(e)


# ── Main ───────────────────────────────────────────────────────────────────
def main():
    print(f"\n{'█'*70}")
    print(f"  coco-rvtb BENCHMARK SUITE")
    print(f"  Repo: {REPO_ROOT}")
    print(f"{'█'*70}")

    suite_start = time.perf_counter()
    all_data = {}
    errors   = {}

    benchmarks = [
        ("bench1", "01_spike_vs_hammer",    "Benchmark 1: Spike CLI vs Hammer Python API"),
        ("bench2", "02_direct_vs_subprocess","Benchmark 2: Direct Import vs CoSim Subprocess"),
        ("bench3", "03_serial_vs_parallel",  "Benchmark 3: Serial vs Parallel ELF Processing"),
        ("bench4", "04_elf_load_bench",      "Benchmark 4: ELF Load Performance"),
    ]

    for key, module, label in benchmarks:
        results, elapsed, err = run_benchmark(key, module, label)
        if results is not None:
            all_data[key] = results
        if err:
            errors[key] = err

    suite_elapsed = time.perf_counter() - suite_start

    # Write JSON
    json_path = RESULTS_DIR / "results.json"
    with open(json_path, "w") as f:
        # Make results JSON-serializable (filter out non-serializable items)
        safe_data = {}
        for k, v in all_data.items():
            try:
                json.dumps(v)
                safe_data[k] = v
            except Exception:
                safe_data[k] = str(v)
        json.dump({
            "generated": datetime.datetime.now().isoformat(),
            "total_sec": suite_elapsed,
            "errors": errors,
            "benchmarks": safe_data,
        }, f, indent=2)
    print(f"\n  JSON results → {json_path}")

    # Write markdown report
    report_md = build_report(all_data, suite_elapsed)
    md_path   = RESULTS_DIR / "report.md"
    with open(md_path, "w") as f:
        f.write(report_md)
    print(f"  Markdown report → {md_path}")

    print(f"\n{'█'*70}")
    print(f"  Suite completed in {suite_elapsed:.1f}s")
    if errors:
        print(f"  Failures: {list(errors.keys())}")
    print(f"{'█'*70}\n")


if __name__ == "__main__":
    main()
