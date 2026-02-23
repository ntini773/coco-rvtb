#!/usr/bin/env python3
"""
Benchmark 3: Serial vs Parallel ELF Processing
===============================================
Demonstrates Python parallelism improvement for testbench workflows by
processing all 7 ELF files in serial vs parallel using ProcessPoolExecutor.

Each "task" = step N instructions on one ELF with Hammer Python API.
Workers are independent (each gets its own Hammer instance) — safe to parallelise.

Metrics: wall-clock time, aggregate throughput, speedup vs serial, efficiency %.

Run:
    conda run -n gsoc python3 bench/03_serial_vs_parallel.py
"""

import os
import sys
import time
import statistics
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import List

# ── Paths ──────────────────────────────────────────────────────────────────
REPO_ROOT  = Path(__file__).resolve().parent.parent
ELF_DIR    = REPO_ROOT / "verif" / "elf_files"
HAMMER_DIR = REPO_ROOT / "submodules" / "hammer" / "builddir"

STEPS_PER_ELF = 2_000    # instructions to step per ELF
TOHOST_ADDR   = 0x80002000
CPU_COUNT     = os.cpu_count() or 4


# ── Worker function (must be top-level for pickling) ──────────────────────
def process_elf(args):
    """
    Worker: import hammer, step an ELF for up to `n_steps`, return stats.
    This runs in a separate process, so hammer import is safe.
    """
    elf_path_str, n_steps, hammer_dir_str = args

    import sys, time
    from pathlib import Path

    if hammer_dir_str not in sys.path:
        sys.path.insert(0, hammer_dir_str)
    import hammer  # noqa

    elf_path = Path(elf_path_str)
    mem_cfg  = hammer.mem_cfg_t(hammer.DramBase, 256 * 1024 * 1024)
    sim      = hammer.Hammer("RV32IMC", "msu", "", [0], [mem_cfg], str(elf_path), None)

    for _ in range(5):        # warm-up / align with subprocess behaviour
        sim.single_step(0)

    t0 = time.perf_counter()
    steps = 0

    while steps < n_steps:
        sim.single_step(0)
        steps += 1
        # Check tohost
        raw = sim.get_memory_at_VA(0, TOHOST_ADDR, 4, 1)
        if raw is not None:
            val = sum(b << (i * 8) for i, b in enumerate(raw))
            if val == 1:
                break

    elapsed = time.perf_counter() - t0
    return {
        "elf": elf_path.name,
        "steps": steps,
        "elapsed_sec": elapsed,
        "insns_per_sec": steps / elapsed if elapsed > 0 else 0,
    }


# ── Serial runner ──────────────────────────────────────────────────────────
def run_serial(elf_files: List[Path], n_steps: int) -> dict:
    args_list = [(str(f), n_steps, str(HAMMER_DIR)) for f in elf_files]
    t0 = time.perf_counter()
    results = [process_elf(a) for a in args_list]
    wall = time.perf_counter() - t0

    total_steps = sum(r["steps"] for r in results)
    return {
        "mode": "serial",
        "workers": 1,
        "wall_sec": wall,
        "total_steps": total_steps,
        "aggregate_insns_per_sec": total_steps / wall if wall > 0 else 0,
        "per_elf": results,
    }


# ── Parallel runner ────────────────────────────────────────────────────────
def run_parallel(elf_files: List[Path], n_steps: int, max_workers: int) -> dict:
    args_list = [(str(f), n_steps, str(HAMMER_DIR)) for f in elf_files]
    t0 = time.perf_counter()
    results = []
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_elf, a): a[0] for a in args_list}
        for fut in as_completed(futures):
            results.append(fut.result())
    wall = time.perf_counter() - t0

    total_steps = sum(r["steps"] for r in results)
    return {
        "mode": "parallel",
        "workers": max_workers,
        "wall_sec": wall,
        "total_steps": total_steps,
        "aggregate_insns_per_sec": total_steps / wall if wall > 0 else 0,
        "per_elf": results,
    }


# ── ASCII bar chart ────────────────────────────────────────────────────────
def bar_chart(label_vals: list, width: int = 40):
    """Print a simple ASCII bar chart."""
    max_val = max(v for _, v in label_vals) or 1
    for label, val in label_vals:
        bar_len = int(val / max_val * width)
        bar = "█" * bar_len
        print(f"  {label:<20} {bar:<{width}} {val:>10,.0f} insns/s")


# ── Main ───────────────────────────────────────────────────────────────────
def main():
    elf_files = sorted(ELF_DIR.glob("*.o"))
    if not elf_files:
        print(f"[ERROR] No ELF files found in {ELF_DIR}"); sys.exit(1)

    worker_counts = sorted(set([1, 2, min(4, CPU_COUNT), CPU_COUNT]))

    print(f"{'='*70}")
    print(f"  BENCHMARK 3: Serial vs Parallel ELF Processing")
    print(f"  ELFs       : {len(elf_files)}   Steps/ELF : {STEPS_PER_ELF:,}")
    print(f"  CPU cores  : {CPU_COUNT}   Worker configs: {worker_counts}")
    print(f"{'='*70}\n")

    # Run serial baseline
    print("Running serial baseline…")
    serial = run_serial(elf_files, STEPS_PER_ELF)
    serial_time = serial["wall_sec"]

    all_runs = [serial]

    # Run parallel with various worker counts
    for w in worker_counts:
        if w == 1:
            continue   # covered by serial
        print(f"Running parallel (workers={w})…")
        p = run_parallel(elf_files, STEPS_PER_ELF, max_workers=w)
        all_runs.append(p)

    # Print results table
    print(f"\n{'Mode':<22} {'Workers':>7} {'Wall (s)':>9} "
          f"{'Total steps':>12} {'Agg insns/s':>13} {'Speedup':>8} {'Efficiency':>11}")
    print("-" * 80)

    chart_data = []
    for r in all_runs:
        speedup    = serial_time / r["wall_sec"] if r["wall_sec"] > 0 else 0
        efficiency = speedup / r["workers"] * 100
        tag        = f"{'serial' if r['workers']==1 else 'parallel-'+str(r['workers'])}"
        print(
            f"  {tag:<20} {r['workers']:>7} {r['wall_sec']:>9.2f} "
            f"{r['total_steps']:>12,} {r['aggregate_insns_per_sec']:>13,.0f} "
            f"{speedup:>8.2f}x {efficiency:>10.1f}%"
        )
        chart_data.append((tag, r["aggregate_insns_per_sec"]))

    print(f"\n  ASCII Bar Chart — Aggregate throughput (insns/s)")
    print(f"  {'─'*65}")
    bar_chart(chart_data)

    # Optional per-ELF breakdown of the fastest run
    best = max(all_runs, key=lambda r: r["aggregate_insns_per_sec"])
    print(f"\n  Per-ELF breakdown for best config ({best['mode']}, workers={best['workers']}):")
    for r in sorted(best["per_elf"], key=lambda x: x["elf"]):
        print(f"    {r['elf']:<42} {r['steps']:>6,} steps  {r['insns_per_sec']:>10,.0f} insns/s")

    print(f"\n{'='*70}")
    return all_runs


if __name__ == "__main__":
    main()
