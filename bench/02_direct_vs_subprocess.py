#!/usr/bin/env python3
"""
Benchmark 2: Hammer direct import vs Hammer via JSON subprocess (cosim IPC)
=============================================================================
Quantifies the overhead introduced by the subprocess JSON-pipe layer used in
verif/env/hammer_cosim.py (HammerCoSim).

  A) Direct   – import hammer in-process, call single_step() directly
  B) CoSim    – use HammerCoSim (JSON over stdin/stdout subprocess)

Metrics: per-step latency (µs), throughput (steps/sec), IPC overhead %.

Run:
    conda run -n gsoc python3 bench/02_direct_vs_subprocess.py
"""

import os
import sys
import time
import statistics
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────
REPO_ROOT  = Path(__file__).resolve().parent.parent
ELF_DIR    = REPO_ROOT / "verif" / "elf_files"
HAMMER_DIR = REPO_ROOT / "submodules" / "hammer" / "builddir"
VERIF_ENV  = REPO_ROOT / "verif" / "env"

# Add hammer and verif/env to path
for p in [str(HAMMER_DIR), str(VERIF_ENV)]:
    if p not in sys.path:
        sys.path.insert(0, p)

import hammer  # noqa: E402

# HammerCoSim lives in verif/env – import after path fix
from hammer_cosim import HammerCoSim  # noqa: E402

STEPS       = 500       # number of steps per trial (keep low for subprocess)
REPEATS     = 3         # repeat trials
TOHOST_ADDR = 0x80002000


# ── Direct Hammer helper ───────────────────────────────────────────────────
def make_hammer(elf_path: Path):
    mem_cfg = hammer.mem_cfg_t(hammer.DramBase, 256 * 1024 * 1024)
    return hammer.Hammer("RV32IMC", "msu", "", [0], [mem_cfg], str(elf_path), None)


def bench_direct(elf_path: Path, n_steps: int) -> dict:
    """Run n_steps via direct in-process Hammer call."""
    latencies = []

    for _ in range(REPEATS):
        sim = make_hammer(elf_path)
        for _ in range(5):           # align with cosim warm-up
            sim.single_step(0)

        step_times = []
        for _ in range(n_steps):
            t0 = time.perf_counter()
            sim.single_step(0)
            t1 = time.perf_counter()
            step_times.append(t1 - t0)

        latencies.extend(step_times)

    mean_lat = statistics.mean(latencies)
    return {
        "method": "direct",
        "elf": elf_path.name,
        "steps": n_steps * REPEATS,
        "mean_latency_us": mean_lat * 1e6,
        "stdev_latency_us": statistics.stdev(latencies) * 1e6,
        "throughput_steps_sec": 1.0 / mean_lat if mean_lat > 0 else 0,
    }


def bench_cosim(elf_path: Path, n_steps: int) -> dict:
    """Run n_steps via HammerCoSim JSON subprocess."""
    latencies = []

    for _ in range(REPEATS):
        cosim = HammerCoSim(
            str(elf_path),
            isa="RV32IMC",
            privilege_levels="msu",
            start_pc=0x80000000,
        )
        result = cosim.start_cosimulation()
        if not result["success"]:
            print(f"[ERROR] CoSim startup failed: {result}")
            return {}

        step_times = []
        for _ in range(n_steps):
            t0 = time.perf_counter()
            r  = cosim.step_instruction(0)
            t1 = time.perf_counter()
            if not r.get("success"):
                break
            step_times.append(t1 - t0)

        cosim.shutdown()
        latencies.extend(step_times)

    mean_lat = statistics.mean(latencies) if latencies else float("inf")
    return {
        "method": "cosim_subprocess",
        "elf": elf_path.name,
        "steps": len(latencies),
        "mean_latency_us": mean_lat * 1e6,
        "stdev_latency_us": statistics.stdev(latencies) * 1e6 if len(latencies) > 1 else 0.0,
        "throughput_steps_sec": 1.0 / mean_lat if mean_lat > 0 else 0,
    }


# ── Main ───────────────────────────────────────────────────────────────────
def main():
    elf_files = sorted(ELF_DIR.glob("*.o"))
    if not elf_files:
        print(f"[ERROR] No ELF files in {ELF_DIR}"); sys.exit(1)

    print(f"{'='*76}")
    print(f"  BENCHMARK 2: Hammer Direct Import vs JSON Subprocess (CoSim IPC)")
    print(f"  Steps/trial : {STEPS}   Repeats : {REPEATS}")
    print(f"{'='*76}\n")

    hdr = (f"{'ELF':<40} {'Method':<20} {'Mean lat (µs)':>14} "
           f"{'Stddev (µs)':>12} {'Steps/sec':>10}")
    print(hdr)
    print("-" * len(hdr))

    all_results = []
    ipc_overheads = []

    for elf in elf_files:
        d = bench_direct(elf, STEPS)
        c = bench_cosim(elf, STEPS)

        if not c:
            continue

        all_results += [d, c]

        overhead_pct = (
            (c["mean_latency_us"] - d["mean_latency_us"]) / d["mean_latency_us"] * 100
            if d["mean_latency_us"] > 0 else 0
        )
        ipc_overheads.append(overhead_pct)

        for r in [d, c]:
            print(
                f"{r['elf']:<40} {r['method']:<20} "
                f"{r['mean_latency_us']:>14.2f} "
                f"{r['stdev_latency_us']:>12.2f} "
                f"{r['throughput_steps_sec']:>10,.0f}"
            )
        print(f"  → IPC overhead per step: {overhead_pct:+.1f}%  "
              f"(subprocess adds ~{c['mean_latency_us']-d['mean_latency_us']:.1f} µs/step)\n")

    if ipc_overheads:
        avg_overhead = statistics.mean(ipc_overheads)
        avg_direct_kips  = statistics.mean(
            r["throughput_steps_sec"]/1000 for r in all_results if r["method"]=="direct")
        avg_cosim_kips   = statistics.mean(
            r["throughput_steps_sec"]/1000 for r in all_results if r["method"]=="cosim_subprocess")

        print(f"\n{'='*76}")
        print(f"  SUMMARY")
        print(f"  Avg direct throughput   : {avg_direct_kips:>8.1f} k-steps/sec")
        print(f"  Avg cosim throughput    : {avg_cosim_kips:>8.1f} k-steps/sec")
        print(f"  Avg IPC overhead        : {avg_overhead:>+8.1f}%")
        print(f"  Insight: JSON subprocess layer adds measurable latency per step.")
        print(f"  For bulk simulation, consider direct Hammer import (no subprocess).")
        print(f"{'='*76}")

    return all_results


if __name__ == "__main__":
    main()
