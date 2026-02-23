#!/usr/bin/env python3
"""
Benchmark 1: Spike CLI (subprocess) vs Hammer Python API (direct import)
=========================================================================
Measures instructions executed per second over a fixed time window using
two strategies:
  A) Spike CLI   – launch ~/riscv/bin/spike -l, kill after WINDOW_SEC,
                   count committed instructions from the log file
  B) Hammer API  – import hammer in-process, single_step() for WINDOW_SEC

Since the provided ELF files do not use an HTIF halt device, both methods
are measured over an identical fixed time budget for a fair comparison.

Run:
    conda run -n gsoc python3 bench/01_spike_vs_hammer.py
"""

import os
import sys
import time
import signal
import tempfile
import subprocess
import statistics
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────
REPO_ROOT  = Path(__file__).resolve().parent.parent
ELF_DIR    = REPO_ROOT / "verif" / "elf_files"
HAMMER_DIR = REPO_ROOT / "submodules" / "hammer" / "builddir"
SPIKE_BIN  = Path.home() / "riscv" / "bin" / "spike"

WINDOW_SEC  = 3.0       # fixed measurement window (seconds)
REPEATS     = 3         # repeat each measurement for stable mean

# ── Hammer import ──────────────────────────────────────────────────────────
if str(HAMMER_DIR) not in sys.path:
    sys.path.insert(0, str(HAMMER_DIR))
import hammer  # noqa: E402


# ── Helpers ────────────────────────────────────────────────────────────────
def make_hammer(elf_path: Path):
    mem_cfg = hammer.mem_cfg_t(hammer.DramBase, 256 * 1024 * 1024)
    return hammer.Hammer("RV32IMC", "msu", "", [0], [mem_cfg], str(elf_path), None)


def count_spike_log_insns(log_path: str) -> int:
    """Count committed instruction lines in a Spike commit log."""
    count = 0
    try:
        with open(log_path, "r", errors="replace") as f:
            for line in f:
                # Spike commit log lines start with 'core'
                # e.g.: core   0: 0x80000080 (0x...) ...
                if line.startswith("core"):
                    count += 1
    except FileNotFoundError:
        pass
    return count


def bench_spike(elf_path: Path) -> dict:
    """
    Run Spike with commit logging for WINDOW_SEC seconds, then SIGTERM it.
    Count committed instructions from the log file.
    """
    insn_counts = []
    actual_times = []

    for _ in range(REPEATS):
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
            log_path = tf.name

        cmd = [
            str(SPIKE_BIN),
            "--isa=rv32imc",
            "--priv=msu",
            f"--pc=0x80000000",
            f"-m0x80000000:0x10000000",
            "-l",
            f"--log={log_path}",
            str(elf_path),
        ]

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        t0 = time.perf_counter()
        time.sleep(WINDOW_SEC)
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        elapsed = time.perf_counter() - t0

        n_insns = count_spike_log_insns(log_path)
        try:
            os.unlink(log_path)
        except OSError:
            pass

        insn_counts.append(n_insns)
        actual_times.append(elapsed)

    mean_insns = statistics.mean(insn_counts)
    mean_time  = statistics.mean(actual_times)
    return {
        "method": "spike_cli",
        "elf": elf_path.name,
        "window_sec": WINDOW_SEC,
        "steps": int(mean_insns),
        "wall_sec_mean": mean_time,
        "insns_per_sec": mean_insns / mean_time if mean_time > 0 else 0,
        "stdev_insns": statistics.stdev(insn_counts) if len(insn_counts) > 1 else 0,
    }


def bench_hammer(elf_path: Path) -> dict:
    """Step Hammer for WINDOW_SEC seconds, count steps."""
    step_counts  = []
    actual_times = []

    for _ in range(REPEATS):
        sim = make_hammer(elf_path)
        for _ in range(5):   # warm-up (mirrors hammer_subprocess.py)
            sim.single_step(0)

        t0       = time.perf_counter()
        steps    = 0
        deadline = t0 + WINDOW_SEC
        while time.perf_counter() < deadline:
            sim.single_step(0)
            steps += 1
        elapsed = time.perf_counter() - t0

        step_counts.append(steps)
        actual_times.append(elapsed)

    mean_steps = statistics.mean(step_counts)
    mean_time  = statistics.mean(actual_times)
    return {
        "method": "hammer_python",
        "elf": elf_path.name,
        "window_sec": WINDOW_SEC,
        "steps": int(mean_steps),
        "wall_sec_mean": mean_time,
        "insns_per_sec": mean_steps / mean_time if mean_time > 0 else 0,
        "stdev_insns": statistics.stdev(step_counts) if len(step_counts) > 1 else 0,
    }


# ── Main ───────────────────────────────────────────────────────────────────
def main():
    elf_files = sorted(ELF_DIR.glob("*.o"))
    if not elf_files:
        print(f"[ERROR] No ELF files found in {ELF_DIR}")
        sys.exit(1)

    print(f"{'='*72}")
    print(f"  BENCHMARK 1: Spike CLI vs Hammer Python API")
    print(f"  Method   : fixed {WINDOW_SEC}s time window (ELFs have no HTIF halt device)")
    print(f"  ELF dir  : {ELF_DIR}")
    print(f"  Spike    : {SPIKE_BIN}")
    print(f"  Hammer   : {HAMMER_DIR}")
    print(f"  Repeats  : {REPEATS}")
    print(f"{'='*72}\n")

    hdr = f"{'ELF':<42} {'Method':<14} {'Insns':>10} {'Insns/s':>12} {'Stdev':>10}"
    print(hdr)
    print("-" * len(hdr))

    all_results = []
    speedups    = []

    for elf in elf_files:
        h = bench_hammer(elf)
        s = bench_spike(elf)
        all_results += [h, s]

        for r in [h, s]:
            print(
                f"{r['elf']:<42} {r['method']:<14} "
                f"{r['steps']:>10,} {r['insns_per_sec']:>12,.0f} "
                f"{r['stdev_insns']:>10,.0f}"
            )

        ratio = s["insns_per_sec"] / h["insns_per_sec"] if h["insns_per_sec"] > 0 else 0
        speedups.append(ratio)
        faster = "Spike" if ratio > 1 else "Hammer"
        print(f"  → Spike/Hammer ratio: {ratio:.2f}x  [{faster} executes more insns/s]\n")

    # Summary
    hammer_ips = statistics.mean(r["insns_per_sec"] for r in all_results if r["method"] == "hammer_python")
    spike_ips  = statistics.mean(r["insns_per_sec"] for r in all_results if r["method"] == "spike_cli")
    avg_ratio  = statistics.mean(speedups)

    print(f"\n{'='*72}")
    print(f"  SUMMARY  (measurement window = {WINDOW_SEC}s per ELF per repeat)")
    print(f"  Avg Hammer insns/sec  : {hammer_ips:>12,.0f}")
    print(f"  Avg Spike  insns/sec  : {spike_ips:>12,.0f}")
    print(f"  Avg Spike/Hammer ratio: {avg_ratio:>12.2f}x")
    print()
    print(f"  ★ Hammer trades some raw throughput for rich per-step observability:")
    print(f"    register writes, memory read/write logs, CSR values — unavailable")
    print(f"    from plain Spike CLI. The cocotb testbench uses this to verify")
    print(f"    every committed instruction against the RTL DUT in real time.")
    print(f"{'='*72}")

    return all_results


if __name__ == "__main__":
    main()
