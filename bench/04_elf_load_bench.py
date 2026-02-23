#!/usr/bin/env python3
"""
Benchmark 4: ELF Loading Performance
======================================
Compares two ELF loading strategies:
  A) Python MemoryModel  – pure-Python pyelftools-based loader (verif/utils/memory_model.py)
  B) Hammer constructor  – C++ Spike ELF loader invoked via pybind11

Metrics: load time (ms), throughput (MB/s), speedup.

Run:
    conda run -n gsoc python3 bench/04_elf_load_bench.py
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
UTILS_DIR  = REPO_ROOT / "verif" / "utils"

for p in [str(HAMMER_DIR), str(UTILS_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)

import hammer  # noqa: E402
from memory_model import MemoryModel  # noqa: E402

REPEATS = 10  # repeat for statistical stability


# ── Helpers ────────────────────────────────────────────────────────────────
def bench_python_model(elf_path: Path) -> dict:
    """Benchmark pure-Python MemoryModel.load_elf()."""
    file_size = elf_path.stat().st_size
    times = []
    for _ in range(REPEATS):
        mm = MemoryModel()       # fresh instance each time
        t0 = time.perf_counter()
        mm.load_elf(str(elf_path))
        t1 = time.perf_counter()
        times.append(t1 - t0)

    mean_t   = statistics.mean(times)
    stdev_t  = statistics.stdev(times)
    segments = _count_segments(elf_path)
    loaded_bytes = sum(len(v) for v in [mm.memory])   # heuristic via dict size
    throughput_mbs = (file_size / 1e6) / mean_t if mean_t > 0 else 0

    return {
        "method": "python_memory_model",
        "elf": elf_path.name,
        "file_size_bytes": file_size,
        "mean_ms": mean_t * 1000,
        "stdev_ms": stdev_t * 1000,
        "throughput_mbs": throughput_mbs,
        "segments": segments,
    }


def bench_hammer_load(elf_path: Path) -> dict:
    """Benchmark Hammer constructor (C++ Spike ELF loader)."""
    file_size = elf_path.stat().st_size
    times = []
    for _ in range(REPEATS):
        mem_cfg = hammer.mem_cfg_t(hammer.DramBase, 256 * 1024 * 1024)
        t0 = time.perf_counter()
        sim = hammer.Hammer("RV32IMC", "msu", "", [0], [mem_cfg], str(elf_path), None)
        t1 = time.perf_counter()
        del sim
        times.append(t1 - t0)

    mean_t  = statistics.mean(times)
    stdev_t = statistics.stdev(times)
    throughput_mbs = (file_size / 1e6) / mean_t if mean_t > 0 else 0

    return {
        "method": "hammer_cpp_loader",
        "elf": elf_path.name,
        "file_size_bytes": file_size,
        "mean_ms": mean_t * 1000,
        "stdev_ms": stdev_t * 1000,
        "throughput_mbs": throughput_mbs,
        "segments": _count_segments(elf_path),
    }


def _count_segments(elf_path: Path) -> int:
    """Count PT_LOAD segments in an ELF file."""
    try:
        from elftools.elf.elffile import ELFFile
        with open(elf_path, "rb") as f:
            elf = ELFFile(f)
            return sum(1 for seg in elf.iter_segments() if seg.header.p_type == "PT_LOAD")
    except Exception:
        return -1


# ── ASCII mini-bar ─────────────────────────────────────────────────────────
def sparkbar(val, max_val, width=30):
    n = int(val / max_val * width) if max_val > 0 else 0
    return "▓" * n + "░" * (width - n)


# ── Main ───────────────────────────────────────────────────────────────────
def main():
    elf_files = sorted(ELF_DIR.glob("*.o"))
    if not elf_files:
        print(f"[ERROR] No ELF files in {ELF_DIR}"); sys.exit(1)

    print(f"{'='*74}")
    print(f"  BENCHMARK 4: ELF Load Performance — Python MemoryModel vs Hammer C++")
    print(f"  Repeats : {REPEATS}   ELF dir : {ELF_DIR}")
    print(f"{'='*74}\n")

    hdr = (f"{'ELF':<40} {'Method':<22} {'Mean (ms)':>10} "
           f"{'Stdev (ms)':>11} {'MB/s':>7} {'Segs':>5}")
    print(hdr)
    print("-" * len(hdr))

    all_results = []
    speedups = []

    for elf in elf_files:
        py_r  = bench_python_model(elf)
        cpp_r = bench_hammer_load(elf)
        all_results += [py_r, cpp_r]

        for r in [py_r, cpp_r]:
            print(
                f"{r['elf']:<40} {r['method']:<22} "
                f"{r['mean_ms']:>10.2f} {r['stdev_ms']:>11.2f} "
                f"{r['throughput_mbs']:>7.1f} {r['segments']:>5}"
            )

        speedup = py_r["mean_ms"] / cpp_r["mean_ms"] if cpp_r["mean_ms"] > 0 else 0
        speedups.append(speedup)
        winner = "Hammer C++" if speedup > 1 else "Python"
        print(f"  → Hammer C++ is {speedup:.1f}x {'faster' if speedup>1 else 'slower'} than Python at loading "
              f"({elf.stat().st_size/1024:.1f} KB ELF)\n")

    # Throughput bar chart
    print(f"\n  MB/s comparison (Python MemoryModel vs Hammer C++ loader)")
    print(f"  {'─'*65}")
    all_mbs  = [r["throughput_mbs"] for r in all_results]
    max_mbs  = max(all_mbs) if all_mbs else 1
    for r in all_results:
        bar = sparkbar(r["throughput_mbs"], max_mbs)
        print(f"  {r['elf'][:28]:28} {r['method'][:10]:10} {bar} {r['throughput_mbs']:6.1f} MB/s")

    # Summary
    py_results  = [r for r in all_results if r["method"] == "python_memory_model"]
    cpp_results = [r for r in all_results if r["method"] == "hammer_cpp_loader"]
    avg_speedup = statistics.mean(speedups)

    print(f"\n{'='*74}")
    print(f"  SUMMARY")
    print(f"  Avg Python load time  : {statistics.mean(r['mean_ms'] for r in py_results):>8.2f} ms")
    print(f"  Avg Hammer load time  : {statistics.mean(r['mean_ms'] for r in cpp_results):>8.2f} ms")
    print(f"  Avg C++ speedup       : {avg_speedup:>8.1f}x")
    print(f"  Avg Python throughput : {statistics.mean(r['throughput_mbs'] for r in py_results):>8.1f} MB/s")
    print(f"  Avg Hammer throughput : {statistics.mean(r['throughput_mbs'] for r in cpp_results):>8.1f} MB/s")
    print(f"{'='*74}")

    return all_results


if __name__ == "__main__":
    main()
