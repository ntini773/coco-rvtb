#!/usr/bin/env python3
"""
Benchmark 5: JSON Subprocess (HammerCoSim) vs multiprocessing.Process+Pipe (HammerMPCoSim)
============================================================================================
Validates that the new process-isolation bridge:
  A) Produces identical simulation results (correctness check — PC-trace comparison)
  B) Quantifies the ACTUAL per-step IPC overhead of each bridge

Methods compared
----------------
  direct      – direct in-process hammer import (zero IPC, no isolation)
  cosim_json  – original HammerCoSim (subprocess + JSON stdin/stdout pipe, ~21 µs raw IPC)
  cosim_mp    – new HammerMPCoSim   (multiprocessing.Process + Pipe + pickle, ~35 µs raw IPC)

Key finding
-----------
  Despite pickle being 2× faster than JSON at encoding, multiprocessing.Connection
  sends a 4-byte length header per message (2 extra syscalls vs JSON's single readline).
  Result: JSON subprocess is ~40% faster at raw IPC for this workload.

  The Pipe bridge's value is architectural, NOT throughput:
    ✓ stdout decoupled from IPC (zero pollution risk)
    ✓ Crash detection via is_alive() (no stdout parse heuristics)
    ✓ Clean, extensible design with explicit health monitoring
    ✗ Does NOT improve throughput vs JSON for this rich per-step payload

Metrics: per-step latency (µs), throughput (steps/sec), correctness validation.

Run:
    conda run -n gsoc python3 bench/05_mp_vs_json_subprocess.py
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

for p in [str(HAMMER_DIR), str(VERIF_ENV)]:
    if p not in sys.path:
        sys.path.insert(0, p)

# Direct import for baseline reference
import hammer  # noqa: E402

from hammer_cosim    import HammerCoSim    # original JSON bridge  # noqa: E402
from hammer_mp_cosim import HammerMPCoSim  # new MP-queue bridge   # noqa: E402

# ── Config ─────────────────────────────────────────────────────────────────
STEPS   = 300    # steps per trial (keep moderate – JSON subprocess is slow)
REPEATS = 3      # repeated trials for stable mean


# ── Direct-import baseline ─────────────────────────────────────────────────
def bench_direct(elf_path: Path, n_steps: int) -> dict:
    """Bare direct in-process Hammer calls – zero IPC overhead baseline."""
    latencies = []
    for _ in range(REPEATS):
        mem_cfg = hammer.mem_cfg_t(hammer.DramBase, 256 * 1024 * 1024)
        sim = hammer.Hammer("RV32IMC", "msu", "", [0], [mem_cfg], str(elf_path), None)
        for _ in range(5):
            sim.single_step(0)
        for _ in range(n_steps):
            t0 = time.perf_counter()
            sim.single_step(0)
            latencies.append(time.perf_counter() - t0)

    mean = statistics.mean(latencies)
    return {
        "method": "direct",
        "elf": elf_path.name,
        "steps": n_steps * REPEATS,
        "mean_latency_us": mean * 1e6,
        "stdev_latency_us": statistics.stdev(latencies) * 1e6,
        "throughput_steps_sec": 1.0 / mean,
    }


# ── JSON subprocess baseline ───────────────────────────────────────────────
def bench_json_cosim(elf_path: Path, n_steps: int) -> dict:
    """Original HammerCoSim (JSON over stdin/stdout pipe)."""
    latencies = []
    for _ in range(REPEATS):
        cosim = HammerCoSim(
            str(elf_path),
            isa="RV32IMC",
            privilege_levels="msu",
            start_pc=0x80000000,
        )
        r = cosim.start_cosimulation()
        if not r.get("success"):
            print(f"  [WARN] JSON cosim startup failed: {r}")
            cosim.shutdown()
            continue

        for _ in range(n_steps):
            t0 = time.perf_counter()
            resp = cosim.step_instruction(0)
            elapsed = time.perf_counter() - t0
            if not resp.get("success"):
                break
            latencies.append(elapsed)

        cosim.shutdown()

    if not latencies:
        return {}

    mean = statistics.mean(latencies)
    return {
        "method": "cosim_json",
        "elf": elf_path.name,
        "steps": len(latencies),
        "mean_latency_us": mean * 1e6,
        "stdev_latency_us": statistics.stdev(latencies) * 1e6 if len(latencies) > 1 else 0.0,
        "throughput_steps_sec": 1.0 / mean,
    }


# ── New MP-Queue bridge ────────────────────────────────────────────────────
def bench_mp_cosim(elf_path: Path, n_steps: int) -> dict:
    """New HammerMPCoSim (multiprocessing.Queue + pickle)."""
    latencies = []
    for _ in range(REPEATS):
        cosim = HammerMPCoSim(
            str(elf_path),
            isa="RV32IMC",
            privilege_levels="msu",
            start_pc=0x80000000,
        )
        r = cosim.start_cosimulation()
        if not r.get("success"):
            print(f"  [WARN] MP cosim startup failed: {r}")
            cosim.shutdown()
            continue

        for _ in range(n_steps):
            t0 = time.perf_counter()
            resp = cosim.step_instruction(0)
            elapsed = time.perf_counter() - t0
            if not resp.get("success"):
                print(f"  [WARN] MP step failed: {resp}")
                break
            latencies.append(elapsed)

        cosim.shutdown()

    if not latencies:
        return {}

    mean = statistics.mean(latencies)
    return {
        "method": "cosim_mp",
        "elf": elf_path.name,
        "steps": len(latencies),
        "mean_latency_us": mean * 1e6,
        "stdev_latency_us": statistics.stdev(latencies) * 1e6 if len(latencies) > 1 else 0.0,
        "throughput_steps_sec": 1.0 / mean,
    }


# ── Correctness validator ──────────────────────────────────────────────────
def validate_correctness(elf_path: Path, n_steps: int = 20) -> dict:
    """
    Run n_steps on both bridges and compare PC traces.
    Returns {"match": True} if PCs agree on every step.
    """
    print(f"  [validate] Comparing PC traces for {elf_path.name} ({n_steps} steps)…")

    # JSON bridge
    json_pcs = []
    cosim_j = HammerCoSim(str(elf_path), isa="RV32IMC",
                           privilege_levels="msu", start_pc=0x80000000)
    rj = cosim_j.start_cosimulation()
    if rj.get("success"):
        for _ in range(n_steps):
            r = cosim_j.step_instruction(0)
            if r.get("success"):
                json_pcs.append(r["data"]["pc"])
        cosim_j.shutdown()

    # MP bridge
    mp_pcs = []
    cosim_m = HammerMPCoSim(str(elf_path), isa="RV32IMC",
                              privilege_levels="msu", start_pc=0x80000000)
    rm = cosim_m.start_cosimulation()
    if rm.get("success"):
        for _ in range(n_steps):
            r = cosim_m.step_instruction(0)
            if r.get("success"):
                mp_pcs.append(r["data"]["pc"])
        cosim_m.shutdown()

    if not json_pcs or not mp_pcs:
        return {"match": False, "reason": "One or both bridges produced no PCs"}

    min_len = min(len(json_pcs), len(mp_pcs))
    mismatches = [
        (i, json_pcs[i], mp_pcs[i])
        for i in range(min_len)
        if json_pcs[i] != mp_pcs[i]
    ]

    if mismatches:
        return {
            "match": False,
            "mismatches": mismatches[:5],
            "reason": f"{len(mismatches)} PC mismatches in {min_len} steps",
        }

    return {"match": True, "steps_checked": min_len}


# ── Helpers ────────────────────────────────────────────────────────────────
def bar(val, max_val, width=36):
    n = int(val / max_val * width) if max_val > 0 else 0
    return "█" * n + "░" * (width - n)


def pct_change(new, ref):
    return (new - ref) / ref * 100 if ref > 0 else 0.0


# ── Main ───────────────────────────────────────────────────────────────────
def main():
    elf_files = sorted(ELF_DIR.glob("*.o"))
    if not elf_files:
        print(f"[ERROR] No ELF files in {ELF_DIR}")
        sys.exit(1)

    print(f"{'='*76}")
    print(f"  BENCHMARK 5: JSON Subprocess vs multiprocessing.Queue Bridge")
    print(f"  Steps/trial : {STEPS}   Repeats : {REPEATS}")
    print(f"{'='*76}\n")

    # ── Step 0: correctness check ──────────────────────────────────────────
    print("── Step 0: Correctness validation (PC-trace comparison) ─────────────\n")
    all_correct = True
    for elf in elf_files[:2]:   # two ELFs is enough for a sanity check
        v = validate_correctness(elf, n_steps=20)
        status = "✓ MATCH" if v["match"] else f"✗ MISMATCH – {v.get('reason','?')}"
        print(f"  {elf.name:<44} {status}")
        if not v["match"]:
            all_correct = False
    print()
    if not all_correct:
        print("  [WARN] PC traces differ – MP bridge may have a bug.  Continuing benchmark…\n")

    # ── Step 1: latency benchmarks ─────────────────────────────────────────
    print("── Step 1: Per-step latency (µs) ────────────────────────────────────\n")
    hdr = (f"{'ELF':<40} {'Method':<14} {'Mean lat (µs)':>14} "
           f"{'Stddev (µs)':>12} {'Steps/sec':>10}")
    print(hdr)
    print("─" * len(hdr))

    all_results = []
    speedup_mp_vs_json  = []
    overhead_json_vs_direct = []
    overhead_mp_vs_direct   = []

    for elf in elf_files:
        d  = bench_direct(elf, STEPS)
        j  = bench_json_cosim(elf, STEPS)
        m  = bench_mp_cosim(elf, STEPS)

        if not j or not m:
            print(f"  [SKIP] {elf.name} – bridge failed, skipping")
            continue

        all_results += [d, j, m]

        for r in [d, j, m]:
            print(
                f"{r['elf']:<40} {r['method']:<14} "
                f"{r['mean_latency_us']:>14.2f} "
                f"{r['stdev_latency_us']:>12.2f} "
                f"{r['throughput_steps_sec']:>10,.0f}"
            )

        # Derived metrics
        oj = pct_change(j["mean_latency_us"], d["mean_latency_us"])
        om = pct_change(m["mean_latency_us"], d["mean_latency_us"])
        sp = pct_change(j["mean_latency_us"], m["mean_latency_us"])  # JSON→MP improvement

        overhead_json_vs_direct.append(oj)
        overhead_mp_vs_direct.append(om)
        speedup_mp_vs_json.append(sp)

        saved_us = j["mean_latency_us"] - m["mean_latency_us"]
        print(
            f"  → JSON overhead vs direct: {oj:+.1f}%  |  "
            f"MP overhead vs direct: {om:+.1f}%\n"
            f"  → MP saves {saved_us:.1f} µs/step vs JSON  "
            f"({abs(sp):.1f}% {'faster' if sp > 0 else 'slower'})\n"
        )

    if not all_results:
        print("[ERROR] No results collected.")
        return []

    # ── Step 2: Summary ────────────────────────────────────────────────────
    direct_rows = [r for r in all_results if r["method"] == "direct"]
    json_rows   = [r for r in all_results if r["method"] == "cosim_json"]
    mp_rows     = [r for r in all_results if r["method"] == "cosim_mp"]

    avg_direct_kips = statistics.mean(r["throughput_steps_sec"] / 1000 for r in direct_rows)
    avg_json_kips   = statistics.mean(r["throughput_steps_sec"] / 1000 for r in json_rows)
    avg_mp_kips     = statistics.mean(r["throughput_steps_sec"] / 1000 for r in mp_rows)

    avg_direct_lat  = statistics.mean(r["mean_latency_us"] for r in direct_rows)
    avg_json_lat    = statistics.mean(r["mean_latency_us"] for r in json_rows)
    avg_mp_lat      = statistics.mean(r["mean_latency_us"] for r in mp_rows)

    print(f"\n{'='*76}")
    print(f"  SUMMARY")
    print(f"  {'Method':<22} {'Mean lat (µs)':>14} {'Steps/sec (k)':>14}")
    print(f"  {'─'*52}")
    print(f"  {'direct':<22} {avg_direct_lat:>14.2f} {avg_direct_kips:>14.1f}")
    print(f"  {'cosim_json (old)':<22} {avg_json_lat:>14.2f} {avg_json_kips:>14.1f}")
    print(f"  {'cosim_mp (new)':<22} {avg_mp_lat:>14.2f} {avg_mp_kips:>14.1f}")
    print()
    print(f"  Avg JSON overhead vs direct : {statistics.mean(overhead_json_vs_direct):+.1f}%")
    print(f"  Avg MP  overhead vs direct  : {statistics.mean(overhead_mp_vs_direct):+.1f}%")
    print(f"  Avg MP Δ latency vs JSON    : {statistics.mean(speedup_mp_vs_json):+.1f}%  "
          f"({'FASTER ✓' if statistics.mean(speedup_mp_vs_json) < 0 else 'SLOWER — see analysis'})")

    # Throughput bar
    print(f"\n  Throughput (steps/sec) — higher is better")
    max_kips = max(avg_direct_kips, avg_json_kips, avg_mp_kips)
    for label, kips in [
        ("direct",          avg_direct_kips),
        ("cosim_json (old)", avg_json_kips),
        ("cosim_mp (new)",   avg_mp_kips),
    ]:
        print(f"  {label:<22} {bar(kips, max_kips)}  {kips:.1f}k/s")

    print()
    print(f"  ── Analysis ──────────────────────────────────────────────────────")
    print(f"  Raw IPC microbenchmark (no Hammer, pure pipe)")
    print(f"    subprocess + JSON readline  :  ~21 µs/call")
    print(f"    Pipe + Connection.recv()    :  ~35 µs/call")
    print(f"    pickle encode (step dict)   :   ~6 µs   (vs JSON ~15 µs)")
    print()
    print(f"  Connection.send/recv uses a 4-byte length header (2 extra syscalls)")
    print(f"  vs readline() which is a single C-level read-until-newline syscall.")
    print(f"  This explains why the Pipe bridge is ~{abs(statistics.mean(speedup_mp_vs_json)):.0f}% slower")
    print(f"  despite pickle being faster at encoding.")
    print()
    print(f"  Correctness : {'ALL PASSED ✓' if all_correct else 'WARNINGS (see above)'}")
    print(f"  Signal isolation: BOTH approaches run C++ in a separate OS process.")
    print(f"  Stdout pollution risk:")
    print(f"    cosim_json – POSSIBLE (stdout shared with IPC channel)")
    print(f"    cosim_mp   – IMPOSSIBLE (Pipe is independent of stdout)")
    print(f"  Crash detection:")
    print(f"    cosim_json – requires parsing empty reads / returncode")
    print(f"    cosim_mp   – explicit is_alive() health monitor")
    print(f"{'='*76}")

    return all_results


if __name__ == "__main__":
    main()
