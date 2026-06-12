"""
hammer_mp_worker.py  –  Isolated pybind11 worker process
=========================================================
This module is the *child* side of the multiprocessing IPC bridge.

IPC mechanism: ``multiprocessing.Connection`` (raw OS pipe pair via Pipe())
---------------------------------------------------------------------------
We intentionally use ``Pipe()`` rather than ``Queue()`` because:
  • Queue internally spawns a feeder-thread + uses a semaphore-wrapped socket,
    adding ~150–200 µs latency per message on Linux.
  • Pipe() is a thin wrapper around a kernel pipe (os.pipe2), costing only a
    single write(2)/read(2) syscall per message — typically 20–50 µs round-trip.
  • pickle is used for serialisation (same as Queue), so Python dicts cross the
    pipe without JSON encoding.

Signal & isolation guarantees (unchanged from Queue version)
------------------------------------------------------------
* ``hammer`` C++ extension is imported ONLY inside ``run()`` — the parent's
  address space never touches the pybind11 shared library.
* Fatal C++ signals (SIGSEGV, SIGABRT …) are fully contained in the child.
* stdout/stderr inside the child go to the terminal, never to the IPC channel.
* The worker loop is simple blocking — no async, no cocotb scheduler — so
  Spike's HTIF condvar is never contended by a competing event loop.

Wire layout
-----------
  parent_conn ←──────── child_conn   (cmd: parent sends, child recvs)
  child_conn  ─────────→ parent_conn (resp: child sends, parent recvs)

  A single ``Pipe(duplex=True)`` gives bidirectional communication over two
  underlying OS pipes, exposed as ``Connection.send()`` / ``Connection.recv()``.
"""

import os
import sys
import signal
import multiprocessing
from multiprocessing.connection import Connection
from pathlib import Path


# ---------------------------------------------------------------------------
# Sentinel strings – kept in sync with hammer_mp_cosim.py
# ---------------------------------------------------------------------------
_READY_SENTINEL  = "__HAMMER_READY__"
_INIT_SENTINEL   = "__HAMMER_INITIALIZED__"
_TIMEOUT_DEFAULT = 30   # seconds to wait for init from parent


# ---------------------------------------------------------------------------
# Worker process class
# ---------------------------------------------------------------------------
class HammerWorker(multiprocessing.Process):
    """
    Isolated worker process for the Hammer pybind11 C++ ISS.

    Parameters
    ----------
    child_conn : Connection  – duplex pipe end owned by this child process
    elf_path : str
    isa : str                           – e.g. "RV32IMC"
    privilege_levels : str              – e.g. "msu"
    start_pc : int | None
    memory_watch_addresses : list[int]
    hammer_dir : str                    – directory containing hammer*.so
    """

    def __init__(
        self,
        child_conn: Connection,
        elf_path: str,
        isa: str = "RV32IMC",
        privilege_levels: str = "msu",
        start_pc=None,
        memory_watch_addresses=None,
        hammer_dir: str = "",
    ):
        super().__init__(daemon=True)
        self._conn       = child_conn
        self._elf_path   = elf_path
        self._isa        = isa
        self._priv       = privilege_levels
        self._start_pc   = start_pc
        self._watch      = list(memory_watch_addresses or [])
        self._hammer_dir = hammer_dir

    # ------------------------------------------------------------------
    # Internal helpers (run inside child process only)
    # ------------------------------------------------------------------

    def _send(self, payload: dict):
        """Send a response dict to the parent via the pipe."""
        self._conn.send(payload)

    def _err(self, msg: str):
        self._send({"success": False, "error": msg})

    # ------------------------------------------------------------------
    # Entry point  — hammer is imported HERE and nowhere else
    # ------------------------------------------------------------------

    def run(self):
        """
        Child entry point.  Runs in an isolated OS process.

        All Spike C++ state, HTIF threads, and signal handlers live here.
        The parent never touches this memory space.
        """
        # Ignore SIGINT inside the child – Ctrl+C belongs to the parent
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        # Add hammer builddir to path
        if self._hammer_dir and self._hammer_dir not in sys.path:
            sys.path.insert(0, self._hammer_dir)

        # ── Import hammer C++ extension ─────────────────────────────────
        try:
            import hammer  # noqa: PLC0415 – intentional deferred import
        except ImportError as exc:
            self._err(f"Failed to import hammer: {exc}")
            return

        # ── Signal parent: C++ module loaded ────────────────────────────
        self._send({"success": True, "type": "ready", "msg": _READY_SENTINEL})

        # ── Construct Hammer instance ────────────────────────────────────
        try:
            if not os.path.exists(self._elf_path):
                raise FileNotFoundError(f"ELF not found: {self._elf_path}")

            mem_cfg = hammer.mem_cfg_t(hammer.DramBase, 256 * 1024 * 1024)
            sim = hammer.Hammer(
                self._isa,
                self._priv,
                "",       # vector arch
                [0],      # hart IDs
                [mem_cfg],
                self._elf_path,
                self._start_pc,
            )
            # Warm-up steps so Spike moves to the real ELF entry point
            for _ in range(5):
                sim.single_step(0)

        except Exception as exc:
            self._err(f"Hammer init failed: {exc}")
            return

        # ── Signal parent: ready to accept commands ──────────────────────
        self._send({"success": True, "type": "init", "msg": _INIT_SENTINEL})

        # ── Main command loop ────────────────────────────────────────────
        while True:
            try:
                cmd = self._conn.recv()
            except EOFError:
                break
            except Exception as exc:
                self._err(f"recv error: {exc}")
                break

            cmd_type = cmd.get("type", "")

            if cmd_type == "shutdown":
                self._send({"success": True, "type": "shutdown_ack"})
                break

            elif cmd_type == "step":
                try:
                    self._send(self._do_step(sim, cmd))
                except Exception as exc:
                    self._err(f"step error: {exc}")

            elif cmd_type == "query_pc":
                try:
                    pc = sim.get_PC(0) & 0xFFFFFFFF
                    self._send({
                        "success": True,
                        "type": "query_result",
                        "pc": pc,
                        "pc_hex": f"0x{pc:08x}",
                    })
                except Exception as exc:
                    self._err(f"query_pc error: {exc}")

            else:
                self._err(f"Unknown command type: {cmd_type!r}")

        self._conn.close()

    # ------------------------------------------------------------------
    # Step execution  (mirrors hammer_subprocess.py logic exactly)
    # ------------------------------------------------------------------

    @staticmethod
    def _safe(fn, default=None):
        try:
            return fn()
        except Exception:
            return default

    def _do_step(self, sim, cmd: dict) -> dict:
        s = self._safe
        pc = sim.get_PC(0) & 0xFFFFFFFF

        data: dict = {
            "hart_id":             cmd.get("hart_id", 0),
            "pc":                  pc,
            "pc_hex":              f"0x{pc:08x}",
            "instruction_hex":     s(lambda: sim.get_insn_hex(0, pc)),
            "instruction_hex_str": s(lambda: f"0x{sim.get_insn_hex(0, pc):08x}", "N/A"),
            "instruction_string":  s(lambda: sim.get_insn_string(0, pc), "N/A"),
            "rs1_addr":            s(lambda: sim.get_rs1_addr(0, pc)),
            "rs2_addr":            s(lambda: sim.get_rs2_addr(0, pc)),
            "rs3_addr":            s(lambda: sim.get_rs3_addr(0, pc)),
            "rd_addr":             s(lambda: sim.get_rd_addr(0, pc)),
        }

        # CSR
        csr_addr = s(lambda: sim.get_csr_addr(0, pc))
        data["csr_addr"] = csr_addr
        if csr_addr is not None:
            csr_val = s(lambda: sim.get_csr(0, csr_addr))
            data["csr_value"]     = csr_val
            data["csr_value_hex"] = f"0x{csr_val:08x}" if csr_val is not None else "N/A"
        else:
            data["csr_value"]     = None
            data["csr_value_hex"] = "N/A"

        # ── EXECUTE STEP ──────────────────────────────────────────────
        sim.single_step(0)

        # Post-step PC
        pc_after = s(lambda: sim.get_PC(0) & 0xFFFFFFFF)
        data["pc_after_step"]     = pc_after
        data["pc_after_step_hex"] = f"0x{pc_after:08x}" if pc_after is not None else "N/A"

        # Register writes
        rw_raw = s(lambda: sim.get_log_reg_writes(0), [])
        data["register_writes"] = [
            {"register": reg, "value": val, "value_hex": f"0x{val:08x}"}
            for reg, val in (rw_raw or [])
        ]

        # Memory reads
        mr_raw = s(lambda: sim.get_log_mem_reads(0), [])
        data["memory_reads"] = [
            {
                "address":     addr & 0xFFFFFFFF,
                "address_hex": f"0x{addr & 0xFFFFFFFF:08x}",
                "value":       val,
                "value_hex":   f"0x{val:08x}",
                "size":        size,
            }
            for addr, val, size in (mr_raw or [])
        ]

        # Memory writes
        mw_raw = s(lambda: sim.get_log_mem_writes(0), [])
        mw_list = []
        for addr, val, size in (mw_raw or []):
            am = addr & 0xFFFFFFFF
            mc = s(lambda: (sim.get_memory_at_VA(0, am, 4, 4) or [None])[0])
            mw_list.append({
                "address":        am,
                "address_hex":    f"0x{am:08x}",
                "value":          val,
                "value_hex":      f"0x{val:08x}",
                "size":           size,
                "memory_content": mc,
            })
        data["memory_writes"] = mw_list

        # Watch addresses
        mem_contents: dict = {}
        for wa in self._watch:
            raw = s(lambda: sim.get_memory_at_VA(0, wa, 4, 1))
            if raw is not None:
                value = sum(b << (i * 8) for i, b in enumerate(raw))
                mem_contents[f"0x{wa:08x}"] = {
                    "value":     value,
                    "value_hex": f"0x{value:08x}",
                    "bytes":     list(raw),
                }
            else:
                mem_contents[f"0x{wa:08x}"] = {
                    "value":     None,
                    "value_hex": "N/A",
                    "bytes":     [],
                }
        data["memory_contents"] = mem_contents

        return {"success": True, "type": "step_result", "data": data}
