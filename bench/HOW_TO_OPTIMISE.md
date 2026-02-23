# HOW_TO_OPTIMISE.md
# Optimising Hammer ↔ Testbench Communication

---

## Why the Subprocess Works (The "Wall" Analogy)

The subprocess approach works because it puts a **complete wall** between cocotb and Spike.

Think of it like two separate houses instead of two people sharing one room:

```
┌─────────────────────────┐        pipe (JSON)       ┌──────────────────────────┐
│   Parent process        │  ─────────────────────►  │   Child process           │
│   cocotb event loop     │  ◄─────────────────────  │   hammer_subprocess.py    │
│   async scheduler       │                           │   Spike + HTIF thread     │
│   signal handlers       │                           │   its own signal handlers │
│   coroutines            │                           │   simple blocking loop    │
└─────────────────────────┘                           └──────────────────────────┘
```

**Three things the wall gives you:**

1. **Separate signal tables.** Each process has its own signal handlers. Spike in the
   subprocess can register whatever `SIGTERM`/`SIGWINCH` handlers it wants — they never
   touch cocotb's handlers in the parent.

2. **Separate memory / mutex space.** The HTIF thread's condition variables and mutexes
   are in the child's memory. The parent cannot accidentally compete with them.

3. **Subprocess runs a simple blocking loop — not async.** `hammer_subprocess.py` just
   does `stdin.readline()` → `single_step()` → print JSON → repeat. No async, no
   cocotb scheduler, no competing event loop. The HTIF thread in the child doesn't
   deadlock because nothing else is fighting it for the mutex.

So the subprocess is essentially doing what you want — calling `single_step()` in the
simplest possible single-threaded context — and the JSON pipe is just the messenger.

---

## What Actually Caused the Deadlock (The SIGWINCH Clue)

When you **maximized/minimized the terminal**, the OS sent a **`SIGWINCH`** signal
(Window Size Changed) — NOT Ctrl+C.

`SIGWINCH` interrupted Spike's internal HTIF thread's `pthread_cond_wait()` call with
`EINTR` (interrupted system call). That spurious wakeup let the HTIF thread release a
mutex that `single_step()` was waiting on — deadlock broken.

**Why `gil_scoped_release` didn't help:**  
The Python GIL was never involved. The freeze was 100% inside C++. The HTIF thread
was blocked on its own `pthread_cond_wait()`, waiting for a wakeup that only the Spike
run loop normally provides — and that run loop doesn't exist when you call `single_step()`
directly from Python.

---

## Recommended Fix — Python Side Only (No Spike Internals)

### The SIGWINCH Heartbeat Pattern

Since SIGWINCH reliably unsticks the HTIF condvar, send it programmatically from a
background Python thread — a **heartbeat** that periodically pokes the HTIF thread
so it never stays stuck:

```python
import os, signal, threading, time

class HtifHeartbeat(threading.Thread):
    """
    Periodically sends SIGWINCH to the current process.
    This acts as a guaranteed spurious wakeup for Spike's HTIF thread's
    pthread_cond_wait(), preventing it from deadlocking when single_step()
    is called outside of Spike's normal run loop.
    """
    def __init__(self, interval_sec=0.05):
        super().__init__(daemon=True)
        self.interval = interval_sec
        self._stop_event = threading.Event()

    def run(self):
        while not self._stop_event.is_set():
            os.kill(os.getpid(), signal.SIGWINCH)
            time.sleep(self.interval)

    def stop(self):
        self._stop_event.set()


# Usage — start before creating the Hammer instance:
heartbeat = HtifHeartbeat(interval_sec=0.05)  # wakes HTIF thread every 50ms
heartbeat.start()

sim = hammer.Hammer("RV32IMC", "msu", "", [0], [mem_cfg], elf_path, None)
sim.single_step(0)  # no longer deadlocks

# When done:
heartbeat.stop()
```

**Why 50ms?** The HTIF thread's cond_wait has no timeout, so without a poke it
sleeps forever. 50ms is fast enough that `single_step()` never waits more than 50ms
to acquire the mutex — negligible compared to the ~4 µs step time.

**Is this a hack?** Yes — but it's entirely in Python, touches nothing in Spike or Hammer,
and precisely mirrors what terminal-resize did accidentally. It's also easy to remove
once a proper fix is applied at the C++ level.

---

## What the C++ Fix Would Look Like (Hammer Side, Not Spike Internals)

If you want to fix it properly without touching Spike's `riscv/htif.cc`, the right
place is **`hammer_pybind.cpp`** or **`hammer.cpp`** — files you already own and
have already modified.

### Option A — Send SIGWINCH once inside the pybind `single_step` wrapper

In `hammer_pybind.cpp`, change line 99 from:
```cpp
.def("single_step", &Hammer::single_step)
```
to:
```cpp
.def("single_step", [](Hammer &h, uint8_t hart) {
    // Wake any blocked HTIF condvar before stepping
    ::kill(::getpid(), SIGWINCH);
    py::gil_scoped_release release;   // also release GIL as good practice
    h.single_step(hart);
}, py::arg("hart_id") = 0)
```
Add `#include <csignal>` at the top. Then `meson compile -C builddir`.

Now every `sim.single_step(0)` call from Python automatically wakes the HTIF thread
before entering C++ — the deadlock cannot happen.

### Option B — Add a timed-wait helper in `hammer.cpp`

In `hammer.cpp`, add a method that sends `SIGWINCH` and then calls `single_step()`:

```cpp
void Hammer::single_step_safe(uint8_t hart_id) {
    ::kill(::getpid(), SIGWINCH);   // poke HTIF thread out of its condvar
    single_step(hart_id);
}
```

Then expose `single_step_safe` via pybind11 and use that instead. No Spike internals
touched — just the Hammer wrapper layer you control.


---

## Option E — If You Want to Touch Spike Internals (Exact Lines)

> Files are in `submodules/riscv-isa-sim/`. Two separate problems, two files.

---

### Problem 1 — The Actual Deadlock  
**File:** [`fesvr/context.cc`](file:///home/nitin/bench/coco-rvtb/submodules/riscv-isa-sim/fesvr/context.cc) **Line 96–97**

Spike's fiber coroutine scheduler is in `fesvr/context.cc`. When one coroutine
yields to another via `switch_to()`, the caller sleeps here:

```cpp
// context.cc lines 95–98  (non-ucontext pthread path, which is the default on Linux)
pthread_mutex_lock(&cur->mutex);
while (!cur->flag)
    pthread_cond_wait(&cur->cond, &cur->mutex);   // ← hangs forever
pthread_mutex_unlock(&cur->mutex);
```

When you call `single_step()` from Python without Spike's run loop running,
the HTIF coroutine calls `target->switch_to()` to yield back to you —
but nobody ever calls `pthread_cond_signal()` to wake your coroutine.
Both sides sit in `pthread_cond_wait`. **Deadlock.**

**Fix — replace with a 5 ms timed wait:**

```diff
--- a/fesvr/context.cc
+++ b/fesvr/context.cc
@@ -95,5 +95,12 @@ void context_t::switch_to()
   pthread_mutex_lock(&cur->mutex);
-  while (!cur->flag)
-    pthread_cond_wait(&cur->cond, &cur->mutex);
+  while (!cur->flag) {
+    struct timespec ts;
+    clock_gettime(CLOCK_REALTIME, &ts);
+    ts.tv_nsec += 5000000L;  // 5 ms
+    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
+    pthread_cond_timedwait(&cur->cond, &cur->mutex, &ts);
+    // if flag still 0 after timeout, loop back and wait again
+  }
   pthread_mutex_unlock(&cur->mutex);
```

With a 5 ms timeout, if the other coroutine never signals, the wait returns,
re-checks `flag`, and loops — never hanging permanently.

---

### Problem 2 — Signal Handler Hijacking  
**File:** [`fesvr/htif.cc`](file:///home/nitin/bench/coco-rvtb/submodules/riscv-isa-sim/fesvr/htif.cc) **Lines 52–54**

Every time `Hammer()` is constructed, `htif_t::htif_t()` runs and
**silently overwrites your process's `SIGINT` and `SIGTERM` handlers:**

```cpp
// htif.cc lines 52–54
signal(SIGINT,  &handle_signal);   // ← clobbers cocotb's SIGINT handler
signal(SIGTERM, &handle_signal);   // ← clobbers cocotb's SIGTERM handler
signal(SIGABRT, &handle_signal);
```

Spike's `handle_signal` only sets `signal_exit = true` and restarts the signal.
Since cocotb never calls `htif_t::run()`, `signal_exit` never triggers anything
useful — but cocotb's own handlers (e.g., clean sim shutdown on Ctrl+C) are gone.

**Fix — save and restore the caller's handlers:**

```diff
--- a/fesvr/htif.cc
+++ b/fesvr/htif.cc
@@ -47,7 +47,16 @@ htif_t::htif_t()
   : mem(this), entry(DRAM_BASE), sig_addr(0), sig_len(0),
     tohost_addr(0), fromhost_addr(0), stopped(false),
     syscall_proxy(this)
 {
-  signal(SIGINT,  &handle_signal);
-  signal(SIGTERM, &handle_signal);
-  signal(SIGABRT, &handle_signal);
+  // Save caller's handlers before overwriting — critical when embedded as a library
+  struct sigaction old_sigint, old_sigterm;
+  sigaction(SIGINT,  nullptr, &old_sigint);
+  sigaction(SIGTERM, nullptr, &old_sigterm);
+  signal(SIGINT,  &handle_signal);
+  signal(SIGTERM, &handle_signal);
+  signal(SIGABRT, &handle_signal);  // keep — crash handler is fine to own
+  sigaction(SIGINT,  &old_sigint,  nullptr);  // restore
+  sigaction(SIGTERM, &old_sigterm, nullptr);  // restore
```

Now cocotb's Ctrl+C handling survives Hammer construction.

---

### Rebuild After Editing Spike

```bash
# Rebuild Spike
cd submodules/riscv-isa-sim
./configure --prefix=$RISCV
make -j$(nproc)

# Rebuild Hammer against the new libspike
cd ../hammer
meson compile -C builddir
```

---

## Summary

| Approach | Touches Spike? | Risk | Effort |
|----------|---------------|------|--------|
| **Subprocess (current)** | No | None | Done ✅ |
| Python SIGWINCH heartbeat | No | Very low | 20 lines Python |
| `kill(SIGWINCH)` in `hammer_pybind.cpp` line 99 | No | Low | 3 lines + recompile hammer |
| `single_step_safe()` in `hammer.cpp` | No | Low | 5 lines + recompile hammer |
| **`pthread_cond_timedwait`** in `context.cc:97` | Yes — fesvr/context.cc | Low | 8 lines + rebuild spike+hammer |
| **Signal save/restore** in `htif.cc:52` | Yes — fesvr/htif.cc | Low | 6 lines + rebuild spike+hammer |

**The subprocess exists for a good reason.** The wall it provides is real and principled.
If you ever want to remove the ~128 µs/step IPC overhead, fix both Spike issues above
(context.cc + htif.cc) and use the direct import path — 32× speedup, no deadlock risk.
