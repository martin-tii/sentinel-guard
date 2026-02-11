#!/usr/bin/env python3
import os
import statistics
import subprocess
import sys
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import src.core as core


def _run_echo_loop(iterations):
    started = time.perf_counter()
    for _ in range(iterations):
        subprocess.run(["echo", "ok"], capture_output=True, text=True, check=False)
    return time.perf_counter() - started


def _bench_mode(label, iterations, interval_ms, sample_rate=0.0):
    os.environ["SENTINEL_APPROVAL_MODE"] = "reject"
    os.environ["SENTINEL_TAMPER_CHECK_INTERVAL_MS"] = str(interval_ms)
    os.environ["SENTINEL_TAMPER_CHECK_SAMPLE_RATE"] = str(sample_rate)

    core.deactivate_sentinel()
    core.activate_sentinel()
    timings = [_run_echo_loop(iterations) for _ in range(3)]
    core.deactivate_sentinel()

    avg = statistics.mean(timings)
    p95 = sorted(timings)[-1]
    print(f"{label:18} avg={avg:.4f}s p95={p95:.4f}s ({iterations} cmds x 3 runs)")


def _bench_baseline(iterations):
    core.deactivate_sentinel()
    timings = [_run_echo_loop(iterations) for _ in range(3)]
    avg = statistics.mean(timings)
    p95 = sorted(timings)[-1]
    print(f"{'baseline':18} avg={avg:.4f}s p95={p95:.4f}s ({iterations} cmds x 3 runs)")


def main():
    iterations = int(os.environ.get("SENTINEL_BENCH_ITERATIONS", "100"))
    print("Sentinel tamper-check benchmark")
    print("Lower avg/p95 is better. Compare against baseline for overhead.")
    print()

    _bench_baseline(iterations)
    _bench_mode("interval=0ms", iterations, interval_ms=0)
    _bench_mode("interval=50ms", iterations, interval_ms=50)
    _bench_mode("interval=250ms", iterations, interval_ms=250)
    _bench_mode("interval=1000ms", iterations, interval_ms=1000)


if __name__ == "__main__":
    main()
