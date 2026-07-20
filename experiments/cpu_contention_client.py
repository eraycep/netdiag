#!/usr/bin/env python3
import concurrent.futures
import os
import time
import sys
import urllib.request


def fetch_until_deadline(url: str, deadline: float, timeout: float) -> tuple[int, int, list[float]]:
    succeeded = 0
    failed = 0
    latencies = []
    while time.monotonic() < deadline:
        try:
            start = time.perf_counter()
            with urllib.request.urlopen(url, timeout=timeout) as response:
                response.read()
            latencies.append((time.perf_counter() - start) * 1000)
            succeeded += 1
        except OSError:
            failed += 1
    return succeeded, failed, latencies


def percentile(values: list[float], percent: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = round((len(ordered) - 1) * percent / 100)
    return ordered[index]


def main() -> int:
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} <url> <duration-seconds> <concurrency>", file=sys.stderr)
        return 2

    url = sys.argv[1]
    duration = float(sys.argv[2])
    concurrency = int(sys.argv[3])
    if duration <= 0:
        print("duration must be positive", file=sys.stderr)
        return 2
    if concurrency < 1:
        print("concurrency must be positive", file=sys.stderr)
        return 2

    deadline = time.monotonic() + duration
    timeout = float(os.environ.get("CLIENT_REQUEST_TIMEOUT", min(5.0, max(1.0, duration))))
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [
            executor.submit(fetch_until_deadline, url, deadline, timeout)
            for _ in range(concurrency)
        ]

    succeeded = 0
    failed = 0
    latencies = []
    for future in futures:
        worker_succeeded, worker_failed, worker_latencies = future.result()
        succeeded += worker_succeeded
        failed += worker_failed
        latencies.extend(worker_latencies)

    print(f"HTTP requests: {succeeded} succeeded, {failed} failed")
    print(
        "Latency milliseconds: "
        f"p50={percentile(latencies, 50):.3f} "
        f"p95={percentile(latencies, 95):.3f} "
        f"p99={percentile(latencies, 99):.3f}"
    )
    return 0 if succeeded > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
