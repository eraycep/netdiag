#!/usr/bin/env python3
import concurrent.futures
import sys
import urllib.request


def fetch(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            response.read(1)
        return True
    except OSError:
        return False


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <url> <request-count>", file=sys.stderr)
        return 2

    url = sys.argv[1]
    requests = int(sys.argv[2])
    if requests < 1:
        print("request count must be positive", file=sys.stderr)
        return 2

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(fetch, [url] * requests))

    succeeded = sum(results)
    print(f"HTTP requests: {succeeded} succeeded, {requests - succeeded} failed")
    return 0 if succeeded else 1


if __name__ == "__main__":
    raise SystemExit(main())
