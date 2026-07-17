#!/usr/bin/env python3
import csv
import statistics
import sys
from collections import defaultdict


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <capture-overhead.tsv>", file=sys.stderr)
        return 2

    with open(sys.argv[1], encoding="utf-8") as source:
        rows = [line for line in source if not line.startswith("#")]
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in csv.DictReader(rows, delimiter="\t"):
        grouped[row["interval"]].append(row)

    print("| Interval | Runs | Median CPU | Peak RSS | Mean samples | Mean output | Bytes/sample |")
    print("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for interval, values in grouped.items():
        cpu = statistics.median(float(row["cpu_percent"]) for row in values)
        rss = max(int(row["max_rss_kib"]) for row in values)
        samples = statistics.mean(int(row["samples"]) for row in values)
        output = statistics.mean(int(row["output_bytes"]) for row in values)
        per_sample = statistics.mean(float(row["bytes_per_sample"]) for row in values)
        print(
            f"| {interval} | {len(values)} | {cpu:.3f}% | {rss} KiB | "
            f"{samples:.1f} | {output:.0f} B | {per_sample:.1f} B |"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
