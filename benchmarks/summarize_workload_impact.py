#!/usr/bin/env python3
import csv
import statistics
import sys
from collections import defaultdict


def optional_float(row: dict[str, str], field: str) -> float | None:
    value = row.get(field, "")
    if value == "":
        return None
    return float(value)


def format_ms(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.3f} ms"


def format_ms_range(values: list[float | None]) -> str:
    present = [value for value in values if value is not None]
    if not present:
        return "n/a"
    return f"{min(present):.3f}–{max(present):.3f} ms"


def format_ms_median(values: list[float | None]) -> str:
    present = [value for value in values if value is not None]
    if not present:
        return "n/a"
    return f"{statistics.median(present):.3f} ms"


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <workload-impact.tsv>", file=sys.stderr)
        return 2

    with open(sys.argv[1], encoding="utf-8") as source:
        rows = [line for line in source if not line.startswith("#")]

    by_run: dict[str, dict[str, dict[str, str]]] = defaultdict(dict)
    for row in csv.DictReader(rows, delimiter="\t"):
        by_run[row["run"]][row["mode"]] = row

    paired = []
    incomplete = []
    for run, modes in sorted(by_run.items(), key=lambda item: int(item[0])):
        baseline = modes.get("without_recorder")
        measured = modes.get("with_recorder")
        if baseline is None or measured is None:
            incomplete.append(run)
            continue

        baseline_rps = float(baseline["requests_per_second"])
        measured_rps = float(measured["requests_per_second"])
        if baseline_rps <= 0:
            incomplete.append(run)
            continue

        impact = 100 * (baseline_rps - measured_rps) / baseline_rps
        baseline_p99 = optional_float(baseline, "p99_ms")
        measured_p99 = optional_float(measured, "p99_ms")
        p99_delta = None
        if baseline_p99 is not None and measured_p99 is not None:
            p99_delta = measured_p99 - baseline_p99

        paired.append(
            (run, baseline_rps, measured_rps, impact, baseline_p99, measured_p99, p99_delta)
        )

    print(
        "| Run | Without recorder | With recorder | Throughput impact | "
        "p99 without | p99 with | p99 delta |"
    )
    print("| ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for run, baseline_rps, measured_rps, impact, baseline_p99, measured_p99, p99_delta in paired:
        print(
            f"| {run} | {baseline_rps:.2f} req/s | {measured_rps:.2f} req/s | "
            f"{impact:.2f}% | {format_ms(baseline_p99)} | {format_ms(measured_p99)} | "
            f"{format_ms(p99_delta)} |"
        )

    if paired:
        baseline_values = [row[1] for row in paired]
        measured_values = [row[2] for row in paired]
        impact_values = [row[3] for row in paired]
        baseline_p99_values = [row[4] for row in paired]
        measured_p99_values = [row[5] for row in paired]
        p99_delta_values = [row[6] for row in paired]

        print()
        print(
            "| Summary | Without recorder | With recorder | Throughput impact | "
            "p99 without | p99 with | p99 delta |"
        )
        print("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
        print(
            "| Median | "
            f"{statistics.median(baseline_values):.2f} req/s | "
            f"{statistics.median(measured_values):.2f} req/s | "
            f"{statistics.median(impact_values):.2f}% | "
            f"{format_ms_median(baseline_p99_values)} | "
            f"{format_ms_median(measured_p99_values)} | "
            f"{format_ms_median(p99_delta_values)} |"
        )
        print(
            "| Range | "
            f"{min(baseline_values):.2f}–{max(baseline_values):.2f} req/s | "
            f"{min(measured_values):.2f}–{max(measured_values):.2f} req/s | "
            f"{min(impact_values):.2f}–{max(impact_values):.2f}% | "
            f"{format_ms_range(baseline_p99_values)} | "
            f"{format_ms_range(measured_p99_values)} | "
            f"{format_ms_range(p99_delta_values)} |"
        )

    if incomplete:
        print()
        print(f"warning: skipped incomplete runs: {', '.join(incomplete)}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
