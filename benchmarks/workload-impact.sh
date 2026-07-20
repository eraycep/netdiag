#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "this benchmark must run as root" >&2
  exit 1
fi

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
NETDIAG_BIN=${NETDIAG_BIN:-"${ROOT_DIR}/bin/netdiag"}
WORKLOAD_BIN=${WORKLOAD_BIN:-"${ROOT_DIR}/bin/netdiag-workload"}
RESULTS=${1:-"${ROOT_DIR}/benchmarks/results/workload-impact.tsv"}
CLIENT_DURATION=${CLIENT_DURATION:-30}
WARMUP_SECONDS=${WARMUP_SECONDS:-5}
DURATION=${DURATION:-}
INTERVAL=${INTERVAL:-1s}
REPETITIONS=${REPETITIONS:-5}
CONCURRENCY=${CONCURRENCY:-32}
PAYLOAD_BYTES=${PAYLOAD_BYTES:-1048576}
EBPF=${EBPF:-false}
STRICT=${STRICT:-0}

for command in ip python3 timeout; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "required command not found: ${command}" >&2
    exit 1
  fi
done
if [[ ! -x ${NETDIAG_BIN} ]]; then
  echo "netdiag binary not found or not executable: ${NETDIAG_BIN}" >&2
  echo "run 'make build' first or set NETDIAG_BIN" >&2
  exit 1
fi
if [[ ! -x ${WORKLOAD_BIN} ]]; then
	echo "netdiag workload binary not found or not executable: ${WORKLOAD_BIN}" >&2
	echo "run 'make build' first or set WORKLOAD_BIN" >&2
	exit 1
fi
if ! [[ ${CLIENT_DURATION} =~ ^[1-9][0-9]*$ ]]; then
	echo "CLIENT_DURATION must be a positive integer number of seconds" >&2
	exit 1
fi
if ! [[ ${WARMUP_SECONDS} =~ ^[0-9]+$ ]]; then
	echo "WARMUP_SECONDS must be a non-negative integer number of seconds" >&2
	exit 1
fi
if [[ -z ${DURATION} ]]; then
	DURATION="$((CLIENT_DURATION + WARMUP_SECONDS + 2))s"
fi
if ! [[ ${REPETITIONS} =~ ^[1-9][0-9]*$ ]]; then
	echo "REPETITIONS must be a positive integer" >&2
	exit 1
fi
if [[ ${EBPF} != "true" && ${EBPF} != "false" ]]; then
  echo "EBPF must be true or false" >&2
  exit 1
fi

mkdir -p "$(dirname -- "${RESULTS}")"
capture_dir="$(dirname -- "${RESULTS}")/workload-impact-captures"
mkdir -p "${capture_dir}"

suffix=$((BASHPID % 100000))
octet=$((BASHPID % 200 + 20))
namespace="netdiag-impact-${BASHPID}"
host_veth="ndh${suffix}"
peer_veth="ndp${suffix}"
host_address="198.21.${octet}.1"
peer_address="198.21.${octet}.2"
server_pid=""
recorder_pid=""

release_outputs() {
  if [[ -n ${SUDO_UID:-} && -n ${SUDO_GID:-} ]]; then
    chown "${SUDO_UID}:${SUDO_GID}" "${RESULTS}" 2>/dev/null || true
    chown -R "${SUDO_UID}:${SUDO_GID}" "${capture_dir}" 2>/dev/null || true
  fi
  chmod u+rw,go+r "${RESULTS}" 2>/dev/null || true
}

cleanup() {
  if [[ -n ${recorder_pid} ]]; then
    kill "${recorder_pid}" >/dev/null 2>&1 || true
    wait "${recorder_pid}" >/dev/null 2>&1 || true
  fi
  if [[ -n ${server_pid} ]]; then
    kill "${server_pid}" >/dev/null 2>&1 || true
    wait "${server_pid}" >/dev/null 2>&1 || true
  fi
  ip netns del "${namespace}" >/dev/null 2>&1 || true
  ip link del "${host_veth}" >/dev/null 2>&1 || true
	release_outputs
}
trap cleanup EXIT INT TERM

extract_client_stats() {
	python3 - "$1" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
counts = re.search(r"HTTP requests:\s+([0-9]+)\s+succeeded,\s+([0-9]+)\s+failed", text)
latency = re.search(r"Latency milliseconds:\s+p50=([0-9.]+)\s+p95=([0-9.]+)\s+p99=([0-9.]+)", text)
if not counts or not latency:
	print("could not parse client output", file=sys.stderr)
	raise SystemExit(1)
print(counts.group(1), counts.group(2), latency.group(1), latency.group(2), latency.group(3))
PY
}

warmup_client() {
	if (( WARMUP_SECONDS == 0 )); then
		return
	fi
	local mode=$1
	local output="${capture_dir}/warmup-${mode}.txt"
	timeout "$((WARMUP_SECONDS + 10))s" \
		"${WORKLOAD_BIN}" client \
		--url "http://${peer_address}:18080/payload" \
		--duration "${WARMUP_SECONDS}s" \
		--concurrency "${CONCURRENCY}" \
		>"${output}" || true
}

run_client() {
	local run=$1
	local mode=$2
	local pair_order=$3
	local output="${capture_dir}/client-${run}-${mode}.txt"
	local status=0

	warmup_client "${run}-${mode}"
	timeout "$((CLIENT_DURATION + 10))s" \
		"${WORKLOAD_BIN}" client \
		--url "http://${peer_address}:18080/payload" \
		--duration "${CLIENT_DURATION}s" \
		--concurrency "${CONCURRENCY}" \
    >"${output}" || status=$?
  if (( status != 0 )); then
		echo "warning: ${mode} run ${run} client exited with status ${status}" >&2
	fi

	read -r succeeded failed p50_ms p95_ms p99_ms < <(extract_client_stats "${output}")
	local rps
	rps=$(awk -v succeeded="${succeeded}" -v duration="${CLIENT_DURATION}" 'BEGIN { printf "%.3f", succeeded / duration }')
	printf '%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
		"${run}" "${mode}" "${pair_order}" "${CLIENT_DURATION}" "${CONCURRENCY}" \
		"${succeeded}" "${failed}" "${rps}" "${p50_ms}" "${p95_ms}" "${p99_ms}" \
		>>"${RESULTS}"
	echo "${mode} run ${run}/${REPETITIONS}: ${succeeded} succeeded, ${failed} failed, ${rps} req/s, p99 ${p99_ms} ms"
}

run_with_recorder() {
	local run=$1
	local pair_order=$2
	local capture="${capture_dir}/capture-${run}.json"

	"${NETDIAG_BIN}" record \
    --duration "${DURATION}" \
    --interval "${INTERVAL}" \
    --max-samples 1000000 \
    --interface "${host_veth}" \
    --ebpf="${EBPF}" \
    --output "${capture}" &
	recorder_pid=$!

	sleep 1
	run_client "${run}" "with_recorder" "${pair_order}"

	wait "${recorder_pid}"
	recorder_pid=""
}

run_mode() {
	local run=$1
	local mode=$2
	local pair_order=$3
	case "${mode}" in
	without_recorder)
		run_client "${run}" "without_recorder" "${pair_order}"
		;;
	with_recorder)
		run_with_recorder "${run}" "${pair_order}"
		;;
	*)
		echo "unknown run mode: ${mode}" >&2
		exit 1
		;;
	esac
}

pair_order_for_run() {
	python3 - <<'PY'
import random

print(random.choice(("without_recorder_first", "with_recorder_first")))
PY
}

{
  printf '# generated_at_utc\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '# hostname\t%s\n' "$(hostname)"
	printf '# kernel\t%s\n' "$(uname -r)"
	printf '# duration\t%s\n' "${DURATION}"
	printf '# client_duration_seconds\t%s\n' "${CLIENT_DURATION}"
	printf '# warmup_seconds\t%s\n' "${WARMUP_SECONDS}"
	printf '# repetitions\t%s\n' "${REPETITIONS}"
	printf '# interval\t%s\n' "${INTERVAL}"
	printf '# concurrency\t%s\n' "${CONCURRENCY}"
	printf '# payload_bytes\t%s\n' "${PAYLOAD_BYTES}"
	printf '# ebpf\t%s\n' "${EBPF}"
	printf '# interface\t%s\n' "${host_veth}"
	printf 'run\tmode\tpair_order\tclient_duration_seconds\tconcurrency\tsucceeded\tfailed\trequests_per_second\tp50_ms\tp95_ms\tp99_ms\n'
} >"${RESULTS}"

ip netns add "${namespace}"
ip link add "${host_veth}" type veth peer name "${peer_veth}"
ip link set "${peer_veth}" netns "${namespace}"
ip address add "${host_address}/24" dev "${host_veth}"
ip link set "${host_veth}" up
ip -n "${namespace}" address add "${peer_address}/24" dev "${peer_veth}"
ip -n "${namespace}" link set lo up
ip -n "${namespace}" link set "${peer_veth}" up

ip netns exec "${namespace}" "${WORKLOAD_BIN}" server \
	--listen "${peer_address}:18080" \
	--payload-bytes "${PAYLOAD_BYTES}" >/dev/null 2>&1 &
server_pid=$!
sleep 0.5
if ! kill -0 "${server_pid}" >/dev/null 2>&1; then
  echo "HTTP server failed to start in the network namespace" >&2
  exit 1
fi

for ((run = 1; run <= REPETITIONS; run++)); do
	pair_order=$(pair_order_for_run)
	if [[ ${pair_order} == "without_recorder_first" ]]; then
		run_mode "${run}" "without_recorder" "${pair_order}"
		sleep 1
		run_mode "${run}" "with_recorder" "${pair_order}"
	else
		run_mode "${run}" "with_recorder" "${pair_order}"
		sleep 1
		run_mode "${run}" "without_recorder" "${pair_order}"
	fi
	sleep 1
done

echo
python3 "${ROOT_DIR}/benchmarks/summarize_workload_impact.py" "${RESULTS}"
echo "raw results: ${RESULTS}"
echo "captures: ${capture_dir}"

if [[ ${STRICT} == "1" ]]; then
  median_impact=$(python3 - "${RESULTS}" <<'PY'
import csv
import statistics
import sys
from collections import defaultdict

with open(sys.argv[1], encoding="utf-8") as source:
    rows = [line for line in source if not line.startswith("#")]
by_run = defaultdict(dict)
for row in csv.DictReader(rows, delimiter="\t"):
    by_run[row["run"]][row["mode"]] = float(row["requests_per_second"])
impacts = []
for modes in by_run.values():
    baseline = modes.get("without_recorder")
    measured = modes.get("with_recorder")
    if baseline and measured is not None:
        impacts.append(100 * (baseline - measured) / baseline)
print(f"{statistics.median(impacts):.3f}" if impacts else "nan")
PY
)
  awk -v impact="${median_impact}" 'BEGIN { exit !(impact > 2.0) }' && {
    echo "error: median workload impact ${median_impact}% exceeds 2% target" >&2
    exit 1
  }
fi
