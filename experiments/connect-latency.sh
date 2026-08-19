#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "this experiment must run as root" >&2
  exit 1
fi

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
WORKLOAD_BIN=${WORKLOAD_BIN:-"${ROOT_DIR}/bin/netdiag-workload"}
OUTPUT_DIR=${1:-"${ROOT_DIR}"}
CLIENT_DURATION=${CLIENT_DURATION:-10}
CONCURRENCY=${CONCURRENCY:-8}
PAYLOAD_BYTES=${PAYLOAD_BYTES:-1024}
NETEM_DELAY=${NETEM_DELAY:-100ms}
STRICT=${STRICT:-0}

for command in ip tc python3 timeout; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "required command not found: ${command}" >&2
    exit 1
  fi
done
if [[ ! -x ${WORKLOAD_BIN} ]]; then
  echo "netdiag workload binary not found or not executable: ${WORKLOAD_BIN}" >&2
  echo "run 'make build' first or set WORKLOAD_BIN" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"
baseline_output="${OUTPUT_DIR}/connect-latency-baseline.txt"
impaired_output="${OUTPUT_DIR}/connect-latency-impaired.txt"

suffix=$((BASHPID % 100000))
octet=$((BASHPID % 200 + 20))
namespace="netdiag-connect-${BASHPID}"
host_veth="ndh${suffix}"
peer_veth="ndp${suffix}"
host_address="198.24.${octet}.1"
peer_address="198.24.${octet}.2"
server_pid=""

release_outputs() {
  local file
  for file in "${baseline_output}" "${impaired_output}"; do
    if [[ -e ${file} ]]; then
      if [[ -n ${SUDO_UID:-} && -n ${SUDO_GID:-} ]]; then
        chown "${SUDO_UID}:${SUDO_GID}" "${file}" 2>/dev/null || true
      fi
      chmod u+rw,go+r "${file}" 2>/dev/null || true
    fi
  done
}

cleanup() {
  if [[ -n ${server_pid} ]]; then
    kill "${server_pid}" >/dev/null 2>&1 || true
    wait "${server_pid}" >/dev/null 2>&1 || true
  fi
  tc qdisc del dev "${host_veth}" root >/dev/null 2>&1 || true
  ip netns del "${namespace}" >/dev/null 2>&1 || true
  ip link del "${host_veth}" >/dev/null 2>&1 || true
  release_outputs
}
trap cleanup EXIT INT TERM

run_client() {
  local label=$1
  local output=$2

  echo "running ${label} workload client with one TCP connection per request"
  timeout "$((CLIENT_DURATION + 10))s" \
    "${WORKLOAD_BIN}" client \
    --url "http://${peer_address}:18080/payload" \
    --duration "${CLIENT_DURATION}s" \
    --concurrency "${CONCURRENCY}" \
    --timeout 5s \
    --new-connection \
    | tee "${output}"
}

connect_p99() {
  local output=$1
  python3 - "${output}" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
match = re.search(r"Connect latency milliseconds:\s+p50=([0-9.]+)\s+p95=([0-9.]+)\s+p99=([0-9.]+)\s+samples=([0-9]+)", text)
if not match:
    print("could not parse connect latency output", file=sys.stderr)
    raise SystemExit(1)
print(match.group(3))
PY
}

expect_impaired_connect_latency() {
  local baseline=$1
  local impaired=$2
  python3 - "${baseline}" "${impaired}" "${STRICT}" <<'PY'
import sys

baseline = float(sys.argv[1])
impaired = float(sys.argv[2])
strict = sys.argv[3] == "1"

if impaired > baseline:
    raise SystemExit

message = (
    f"impaired connect p99 did not increase: baseline={baseline:.3f} ms, "
    f"impaired={impaired:.3f} ms; try increasing NETEM_DELAY or CLIENT_DURATION"
)
if strict:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)
print(f"warning: {message}", file=sys.stderr)
PY
}

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

echo "baseline output: ${baseline_output}"
run_client "baseline" "${baseline_output}"
baseline_p99=$(connect_p99 "${baseline_output}")
echo "baseline connect p99: ${baseline_p99} ms"

echo
echo "installing netem delay: ${NETEM_DELAY}"
tc qdisc replace dev "${host_veth}" root netem delay "${NETEM_DELAY}"
tc -s qdisc show dev "${host_veth}"

echo
echo "impaired output: ${impaired_output}"
run_client "impaired" "${impaired_output}"
impaired_p99=$(connect_p99 "${impaired_output}")
echo "impaired connect p99: ${impaired_p99} ms"

expect_impaired_connect_latency "${baseline_p99}" "${impaired_p99}"
release_outputs

echo
echo "baseline output: ${baseline_output}"
echo "impaired output: ${impaired_output}"
