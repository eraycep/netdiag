#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "this experiment must run as root" >&2
  exit 1
fi

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
NETDIAG_BIN=${NETDIAG_BIN:-"${ROOT_DIR}/bin/netdiag"}
OUTPUT_DIR=${1:-"${ROOT_DIR}"}
DURATION=${DURATION:-12s}
INTERVAL=${INTERVAL:-1s}
CLIENT_DURATION=${CLIENT_DURATION:-10}
NETEM_DELAY=${NETEM_DELAY:-150ms}
STRICT=${STRICT:-0}

for command in ip tc ss python3 timeout; do
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

mkdir -p "${OUTPUT_DIR}"
baseline_output="${OUTPUT_DIR}/tcp-rtt-delay-baseline.json"
impaired_output="${OUTPUT_DIR}/tcp-rtt-delay-impaired.json"
baseline_analysis="${OUTPUT_DIR}/tcp-rtt-delay-baseline.txt"
impaired_analysis="${OUTPUT_DIR}/tcp-rtt-delay-impaired.txt"
comparison_output="${OUTPUT_DIR}/tcp-rtt-delay-compare.txt"

suffix=$((BASHPID % 100000))
octet=$((BASHPID % 200 + 20))
namespace="netdiag-rtt-${BASHPID}"
host_veth="ndh${suffix}"
peer_veth="ndp${suffix}"
host_address="198.23.${octet}.1"
peer_address="198.23.${octet}.2"
server_pid=""
recorder_pid=""

release_outputs() {
  local file
  for file in "${baseline_output}" "${impaired_output}" "${baseline_analysis}" "${impaired_analysis}" "${comparison_output}"; do
    if [[ -e ${file} ]]; then
      if [[ -n ${SUDO_UID:-} && -n ${SUDO_GID:-} ]]; then
        chown "${SUDO_UID}:${SUDO_GID}" "${file}" 2>/dev/null || true
      fi
      chmod u+rw,go+r "${file}" 2>/dev/null || true
    fi
  done
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
  tc qdisc del dev "${host_veth}" root >/dev/null 2>&1 || true
  ip netns del "${namespace}" >/dev/null 2>&1 || true
  ip link del "${host_veth}" >/dev/null 2>&1 || true
  release_outputs
}
trap cleanup EXIT INT TERM

start_server() {
  ip netns exec "${namespace}" python3 - "${peer_address}" <<'PY' &
import socket
import sys
import threading

address = sys.argv[1]

def handle(conn):
    with conn:
        while True:
            data = conn.recv(4096)
            if not data:
                return
            conn.sendall(data)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((address, 18080))
    server.listen()
    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()
PY
  server_pid=$!
  sleep 0.5
  if ! kill -0 "${server_pid}" >/dev/null 2>&1; then
    echo "TCP echo server failed to start in the network namespace" >&2
    exit 1
  fi
}

run_client() {
  timeout "$((CLIENT_DURATION + 5))s" python3 - "${peer_address}" "${CLIENT_DURATION}" <<'PY'
import socket
import sys
import time

address = sys.argv[1]
duration = float(sys.argv[2])
deadline = time.monotonic() + duration
payload = b"x" * 1024
requests = 0

with socket.create_connection((address, 18080), timeout=5) as sock:
    sock.settimeout(5)
    while time.monotonic() < deadline:
        sock.sendall(payload)
        received = 0
        while received < len(payload):
            chunk = sock.recv(len(payload) - received)
            if not chunk:
                raise RuntimeError("server closed connection")
            received += len(chunk)
        requests += 1

print(f"echo exchanges: {requests}")
PY
}

run_capture() {
 local label=$1
 local output=$2
 local analysis=$3

  echo "recording ${label} capture in ${namespace} on ${peer_veth}"
  ip netns exec "${namespace}" "${NETDIAG_BIN}" record \
    --duration "${DURATION}" \
    --interval "${INTERVAL}" \
    --max-samples 3600 \
    --interface "${peer_veth}" \
    --tcp-info \
    --max-tcp-info-sockets 8 \
    --ebpf=false \
    --output "${output}" &
  recorder_pid=$!

  sleep 1
  local client_status=0
  run_client || client_status=$?
  if (( client_status != 0 )); then
    echo "warning: ${label} client exited with status ${client_status}; continuing to analyze recorder output" >&2
  fi

  wait "${recorder_pid}"
  recorder_pid=""

  "${NETDIAG_BIN}" analyze "${output}" | tee "${analysis}"
}

highest_rtt() {
  local capture=$1
  python3 - "${capture}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    recording = json.load(f)

highest = 0.0
for sample in recording.get("samples", []):
    for socket in (sample.get("tcp_info") or {}).get("sockets") or []:
        highest = max(highest, float(socket.get("rtt_ms", 0)))
print(f"{highest:.1f}")
PY
}

expect_impaired_rtt_finding() {
  if grep -q "TCP RTT was elevated during the capture" "${impaired_analysis}"; then
    return
  fi
  local message="impaired capture did not report elevated TCP RTT; try increasing NETEM_DELAY or CLIENT_DURATION"
  if [[ ${STRICT} == "1" ]]; then
    echo "error: ${message}" >&2
    exit 1
  fi
  echo "warning: ${message}" >&2
}

expect_baseline_rtt_quiet() {
  if ! grep -q "TCP RTT was elevated during the capture" "${baseline_analysis}"; then
    return
  fi
  local message="baseline reported elevated TCP RTT; try running on a quieter host or lowering unrelated namespace traffic"
  if [[ ${STRICT} == "1" ]]; then
    echo "error: ${message}" >&2
    exit 1
  fi
  echo "warning: ${message}" >&2
}

ip netns add "${namespace}"
ip link add "${host_veth}" type veth peer name "${peer_veth}"
ip link set "${peer_veth}" netns "${namespace}"
ip address add "${host_address}/24" dev "${host_veth}"
ip link set "${host_veth}" up
ip -n "${namespace}" address add "${peer_address}/24" dev "${peer_veth}"
ip -n "${namespace}" link set lo up
ip -n "${namespace}" link set "${peer_veth}" up

start_server

echo "baseline output: ${baseline_output}"
run_capture "baseline" "${baseline_output}" "${baseline_analysis}"
baseline_rtt=$(highest_rtt "${baseline_output}")
echo "baseline highest TCP RTT: ${baseline_rtt} ms"

echo
echo "installing netem delay: ${NETEM_DELAY}"
tc qdisc replace dev "${host_veth}" root netem delay "${NETEM_DELAY}"
tc -s qdisc show dev "${host_veth}"

echo
echo "impaired output: ${impaired_output}"
run_capture "impaired" "${impaired_output}" "${impaired_analysis}"
impaired_rtt=$(highest_rtt "${impaired_output}")
echo "impaired highest TCP RTT: ${impaired_rtt} ms"

"${NETDIAG_BIN}" compare "${baseline_output}" "${impaired_output}" | tee "${comparison_output}"

expect_baseline_rtt_quiet
expect_impaired_rtt_finding
release_outputs

echo
echo "baseline capture: ${baseline_output}"
echo "baseline analysis: ${baseline_analysis}"
echo "impaired capture: ${impaired_output}"
echo "impaired analysis: ${impaired_analysis}"
echo "comparison: ${comparison_output}"
