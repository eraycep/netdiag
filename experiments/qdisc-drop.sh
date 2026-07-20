#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "this experiment must run as root" >&2
  exit 1
fi

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
NETDIAG_BIN=${NETDIAG_BIN:-"${ROOT_DIR}/bin/netdiag"}
OUTPUT_DIR=${1:-"${ROOT_DIR}"}
DURATION=${DURATION:-20s}
INTERVAL=${INTERVAL:-1s}
CLIENT_DURATION=${CLIENT_DURATION:-18}
CLIENT_TIMEOUT_GRACE=${CLIENT_TIMEOUT_GRACE:-10}
CLIENT_REQUEST_TIMEOUT=${CLIENT_REQUEST_TIMEOUT:-2}
CONCURRENCY=${CONCURRENCY:-32}
PAYLOAD_BYTES=${PAYLOAD_BYTES:-4194304}
NETEM_LIMIT=${NETEM_LIMIT:-1}
NETEM_DELAY=${NETEM_DELAY:-100ms}
STRICT=${STRICT:-0}

for command in ip tc python3 timeout; do
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
baseline_output="${OUTPUT_DIR}/qdisc-drop-baseline.json"
impaired_output="${OUTPUT_DIR}/qdisc-drop-impaired.json"
baseline_analysis="${OUTPUT_DIR}/qdisc-drop-baseline.txt"
impaired_analysis="${OUTPUT_DIR}/qdisc-drop-impaired.txt"

suffix=$((BASHPID % 100000))
octet=$((BASHPID % 200 + 20))
namespace="netdiag-qdisc-${BASHPID}"
host_veth="ndh${suffix}"
peer_veth="ndp${suffix}"
host_address="198.20.${octet}.1"
peer_address="198.20.${octet}.2"
server_dir=""
server_pid=""
recorder_pid=""

release_outputs() {
  local file
  for file in "${baseline_output}" "${impaired_output}" "${baseline_analysis}" "${impaired_analysis}"; do
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
  if [[ -n ${server_dir} ]]; then
    rm -rf "${server_dir}"
  fi
  release_outputs
}
trap cleanup EXIT INT TERM

run_capture() {
  local label=$1
  local output=$2
  local analysis=$3

  echo "recording ${label} capture on ${host_veth}"
  "${NETDIAG_BIN}" record \
    --duration "${DURATION}" \
    --interval "${INTERVAL}" \
    --max-samples 3600 \
    --interface "${host_veth}" \
    --output "${output}" &
  recorder_pid=$!

  sleep 1
  local client_status=0
  timeout "$((CLIENT_DURATION + CLIENT_TIMEOUT_GRACE))s" \
    ip netns exec "${namespace}" env CLIENT_REQUEST_TIMEOUT="${CLIENT_REQUEST_TIMEOUT}" \
    python3 "${ROOT_DIR}/experiments/cpu_contention_client.py" \
    "http://${host_address}:18080/payload.bin" "${CLIENT_DURATION}" "${CONCURRENCY}" || client_status=$?
  if (( client_status != 0 )); then
    echo "warning: ${label} client exited with status ${client_status}; continuing to analyze recorder output" >&2
  fi

  wait "${recorder_pid}"
  recorder_pid=""

  "${NETDIAG_BIN}" analyze "${output}" | tee "${analysis}"
}

qdisc_totals() {
  local capture=$1
  python3 - "${capture}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    recording = json.load(f)

samples = recording.get("samples", [])
if not samples:
    print("0 0 0")
    raise SystemExit

qdiscs = samples[-1].get("qdisc", {}).get("qdiscs") or []
drops = sum(int(q.get("drops", 0)) for q in qdiscs)
overlimits = sum(int(q.get("overlimits", 0)) for q in qdiscs)
backlog_packets = sum(int(q.get("backlog_packets", 0)) for q in qdiscs)
print(drops, overlimits, backlog_packets)
PY
}

expect_baseline_quiet() {
  local drops=$1
  local overlimits=$2
  if (( drops > 0 || overlimits > 0 )); then
    local message="baseline qdisc counters were not quiet: drops=${drops}, overlimits=${overlimits}"
    if [[ ${STRICT} == "1" ]]; then
      echo "error: ${message}" >&2
      exit 1
    fi
    echo "warning: ${message}" >&2
  fi
}

expect_impaired_drops() {
  local drops=$1
  local overlimits=$2
  if (( drops == 0 && overlimits == 0 )); then
    local message="impaired qdisc counters did not increase; try increasing CONCURRENCY, PAYLOAD_BYTES, NETEM_DELAY or reducing NETEM_LIMIT"
    if [[ ${STRICT} == "1" ]]; then
      echo "error: ${message}" >&2
      exit 1
    fi
    echo "warning: ${message}" >&2
  fi
}

ip netns add "${namespace}"
ip link add "${host_veth}" type veth peer name "${peer_veth}"
ip link set "${peer_veth}" netns "${namespace}"
ip address add "${host_address}/24" dev "${host_veth}"
ip link set "${host_veth}" up
ip -n "${namespace}" address add "${peer_address}/24" dev "${peer_veth}"
ip -n "${namespace}" link set lo up
ip -n "${namespace}" link set "${peer_veth}" up

server_dir=$(mktemp -d /tmp/netdiag-qdisc-server.XXXXXX)
python3 - "${server_dir}/payload.bin" "${PAYLOAD_BYTES}" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
size = int(sys.argv[2])
path.write_bytes(b"x" * size)
PY

python3 -m http.server 18080 \
  --bind "${host_address}" --directory "${server_dir}" >/dev/null 2>&1 &
server_pid=$!
sleep 0.5
if ! kill -0 "${server_pid}" >/dev/null 2>&1; then
  echo "HTTP server failed to start on ${host_address}" >&2
  exit 1
fi

echo "baseline output: ${baseline_output}"
run_capture "baseline" "${baseline_output}" "${baseline_analysis}"
read -r baseline_drops baseline_overlimits baseline_backlog < <(qdisc_totals "${baseline_output}")
echo "baseline qdisc totals: drops=${baseline_drops}, overlimits=${baseline_overlimits}, backlog_packets=${baseline_backlog}"

echo
echo "installing netem qdisc: limit ${NETEM_LIMIT}, delay ${NETEM_DELAY}"
tc qdisc replace dev "${host_veth}" root netem limit "${NETEM_LIMIT}" delay "${NETEM_DELAY}"
tc -s qdisc show dev "${host_veth}"

echo
echo "impaired output: ${impaired_output}"
run_capture "impaired" "${impaired_output}" "${impaired_analysis}"
read -r impaired_drops impaired_overlimits impaired_backlog < <(qdisc_totals "${impaired_output}")
echo "impaired qdisc totals: drops=${impaired_drops}, overlimits=${impaired_overlimits}, backlog_packets=${impaired_backlog}"

expect_baseline_quiet "${baseline_drops}" "${baseline_overlimits}"
expect_impaired_drops "${impaired_drops}" "${impaired_overlimits}"

release_outputs

echo
echo "baseline capture: ${baseline_output}"
echo "baseline analysis: ${baseline_analysis}"
echo "impaired capture: ${impaired_output}"
echo "impaired analysis: ${impaired_analysis}"
