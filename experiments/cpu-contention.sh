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
CONCURRENCY=${CONCURRENCY:-16}
TARGET_CPU=${TARGET_CPU:-1}
CLIENT_CPU=${CLIENT_CPU:-0}
BASELINE_CLIENT_CPU=${BASELINE_CLIENT_CPU:-${CLIENT_CPU}}
IMPAIRED_CLIENT_CPU=${IMPAIRED_CLIENT_CPU:-${TARGET_CPU}}
PAYLOAD_BYTES=${PAYLOAD_BYTES:-1048576}
STRICT=${STRICT:-0}

for command in ip python3 taskset nproc; do
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

cpu_count=$(nproc)
if (( cpu_count < 2 )); then
  echo "this experiment needs at least two CPUs so load and client traffic can be separated" >&2
  exit 1
fi
if (( TARGET_CPU < 0 || TARGET_CPU >= cpu_count )); then
  echo "TARGET_CPU=${TARGET_CPU} is outside available CPU range 0-$((cpu_count - 1))" >&2
  exit 1
fi
if (( BASELINE_CLIENT_CPU < 0 || BASELINE_CLIENT_CPU >= cpu_count )); then
  echo "BASELINE_CLIENT_CPU=${BASELINE_CLIENT_CPU} is outside available CPU range 0-$((cpu_count - 1))" >&2
  exit 1
fi
if (( IMPAIRED_CLIENT_CPU < 0 || IMPAIRED_CLIENT_CPU >= cpu_count )); then
  echo "IMPAIRED_CLIENT_CPU=${IMPAIRED_CLIENT_CPU} is outside available CPU range 0-$((cpu_count - 1))" >&2
  exit 1
fi
if (( BASELINE_CLIENT_CPU == TARGET_CPU )); then
  BASELINE_CLIENT_CPU=$(((TARGET_CPU + 1) % cpu_count))
  echo "BASELINE_CLIENT_CPU matched TARGET_CPU; using BASELINE_CLIENT_CPU=${BASELINE_CLIENT_CPU}" >&2
fi

mkdir -p "${OUTPUT_DIR}"
baseline_output="${OUTPUT_DIR}/cpu-contention-baseline.json"
impaired_output="${OUTPUT_DIR}/cpu-contention-impaired.json"
baseline_analysis="${OUTPUT_DIR}/cpu-contention-baseline.txt"
impaired_analysis="${OUTPUT_DIR}/cpu-contention-impaired.txt"

suffix=$((BASHPID % 100000))
octet=$((BASHPID % 200 + 20))
namespace="netdiag-cpu-${BASHPID}"
host_veth="ndh${suffix}"
peer_veth="ndp${suffix}"
host_address="198.19.${octet}.1"
peer_address="198.19.${octet}.2"
server_dir=""
server_pid=""
recorder_pid=""
burner_pid=""
rps_file=""

cpu_mask_hex() {
  python3 - "$1" <<'PY'
import sys

cpu = int(sys.argv[1])
chunks = [0] * (cpu // 32 + 1)
chunks[cpu // 32] = 1 << (cpu % 32)
print(",".join(f"{chunk:x}" for chunk in reversed(chunks)))
PY
}

cleanup() {
  if [[ -n ${recorder_pid} ]]; then
    kill "${recorder_pid}" >/dev/null 2>&1 || true
    wait "${recorder_pid}" >/dev/null 2>&1 || true
  fi
  if [[ -n ${burner_pid} ]]; then
    kill "${burner_pid}" >/dev/null 2>&1 || true
    wait "${burner_pid}" >/dev/null 2>&1 || true
  fi
  if [[ -n ${server_pid} ]]; then
    kill "${server_pid}" >/dev/null 2>&1 || true
    wait "${server_pid}" >/dev/null 2>&1 || true
  fi
  ip netns del "${namespace}" >/dev/null 2>&1 || true
  ip link del "${host_veth}" >/dev/null 2>&1 || true
  if [[ -n ${server_dir} ]]; then
    rm -rf "${server_dir}"
  fi
}
trap cleanup EXIT INT TERM

run_capture() {
  local label=$1
  local output=$2
  local analysis=$3
  local with_burner=$4
  local client_cpu=$5

  burner_pid=""
  if [[ ${with_burner} == "yes" ]]; then
    taskset -c "${TARGET_CPU}" bash -c 'while :; do :; done' &
    burner_pid=$!
    sleep 0.2
  fi

  echo "recording ${label} capture on ${host_veth}; target CPU ${TARGET_CPU}, client CPU ${client_cpu}"
  "${NETDIAG_BIN}" record \
    --duration "${DURATION}" \
    --interval "${INTERVAL}" \
    --max-samples 3600 \
    --interface "${host_veth}" \
    --output "${output}" &
  recorder_pid=$!

  sleep 1
  taskset -c "${client_cpu}" python3 "${ROOT_DIR}/experiments/cpu_contention_client.py" \
    "http://${peer_address}:18080/payload.bin" "${CLIENT_DURATION}" "${CONCURRENCY}"

  wait "${recorder_pid}"
  recorder_pid=""

  if [[ -n ${burner_pid} ]]; then
    kill "${burner_pid}" >/dev/null 2>&1 || true
    wait "${burner_pid}" >/dev/null 2>&1 || true
    burner_pid=""
  fi

  "${NETDIAG_BIN}" analyze "${output}" | tee "${analysis}"
}

expect_absent() {
  local file=$1
  local pattern=$2
  local message=$3
  if grep -q "${pattern}" "${file}"; then
    if [[ ${STRICT} == "1" ]]; then
      echo "error: ${message}" >&2
      exit 1
    fi
    echo "warning: ${message}" >&2
  fi
}

expect_present() {
  local file=$1
  local pattern=$2
  local message=$3
  if ! grep -q "${pattern}" "${file}"; then
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

target_mask=$(cpu_mask_hex "${TARGET_CPU}")
steered=0
for rps_file in "/sys/class/net/${host_veth}"/queues/rx-*/rps_cpus; do
  if [[ -w ${rps_file} ]]; then
    printf '%s\n' "${target_mask}" >"${rps_file}"
    steered=1
  fi
done
for xps_file in "/sys/class/net/${host_veth}"/queues/tx-*/xps_cpus; do
  if [[ -w ${xps_file} ]]; then
    printf '%s\n' "${target_mask}" >"${xps_file}"
    steered=1
  fi
done
if (( steered == 1 )); then
  echo "steered ${host_veth} queue processing toward CPU ${TARGET_CPU} with mask ${target_mask}"
else
  echo "warning: cannot write ${host_veth} RPS/XPS masks; receive CPU concentration may be less deterministic" >&2
fi

server_dir=$(mktemp -d /tmp/netdiag-cpu-server.XXXXXX)
python3 - "${server_dir}/payload.bin" "${PAYLOAD_BYTES}" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
size = int(sys.argv[2])
path.write_bytes(b"x" * size)
PY

ip netns exec "${namespace}" taskset -c "${TARGET_CPU}" python3 -m http.server 18080 \
  --bind "${peer_address}" --directory "${server_dir}" >/dev/null 2>&1 &
server_pid=$!
sleep 0.5
if ! kill -0 "${server_pid}" >/dev/null 2>&1; then
  echo "HTTP server failed to start in the network namespace" >&2
  exit 1
fi

echo "baseline output: ${baseline_output}"
run_capture "baseline" "${baseline_output}" "${baseline_analysis}" "no" "${BASELINE_CLIENT_CPU}"

echo
echo "impaired output: ${impaired_output}"
run_capture "impaired" "${impaired_output}" "${impaired_analysis}" "yes" "${IMPAIRED_CLIENT_CPU}"

finding="Network receive processing was concentrated on a busy CPU"
expect_absent "${baseline_analysis}" "${finding}" "baseline reported CPU concentration; try reducing CONCURRENCY or using a quieter host"
expect_present "${impaired_analysis}" "${finding}" "impaired capture did not report CPU concentration; try increasing CONCURRENCY, CLIENT_DURATION, PAYLOAD_BYTES, or choose another TARGET_CPU"

if [[ -n ${SUDO_UID:-} && -n ${SUDO_GID:-} ]]; then
  chown "${SUDO_UID}:${SUDO_GID}" \
    "${baseline_output}" "${impaired_output}" "${baseline_analysis}" "${impaired_analysis}"
fi

echo
echo "baseline capture: ${baseline_output}"
echo "baseline analysis: ${baseline_analysis}"
echo "impaired capture: ${impaired_output}"
echo "impaired analysis: ${impaired_analysis}"
