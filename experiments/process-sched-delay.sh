#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
NETDIAG_BIN=${NETDIAG_BIN:-"${ROOT_DIR}/bin/netdiag"}
WORKLOAD_BIN=${WORKLOAD_BIN:-"${ROOT_DIR}/bin/netdiag-workload"}
OUTPUT_DIR=${1:-"${ROOT_DIR}"}
DURATION=${DURATION:-20s}
INTERVAL=${INTERVAL:-1s}
CLIENT_DURATION=${CLIENT_DURATION:-18s}
CONCURRENCY=${CONCURRENCY:-32}
BASELINE_CONCURRENCY=${BASELINE_CONCURRENCY:-4}
IMPAIRED_CONCURRENCY=${IMPAIRED_CONCURRENCY:-${CONCURRENCY}}
PAYLOAD_BYTES=${PAYLOAD_BYTES:-1048576}
TARGET_CPU=${TARGET_CPU:-}
BASELINE_CLIENT_CPU=${BASELINE_CLIENT_CPU:-}
IMPAIRED_CLIENT_CPU=${IMPAIRED_CLIENT_CPU:-}
STRICT=${STRICT:-0}

for command in taskset timeout; do
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

expand_cpu_list() {
  local list=$1
  local part start end cpu
  local -a expanded=()

  IFS=',' read -ra parts <<<"${list}"
  for part in "${parts[@]}"; do
    if [[ ${part} == *-* ]]; then
      start=${part%-*}
      end=${part#*-}
      for ((cpu = start; cpu <= end; cpu++)); do
        expanded+=("${cpu}")
      done
    else
      expanded+=("${part}")
    fi
  done

  printf '%s\n' "${expanded[@]}"
}

cpu_is_allowed() {
  local needle=$1
  local cpu
  for cpu in "${allowed_cpus[@]}"; do
    if [[ ${cpu} == "${needle}" ]]; then
      return 0
    fi
  done
  return 1
}

affinity_output=$(taskset -pc "$$")
affinity_list=${affinity_output##*: }
mapfile -t allowed_cpus < <(expand_cpu_list "${affinity_list}")
if (( ${#allowed_cpus[@]} < 2 )); then
  echo "this experiment needs at least two allowed CPUs so baseline client and selected process can be separated" >&2
  exit 1
fi

TARGET_CPU=${TARGET_CPU:-${allowed_cpus[1]}}
BASELINE_CLIENT_CPU=${BASELINE_CLIENT_CPU:-${allowed_cpus[0]}}
IMPAIRED_CLIENT_CPU=${IMPAIRED_CLIENT_CPU:-${TARGET_CPU}}

if ! cpu_is_allowed "${TARGET_CPU}"; then
  echo "TARGET_CPU=${TARGET_CPU} is outside allowed CPU list ${affinity_list}" >&2
  exit 1
fi
if ! cpu_is_allowed "${BASELINE_CLIENT_CPU}"; then
  echo "BASELINE_CLIENT_CPU=${BASELINE_CLIENT_CPU} is outside allowed CPU list ${affinity_list}" >&2
  exit 1
fi
if ! cpu_is_allowed "${IMPAIRED_CLIENT_CPU}"; then
  echo "IMPAIRED_CLIENT_CPU=${IMPAIRED_CLIENT_CPU} is outside allowed CPU list ${affinity_list}" >&2
  exit 1
fi
if (( BASELINE_CLIENT_CPU == TARGET_CPU )); then
  BASELINE_CLIENT_CPU=${allowed_cpus[0]}
  if (( BASELINE_CLIENT_CPU == TARGET_CPU )); then
    BASELINE_CLIENT_CPU=${allowed_cpus[1]}
  fi
  echo "BASELINE_CLIENT_CPU matched TARGET_CPU; using BASELINE_CLIENT_CPU=${BASELINE_CLIENT_CPU}" >&2
fi

mkdir -p "${OUTPUT_DIR}"
baseline_output="${OUTPUT_DIR}/process-sched-delay-baseline.json"
impaired_output="${OUTPUT_DIR}/process-sched-delay-impaired.json"
baseline_analysis="${OUTPUT_DIR}/process-sched-delay-baseline.txt"
impaired_analysis="${OUTPUT_DIR}/process-sched-delay-impaired.txt"

port=$((18080 + BASHPID % 10000))
server_pid=""
recorder_pid=""
burner_pid=""

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
}
trap cleanup EXIT INT TERM

wait_for_server() {
  local url=$1
  for _ in {1..30}; do
    if timeout 2s "${WORKLOAD_BIN}" client --url "${url}" --duration 100ms --concurrency 1 >/dev/null 2>&1; then
      return
    fi
    sleep 0.1
  done
  echo "workload server did not become ready" >&2
  exit 1
}

run_capture() {
  local label=$1
  local output=$2
  local analysis=$3
  local with_burner=$4
  local client_cpu=$5
  local concurrency=$6
  local url="http://127.0.0.1:${port}/payload"

  burner_pid=""
  if [[ ${with_burner} == "yes" ]]; then
    taskset -c "${TARGET_CPU}" bash -c 'while :; do :; done' &
    burner_pid=$!
    sleep 0.2
  fi

  echo "recording ${label} capture for pid ${server_pid}; target CPU ${TARGET_CPU}, client CPU ${client_cpu}, concurrency ${concurrency}"
  "${NETDIAG_BIN}" record \
    --duration "${DURATION}" \
    --interval "${INTERVAL}" \
    --max-samples 3600 \
    --pid "${server_pid}" \
    --ebpf=false \
    --output "${output}" &
  recorder_pid=$!

  sleep 1
  taskset -c "${client_cpu}" "${WORKLOAD_BIN}" client \
    --url "${url}" \
    --duration "${CLIENT_DURATION}" \
    --concurrency "${concurrency}"

  wait "${recorder_pid}"
  recorder_pid=""

  if [[ -n ${burner_pid} ]]; then
    kill "${burner_pid}" >/dev/null 2>&1 || true
    wait "${burner_pid}" >/dev/null 2>&1 || true
    burner_pid=""
  fi

  "${NETDIAG_BIN}" analyze "${output}" | tee "${analysis}"
}

set_server_affinity() {
  local cpu_list=$1
  if ! taskset -pc "${cpu_list}" "${server_pid}" >/dev/null; then
    echo "failed to set server affinity to ${cpu_list}" >&2
    exit 1
  fi
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

"${WORKLOAD_BIN}" server \
  --listen "127.0.0.1:${port}" \
  --payload-bytes "${PAYLOAD_BYTES}" >/dev/null 2>&1 &
server_pid=$!
wait_for_server "http://127.0.0.1:${port}/payload"

echo "baseline output: ${baseline_output}"
set_server_affinity "${affinity_list}"
run_capture "baseline" "${baseline_output}" "${baseline_analysis}" "no" "${BASELINE_CLIENT_CPU}" "${BASELINE_CONCURRENCY}"

echo
echo "impaired output: ${impaired_output}"
set_server_affinity "${TARGET_CPU}"
run_capture "impaired" "${impaired_output}" "${impaired_analysis}" "yes" "${IMPAIRED_CLIENT_CPU}" "${IMPAIRED_CONCURRENCY}"

finding="Selected process accumulated runqueue wait time"
expect_absent "${baseline_analysis}" "${finding}" "baseline reported selected-process runqueue wait; try reducing BASELINE_CONCURRENCY or using a quieter host"
expect_present "${impaired_analysis}" "${finding}" "impaired capture did not report selected-process runqueue wait; try increasing IMPAIRED_CONCURRENCY, CLIENT_DURATION, PAYLOAD_BYTES, or choose another TARGET_CPU"

echo
echo "baseline capture: ${baseline_output}"
echo "baseline analysis: ${baseline_analysis}"
echo "impaired capture: ${impaired_output}"
echo "impaired analysis: ${impaired_analysis}"
