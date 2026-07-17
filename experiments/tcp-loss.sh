#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "this experiment must run as root" >&2
  exit 1
fi

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
NETDIAG_BIN=${NETDIAG_BIN:-"${ROOT_DIR}/bin/netdiag"}
OUTPUT=${1:-"${ROOT_DIR}/loss-capture.json"}
DURATION=${DURATION:-20s}
INTERVAL=${INTERVAL:-1s}
LOSS_PERCENT=${LOSS_PERCENT:-10%}
NETEM_SEED=${NETEM_SEED:-42}
REQUESTS=${REQUESTS:-100}

for command in ip tc python3; do
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

suffix=$((BASHPID % 100000))
octet=$((BASHPID % 200 + 20))
namespace="netdiag-loss-${BASHPID}"
host_veth="ndh${suffix}"
peer_veth="ndp${suffix}"
host_address="198.18.${octet}.1"
peer_address="198.18.${octet}.2"
server_pid=""
recorder_pid=""
netem_error=""

cleanup() {
  if [[ -n ${recorder_pid} ]]; then
    kill "${recorder_pid}" >/dev/null 2>&1 || true
    wait "${recorder_pid}" >/dev/null 2>&1 || true
  fi
  if [[ -n ${server_pid} ]]; then
    kill "${server_pid}" >/dev/null 2>&1 || true
    wait "${server_pid}" >/dev/null 2>&1 || true
  fi
  if [[ -n ${netem_error} ]]; then
    rm -f "${netem_error}"
  fi
  ip netns del "${namespace}" >/dev/null 2>&1 || true
  ip link del "${host_veth}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

ip netns add "${namespace}"
ip link add "${host_veth}" type veth peer name "${peer_veth}"
ip link set "${peer_veth}" netns "${namespace}"
ip address add "${host_address}/24" dev "${host_veth}"
ip link set "${host_veth}" up
ip -n "${namespace}" address add "${peer_address}/24" dev "${peer_veth}"
ip -n "${namespace}" link set lo up
ip -n "${namespace}" link set "${peer_veth}" up

ip netns exec "${namespace}" python3 -m http.server 18080 \
  --bind "${peer_address}" >/dev/null 2>&1 &
server_pid=$!
sleep 0.5
if ! kill -0 "${server_pid}" >/dev/null 2>&1; then
  echo "HTTP server failed to start in the network namespace" >&2
  exit 1
fi

netem_error=$(mktemp /tmp/netdiag-netem.XXXXXX)
if tc qdisc replace dev "${host_veth}" root netem \
  loss "${LOSS_PERCENT}" seed "${NETEM_SEED}" 2>"${netem_error}"; then
  echo "using netem random seed ${NETEM_SEED}"
elif grep -q 'What is "seed"' "${netem_error}"; then
  echo "warning: this iproute2 version does not support a netem seed; using unseeded loss" >&2
  tc qdisc replace dev "${host_veth}" root netem loss "${LOSS_PERCENT}"
else
  cat "${netem_error}" >&2
  rm -f "${netem_error}"
  exit 1
fi
rm -f "${netem_error}"
netem_error=""

echo "recording ${DURATION} with ${LOSS_PERCENT} loss on ${host_veth}"
"${NETDIAG_BIN}" record \
  --duration "${DURATION}" \
  --interval "${INTERVAL}" \
  --max-samples 3600 \
  --interface "${host_veth}" \
  --output "${OUTPUT}" &
recorder_pid=$!

sleep 1
python3 "${ROOT_DIR}/experiments/tcp_loss_client.py" \
  "http://${peer_address}:18080/" "${REQUESTS}"

wait "${recorder_pid}"
recorder_pid=""

if [[ -n ${SUDO_UID:-} && -n ${SUDO_GID:-} ]]; then
  chown "${SUDO_UID}:${SUDO_GID}" "${OUTPUT}"
fi

echo
echo "capture: ${OUTPUT}"
"${NETDIAG_BIN}" analyze "${OUTPUT}"
