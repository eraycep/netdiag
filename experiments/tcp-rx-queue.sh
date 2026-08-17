#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
NETDIAG_BIN=${NETDIAG_BIN:-"${ROOT_DIR}/bin/netdiag"}
OUTPUT_DIR=${1:-"${ROOT_DIR}"}
DURATION=${DURATION:-10s}
INTERVAL=${INTERVAL:-500ms}
PAYLOAD_BYTES=${PAYLOAD_BYTES:-16777216}
SERVER_SLEEP=${SERVER_SLEEP:-8}
CLIENT_TIMEOUT=${CLIENT_TIMEOUT:-0.2}
MAX_TCP_SOCKET_QUEUES=${MAX_TCP_SOCKET_QUEUES:-16}

if ! command -v python3 >/dev/null 2>&1; then
  echo "required command not found: python3" >&2
  exit 1
fi
if [[ ! -x ${NETDIAG_BIN} ]]; then
  echo "netdiag binary not found or not executable: ${NETDIAG_BIN}" >&2
  echo "run 'make build' first or set NETDIAG_BIN" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"
capture="${OUTPUT_DIR}/tcp-rx-queue.json"
analysis="${OUTPUT_DIR}/tcp-rx-queue.txt"
recorder_pid=""

cleanup() {
  if [[ -n ${recorder_pid} ]]; then
    kill "${recorder_pid}" >/dev/null 2>&1 || true
    wait "${recorder_pid}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

echo "recording ${DURATION} while a local TCP server accepts but does not read"
"${NETDIAG_BIN}" record \
  --duration "${DURATION}" \
  --interval "${INTERVAL}" \
  --max-samples 3600 \
  --max-tcp-socket-queues "${MAX_TCP_SOCKET_QUEUES}" \
  --ebpf=false \
  --output "${capture}" &
recorder_pid=$!

sleep 1
python3 - "${PAYLOAD_BYTES}" "${SERVER_SLEEP}" "${CLIENT_TIMEOUT}" <<'PY'
import queue
import socket
import sys
import threading
import time

payload_bytes = int(sys.argv[1])
server_sleep = float(sys.argv[2])
client_timeout = float(sys.argv[3])
chunk = b"x" * 65536
port_queue = queue.Queue(maxsize=1)

def server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port_queue.put(listener.getsockname()[1])
        conn, _ = listener.accept()
        with conn:
            time.sleep(server_sleep)

thread = threading.Thread(target=server, daemon=True)
thread.start()
port = port_queue.get(timeout=2)

sent = 0
timeouts = 0
deadline = time.monotonic() + server_sleep
with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
    client.settimeout(client_timeout)
    while sent < payload_bytes and time.monotonic() < deadline:
        try:
            sent += client.send(chunk[: min(len(chunk), payload_bytes - sent)])
        except socket.timeout:
            timeouts += 1
            time.sleep(0.05)
        except (BrokenPipeError, ConnectionResetError):
            break

thread.join(timeout=server_sleep + 1)
print(f"client sent {sent} bytes; send timeouts {timeouts}")
PY

wait "${recorder_pid}"
recorder_pid=""

"${NETDIAG_BIN}" analyze "${capture}" | tee "${analysis}"

if ! grep -q "TCP socket receive queues grew during the capture" "${analysis}"; then
  echo "warning: socket receive queue finding was not reported; try increasing PAYLOAD_BYTES or SERVER_SLEEP" >&2
fi
if ! grep -q "Top TCP socket receive queue" "${analysis}"; then
  echo "warning: top TCP socket receive queue evidence was not reported; check MAX_TCP_SOCKET_QUEUES or whether queues cleared between samples" >&2
fi

echo
echo "capture: ${capture}"
echo "analysis: ${analysis}"
