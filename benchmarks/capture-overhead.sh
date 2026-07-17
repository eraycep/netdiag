#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
NETDIAG_BIN=${NETDIAG_BIN:-"${ROOT_DIR}/bin/netdiag"}
RESULTS=${1:-"${ROOT_DIR}/benchmarks/results/capture-overhead.tsv"}
DURATION_SECONDS=${DURATION_SECONDS:-10}
REPETITIONS=${REPETITIONS:-3}
INTERVALS=${INTERVALS:-"100ms 500ms 1s"}
EBPF=${EBPF:-false}
INTERFACE=${INTERFACE:-}
TIME_BIN=${TIME_BIN:-/usr/bin/time}

if [[ ! -x ${NETDIAG_BIN} ]]; then
  echo "netdiag binary not found or not executable: ${NETDIAG_BIN}" >&2
  echo "run 'make build' first or set NETDIAG_BIN" >&2
  exit 1
fi
if [[ ! -x ${TIME_BIN} ]]; then
  echo "GNU time not found at ${TIME_BIN}" >&2
  exit 1
fi
if ! [[ ${DURATION_SECONDS} =~ ^[1-9][0-9]*$ ]]; then
  echo "DURATION_SECONDS must be a positive integer" >&2
  exit 1
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
work_dir=$(mktemp -d /tmp/netdiag-benchmark.XXXXXX)
cleanup() {
  rm -rf "${work_dir}"
}
trap cleanup EXIT INT TERM

{
  printf '# generated_at_utc\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '# hostname\t%s\n' "$(hostname)"
  printf '# kernel\t%s\n' "$(uname -r)"
  printf '# duration_seconds\t%s\n' "${DURATION_SECONDS}"
  printf '# repetitions\t%s\n' "${REPETITIONS}"
  printf '# ebpf\t%s\n' "${EBPF}"
  printf '# interface\t%s\n' "${INTERFACE:-none}"
  printf 'interval\trun\twall_seconds\tuser_seconds\tsystem_seconds\tcpu_percent\tmax_rss_kib\tsamples\toutput_bytes\tbytes_per_sample\n'
} >"${RESULTS}"

for interval in ${INTERVALS}; do
  for ((run = 1; run <= REPETITIONS; run++)); do
    capture="${work_dir}/capture-${interval}-${run}.json"
    timing="${work_dir}/time-${interval}-${run}.txt"

    record_args=(
      record
      --duration "${DURATION_SECONDS}s"
      --interval "${interval}"
      --max-samples 1000000
      --ebpf="${EBPF}"
      --output "${capture}"
    )
    if [[ -n ${INTERFACE} ]]; then
      record_args+=(--interface "${INTERFACE}")
    fi

    "${TIME_BIN}" -f '%e\t%U\t%S\t%M' -o "${timing}" \
      "${NETDIAG_BIN}" "${record_args[@]}" >/dev/null

    IFS=$'\t' read -r wall user system max_rss <"${timing}"
    samples=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["samples"]))' "${capture}")
    output_bytes=$(stat -c '%s' "${capture}")
    cpu_percent=$(awk -v user_cpu="${user}" -v sys_cpu="${system}" -v wall="${wall}" 'BEGIN { printf "%.3f", 100 * (user_cpu + sys_cpu) / wall }')
    bytes_per_sample=$(awk -v bytes="${output_bytes}" -v samples="${samples}" 'BEGIN { printf "%.1f", bytes / samples }')

    printf '%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "${interval}" "${run}" "${wall}" "${user}" "${system}" \
      "${cpu_percent}" "${max_rss}" "${samples}" "${output_bytes}" \
      "${bytes_per_sample}" >>"${RESULTS}"
    echo "${interval} run ${run}/${REPETITIONS}: CPU ${cpu_percent}%, RSS ${max_rss} KiB, ${output_bytes} bytes"
  done
done

echo
python3 "${ROOT_DIR}/benchmarks/summarize_capture_overhead.py" "${RESULTS}"
echo "raw results: ${RESULTS}"
