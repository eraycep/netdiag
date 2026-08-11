.PHONY: build test test-integration experiment-loss experiment-cpu-contention experiment-qdisc-drop experiment-rx-queue experiment-process-sched-delay benchmark benchmark-ebpf benchmark-workload-impact fmt generate

build:
	go build -buildvcs=false -o bin/netdiag ./cmd/netdiag
	go build -buildvcs=false -o bin/netdiag-workload ./cmd/netdiag-workload

test:
	go test ./...

test-integration:
	@tmp=$$(mktemp /tmp/netdiag-ebpf-integration.XXXXXX); \
	trap 'rm -f "$$tmp"' EXIT; \
	go test -c -o "$$tmp" ./internal/ebpfcollector; \
	sudo env NETDIAG_ROOT_TESTS=1 "$$tmp" -test.run='^TestTCPRetransmitIntegration$$' -test.v

experiment-loss: build
	sudo env NETDIAG_BIN="$(CURDIR)/bin/netdiag" bash experiments/tcp-loss.sh "$(CURDIR)/loss-capture.json"

experiment-cpu-contention: build
	sudo env NETDIAG_BIN="$(CURDIR)/bin/netdiag" bash experiments/cpu-contention.sh "$(CURDIR)"

experiment-qdisc-drop: build
	sudo env NETDIAG_BIN="$(CURDIR)/bin/netdiag" bash experiments/qdisc-drop.sh "$(CURDIR)"

experiment-rx-queue: build
	NETDIAG_BIN="$(CURDIR)/bin/netdiag" bash experiments/tcp-rx-queue.sh "$(CURDIR)"

experiment-process-sched-delay: build
	NETDIAG_BIN="$(CURDIR)/bin/netdiag" WORKLOAD_BIN="$(CURDIR)/bin/netdiag-workload" bash experiments/process-sched-delay.sh "$(CURDIR)"

benchmark: build
	NETDIAG_BIN="$(CURDIR)/bin/netdiag" bash benchmarks/capture-overhead.sh

benchmark-ebpf: build
	sudo env NETDIAG_BIN="$(CURDIR)/bin/netdiag" EBPF=true DURATION_SECONDS=30 REPETITIONS=5 bash benchmarks/capture-overhead.sh "$(CURDIR)/benchmarks/results/capture-overhead-ebpf.tsv"

benchmark-workload-impact: build
	sudo env NETDIAG_BIN="$(CURDIR)/bin/netdiag" bash benchmarks/workload-impact.sh "$(CURDIR)/benchmarks/results/workload-impact.tsv"

fmt:
	gofmt -w cmd internal

generate:
	GOCACHE="$${GOCACHE:-/tmp/netdiag-go-cache}" go generate ./internal/ebpfcollector
