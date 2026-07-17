.PHONY: build test test-integration experiment-loss benchmark fmt generate

build:
	go build -buildvcs=false -o bin/netdiag ./cmd/netdiag

test:
	go test ./...

test-integration:
	@tmp=$$(mktemp /tmp/netdiag-ebpf-integration.XXXXXX); \
	trap 'rm -f "$$tmp"' EXIT; \
	go test -c -o "$$tmp" ./internal/ebpfcollector; \
	sudo env NETDIAG_ROOT_TESTS=1 "$$tmp" -test.run='^TestTCPRetransmitIntegration$$' -test.v

experiment-loss: build
	sudo env NETDIAG_BIN="$(CURDIR)/bin/netdiag" bash experiments/tcp-loss.sh "$(CURDIR)/loss-capture.json"

benchmark: build
	NETDIAG_BIN="$(CURDIR)/bin/netdiag" bash benchmarks/capture-overhead.sh

fmt:
	gofmt -w cmd internal

generate:
	go generate ./internal/ebpfcollector
