# Makefile for ebpf-tcx-filter
#
# System build dependencies (Debian/Ubuntu):
#   sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r)
#
# Go tool dependency (bpf2go) is declared in go.mod and installed via:
#   go get -tool github.com/cilium/ebpf/cmd/bpf2go
#
# Running the binary requires root privileges (eBPF program loading).

BINARY       := ebpf-tcx-filter
INSTALL_DIR  := /usr/local/bin
BPF2GO       := $(shell go env GOPATH)/bin/bpf2go

# Default target
.PHONY: all
all: generate build

# ── Dependencies ─────────────────────────────────────────────────────────────

# Install system packages (Debian/Ubuntu) and the bpf2go Go tool
.PHONY: deps
deps: apt-deps bpf2go

# Install clang / llvm / libbpf / kernel headers
.PHONY: apt-deps
apt-deps:
	sudo apt install -y clang llvm libbpf-dev linux-headers-$(shell uname -r)

# Install bpf2go as a tracked Go tool (declared in go.mod via `tool` directive)
.PHONY: bpf2go
bpf2go:
	go get -tool github.com/cilium/ebpf/cmd/bpf2go
	go mod tidy

# ── Code generation ───────────────────────────────────────────────────────────

# Compile tcx.c with bpf2go → bpf_bpfel.go / bpf_bpfeb.go
.PHONY: generate
generate:
	go generate ./...

# ── Build ─────────────────────────────────────────────────────────────────────

# Build the Go binary (Linux only, static, no CGO)
.PHONY: build
build:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags linux -o $(BINARY) .

# ── Install ───────────────────────────────────────────────────────────────────

# Build and install to INSTALL_DIR (requires sudo)
.PHONY: install
install: build
	@echo "Installing $(BINARY) to $(INSTALL_DIR) ..."
	sudo install -m 0755 $(BINARY) $(INSTALL_DIR)/$(BINARY)
	@echo "Done. Run with: sudo $(BINARY) <interface>"

# ── Run ───────────────────────────────────────────────────────────────────────

# Build and run with sudo — requires IFACE=<interface>, e.g. make run IFACE=eth0
.PHONY: run
run: build
	@if [ -z "$(IFACE)" ]; then \
		echo "Usage: make run IFACE=<network_interface>"; \
		exit 1; \
	fi
	sudo ./$(BINARY) $(IFACE)

# ── Clean ─────────────────────────────────────────────────────────────────────

# Remove the compiled binary
.PHONY: clean
clean:
	rm -f $(BINARY)

# Remove binary and all bpf2go-generated files
.PHONY: cleanall
cleanall: clean
	rm -f bpf_bpfel.go bpf_bpfel.o bpf_bpfeb.go bpf_bpfeb.o

# ── Help ──────────────────────────────────────────────────────────────────────

.PHONY: help
help:
	@echo ""
	@echo "Usage: make [target] [IFACE=<interface>]"
	@echo ""
	@echo "Targets:"
	@echo "  all        Generate eBPF bindings + build binary (default)"
	@echo "  deps       Install all dependencies: apt packages + bpf2go tool"
	@echo "  apt-deps   Install system packages (clang, llvm, libbpf-dev, linux-headers)"
	@echo "  bpf2go     Install bpf2go Go tool (tracked in go.mod)"
	@echo "  generate   Compile tcx.c with bpf2go (go generate)"
	@echo "  build      Build the Go binary"
	@echo "  install    Build and install to $(INSTALL_DIR) (uses sudo)"
	@echo "  run        Build and run with sudo  (IFACE=<iface> required)"
	@echo "  clean      Remove compiled binary"
	@echo "  cleanall   Remove binary and generated eBPF files"
	@echo ""
