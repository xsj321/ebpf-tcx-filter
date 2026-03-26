# ebpf-tcx-filter

An eBPF-based network packet filter and monitor using **Linux TCX** (Traffic Control with eBPF).  
It attaches eBPF programs to a network interface to capture, count, and inspect ingress/egress packets in real time, and exposes a live web dashboard.

> **Requires Linux kernel 6.6 or newer** (TCX `bpf_link` support).  
> **Root privileges are required** to load eBPF programs.

---

## Features

- Attaches eBPF programs to a network interface via TCX hooks (ingress & egress)
- Counts ingress and egress packets in kernel space
- Captures packet metadata (protocol, VLAN, direction, length, etc.) via ring buffer
- Live web dashboard served over HTTP

---

## Prerequisites

### System Dependencies (Debian / Ubuntu)

```bash
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r)
```

### Go Toolchain

Go **1.24** or newer is required (uses the `tool` directive in `go.mod`). Download from https://go.dev/dl/

### bpf2go

`bpf2go` compiles the eBPF C code (`tcx.c`) into Go-embeddable objects. It is declared as a tracked Go tool in `go.mod`:

```
tool github.com/cilium/ebpf/cmd/bpf2go
```

Install it (and sync `go.sum`) with:

```bash
make bpf2go
# equivalent to:
# go get -tool github.com/cilium/ebpf/cmd/bpf2go && go mod tidy
```

Or install **all dependencies** at once:

```bash
make deps
```

---

## Build

### 1. Install all dependencies

```bash
make deps
# installs: clang, llvm, libbpf-dev, linux-headers, bpf2go
```

Or separately:

```bash
make apt-deps   # system packages only
make bpf2go     # bpf2go Go tool only (tracked in go.mod)
```

### 2. Generate eBPF Go bindings

Compiles `tcx.c` via `bpf2go` and produces `bpf_bpfel.go` / `bpf_bpfeb.go`:

```bash
make generate
```

### 3. Build the binary

```bash
make build
```

The output binary `ebpf-tcx-filter` will appear in the project root.

### One-liner (generate + build)

```bash
make
```

---

## Install

Installs the binary to `/usr/local/bin` (requires `sudo`):

```bash
make install
```

---

## Usage

> **Root privileges are required** because loading eBPF programs and attaching TCX hooks require `CAP_BPF` / `CAP_NET_ADMIN`.

```bash
sudo ./ebpf-tcx-filter <network-interface>
# e.g.
sudo ./ebpf-tcx-filter eth0
```

Or via Make (auto-builds first):

```bash
make run IFACE=eth0
```

Once running, the web dashboard is available at:

```
http://localhost:8080
```

---

## Makefile Targets

| Target | Description |
|---|---|
| `make` / `make all` | Generate eBPF bindings + build binary |
| `make deps` | Install all dependencies: system packages + `bpf2go` |
| `make apt-deps` | Install system packages only (`clang`, `llvm`, `libbpf-dev`, `linux-headers`) |
| `make bpf2go` | Install `bpf2go` Go tool (tracked via `tool` directive in `go.mod`) |
| `make generate` | Compile `tcx.c` with `bpf2go` |
| `make build` | Build the Go binary |
| `make install` | Build and install to `/usr/local/bin` (uses `sudo`) |
| `make run IFACE=eth0` | Build and run with `sudo` |
| `make clean` | Remove the compiled binary |
| `make cleanall` | Remove binary and all generated eBPF files |

---

## Project Structure

```
.
├── main.go          # Userspace Go program (loads eBPF, serves dashboard)
├── tcx.c            # eBPF C program (kernel-side packet filter/counter)
├── bpf_bpfel.go     # Generated: little-endian eBPF Go bindings
├── bpf_bpfeb.go     # Generated: big-endian eBPF Go bindings
├── bpf_bpfel.o      # Compiled eBPF object (little-endian)
├── bpf_bpfeb.o      # Compiled eBPF object (big-endian)
├── headers/         # eBPF helper headers (bpf_helpers.h, common.h, …)
├── go.mod
├── go.sum
└── Makefile
```

---

## License

Dual MIT / GPL-2.0 — see source file headers for details.

