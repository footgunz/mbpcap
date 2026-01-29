# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

mbpcap is a Go serial capture tool that frames data from a serial port into packets and records them as PCAP files for analysis with Wireshark/TShark. The primary use case is capturing Modbus RTU traffic on RS-485 buses. Inspired by the C-based `mstpcap` tool from the [bacnet-stack](https://github.com/bacnet-stack/bacnet-stack) project, but protocol-agnostic.

## Build & Development Commands

```bash
go build ./...          # Build all packages
go test ./...           # Run all tests
go test ./pkg/pcap      # Run tests for a specific package
go test -run TestName   # Run a single test
go vet ./...            # Static analysis
```

## Architecture

Three core stages in a capture loop:

1. **Serial Port Reader** — Reads bytes from the serial port as they arrive
2. **Silence-Based Framer** — Accumulates bytes into a packet buffer; when idle time exceeds a configurable threshold (default 20ms), the buffered bytes are emitted as a complete packet. The timestamp of the first byte in each packet is used as the packet timestamp.
3. **PCAP Writer** — Writes each completed packet to a PCAP file with its timestamp

### Framing Strategy

Framing is silence-based (not protocol-aware). In Modbus RTU, the master initiates all traffic and slaves only respond when polled, producing natural gaps of ~20ms+ between messages. A configurable silence threshold detects these gaps. This approach is protocol-agnostic — it works for any serial protocol with inter-message gaps.

### PCAP File Format (libpcap)

- **Global header** (28 bytes): magic `0xa1b2c3d4`, version 2.4, snaplen 65535, link type (DLT)
- **Per-packet header** (16 bytes): timestamp (sec + usec), captured length, original length
- **Per-packet data**: the raw frame bytes

Use DLT 147 (USER0) for the link type. Wireshark will show raw bytes by default; users can configure a custom dissector (e.g. Modbus RTU) via Wireshark's DLT_USER protocol preferences.

### Serial Port Defaults

- Baud: 115200, Data bits: 8, Parity: none, Stop bits: 1
- The serial port path is a required argument
- Silence threshold: 20ms (configurable)

## Design Constraints

- Most minimal PCAP implementation possible — timestamp, data, and minimum required fields for a valid capture file
- Wireshark plugin/pipe integration is out of scope unless completely trivial
- Protocol-agnostic: no Modbus or BACnet protocol parsing; framing is purely silence-based
- Serial library: `go.bug.st/serial`
