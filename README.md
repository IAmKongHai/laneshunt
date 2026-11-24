# LaneShunt

[![CI](https://github.com/IAmKongHai/laneshunt/actions/workflows/ci.yml/badge.svg)](https://github.com/IAmKongHai/laneshunt/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[中文文档](README.zh-CN.md)

**Zero-dependency multi-connection segmented HTTP downloader with slow-stream rotation and incremental tail hedging, implemented natively in Swift and Go.**

LaneShunt is built for hostile, high-packet-loss networks (such as 30%+ loss cross-border links) where a single TCP or HTTP/2 connection gets stuck in a collapsed congestion window and trickles at a few KB/s for minutes without triggering an idle timeout.

---

## Why LaneShunt?

Most lightweight HTTP downloaders wrap a shared `URLSession` or `http.Client`. On high-loss links, two failure modes kill throughput:

1. **HTTP/2 single-connection coalescing**: Multiple concurrent requests multiplex onto the *same* underlying TCP socket, sharing a single congestion window and head-of-line blocking.
2. **Slow-stream stickiness**: A connection throttled by packet loss still trickles a few KB/s, so standard idle timeouts never fire and the download crawls for minutes.

LaneShunt solves both with **zero external dependencies**:

- **True TCP lane isolation**: Each worker slot owns an isolated transport (`URLSession(.ephemeral)` with `httpMaximumConnectionsPerHost = 1` in Swift; cloned `http.Transport` with `ForceAttemptHTTP2 = false` and explicit `TLSClientConfig.NextProtos = ["http/1.1"]` in Go).
- **Zero-waste probe & graceful fallback**: Probes with `GET Range: bytes=0-0`. Small payloads, servers without byte-range support, or non-identity encodings fall back seamlessly to single-stream download.
- **256 KiB immutable micro-chunk ledger**: Workers write directly at file offsets (`pwrite` / `os.File.WriteAt`) into a single preallocated temporary file with constant low memory.
- **Adaptive slow-lane shunting & bounded scouting**: Tracks per-lane throughput against a decaying high-speed baseline, rotates stuck/slow TCP sockets, and runs bounded single-slot scouts so genuinely narrowband networks (e.g. 15 KB/s hotspots) shrink concurrency instead of thrashing.
- **Incremental tail hedging**: When the chunk queue drains, idle fast lanes hedge remaining slow tail chunks from their last committed offset and cancel the loser as soon as the winner finishes.
- **Production-grade safety**: HTTPS-only by default (blocks `https -> http` downgrade redirects), strips `If-Range` across origins, enforces strong validators (`ETag` / `Last-Modified`) and `Content-Range` total length to prevent splicing bytes across file updates, respects `Retry-After` with concurrency halving on `429/502/503/504`, and fails fast on permanent TLS errors.

### Production Benchmark (Real Cross-Border Link)

Extracted from [CraftPaste](https://github.com/IAmKongHai/CraftPaste) after real production auto-update validation over a cross-border link (~31% peak packet loss):

| Metric | Single-Connection HTTP/2 | LaneShunt (6 Lanes) |
| --- | --- | --- |
| Payload size | 6.28 MiB (`6,587,560` bytes) | 6.28 MiB (`6,587,560` bytes) |
| Observed completion time | 3–10 min (frequent stall/timeout) | **3.5–4.0 s** (peak ~3.25 MiB/s) |
| Server 4xx / 5xx / 416 errors | — | **0** |
| Tail-hedging traffic overhead | — | **~10.9%** (~705 KiB) |

---

## Installation & Quick Start

### Swift (Swift Package Manager)

Requires Swift 6.0+ (`macOS 13+`, `iOS 16+`, `tvOS 16+`, `watchOS 9+`). Zero third-party dependencies (`Foundation` + `Darwin`/`Glibc` only).

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/IAmKongHai/laneshunt.git", from: "0.1.0")
]
```

```swift
import Foundation
import LaneShunt

let url = URL(string: "https://example.com/release.dmg")!
let destination = URL(fileURLWithPath: "/tmp/release.dmg")

let result = try await LaneShunt.download(
    from: url,
    to: destination,
    config: LaneShuntConfig(maxConnections: 6)
) { progress in
    if let fraction = progress.fractionCompleted {
        print(String(format: "%.1f%% (%lld / %lld)",
                     fraction * 100, progress.bytesReceived, progress.totalBytes ?? 0))
    }
}

print("Saved \(result.bytesWritten) bytes (segmented: \(result.usedSegmented))")
```

### Go (Go Module)

Requires Go 1.22+. Pure Go standard library (`net/http`, `os`, `sync`, etc.), zero external dependencies, cross-platform (macOS / Linux / Windows).

```bash
go get github.com/IAmKongHai/laneshunt/go@v0.1.0
```

```go
package main

import (
	"context"
	"fmt"
	"log"

	laneshunt "github.com/IAmKongHai/laneshunt/go"
)

func main() {
	cfg := laneshunt.DefaultConfig()
	cfg.MaxConnections = 6
	cfg.OnProgress = func(p laneshunt.Progress) {
		if p.TotalBytes > 0 {
			pct := float64(p.BytesReceived) * 100 / float64(p.TotalBytes)
			fmt.Printf("\r%.1f%% (%d / %d bytes)", pct, p.BytesReceived, p.TotalBytes)
		}
	}

	res, err := laneshunt.Download(
		context.Background(),
		"https://example.com/release-setup.exe",
		"/tmp/release-setup.exe",
		cfg,
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\nSaved %d bytes (segmented: %v)\n", res.BytesWritten, res.UsedSegmented)
}
```

### CLI & Built-in Local Slow-Lane Benchmark

Try LaneShunt directly from the command line or run the built-in loopback slow-lane benchmark (simulating 4 throttled lanes + 2 fast lanes):

```bash
cd go
# Run built-in local slow-lane benchmark (single-stream vs LaneShunt)
go run ./cmd/laneshunt -bench

# Download a file
go run ./cmd/laneshunt https://example.com/archive.tar.gz ./archive.tar.gz
```

---

## Repository Layout

```text
laneshunt/
├── Package.swift                 # SwiftPM manifest (root for seamless SPM integration)
├── swift/
│   ├── Sources/LaneShunt/        # Zero-dependency Swift engine
│   └── Tests/LaneShuntTests/     # 26 end-to-end & state-machine tests
├── go/
│   ├── go.mod                    # github.com/IAmKongHai/laneshunt/go (Go 1.22+, stdlib only)
│   ├── *.go                      # Zero-dependency Go engine & -race test suite
│   └── cmd/laneshunt/            # CLI downloader & local slow-lane benchmark
└── docs/
    └── architecture.md           # Scheduling algorithm & cross-language parity spec
```

## Design Scope & Non-Goals

- **Single-session resilience**: LaneShunt focuses on fast, reliable delivery of installers, release artifacts, and medium-sized assets within a single session. It intentionally does not persist cross-restart checkpoint metadata on disk; cancelled or failed runs clean up temporary `.laneshunt-*.tmp` files automatically.
- **Transport-layer purity**: Domain allowlists, checksum verification, code-signature checks, and localized UI strings belong in the caller's application layer.

See [docs/architecture.md](docs/architecture.md) for the full state machine, adaptive slow-lane shunting algorithm, and Swift/Go parity details.

## License

[MIT](LICENSE)
