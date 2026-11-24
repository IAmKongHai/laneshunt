# LaneShunt Architecture & Cross-Language Parity Spec

LaneShunt implements the same transport isolation model, micro-chunk ledger, adaptive slow-lane shunting algorithm, and HTTP safety invariants in both **Swift** and **Go** with zero third-party dependencies.

## 1. Transport Isolation (Why Not Single-Connection HTTP/2 or HTTP/3?)

- **Single-connection HTTP/2**: Under 30%+ packet loss, multiplexing N logical streams over one TCP socket still suffers from TCP head-of-line blocking and a single collapsed congestion window.
- **HTTP/3 (QUIC/UDP)**: Cross-border and enterprise networks frequently apply aggressive QoS throttling to UDP/443, and Go's standard library does not include a native HTTP/3 client.
- **LaneShunt's approach**: Each worker slot owns an isolated transport:
  - **Go (`go/http_policy.go`)**: Deep-clones the base `http.Transport`, sets `ForceAttemptHTTP2 = false`, and explicitly overwrites `TLSClientConfig.NextProtos = []string{"http/1.1"}` (preventing residual `"h2"` ALPN entries when cloning an already-initialized `http.DefaultTransport`).
  - **Swift (`swift/Sources/LaneShunt/IsolatedSessionDriver.swift`)**: Creates an isolated `.ephemeral` `URLSession` per slot with `httpMaximumConnectionsPerHost = 1`, zero disk/memory cache, and no cookies. Even if a slot negotiates HTTP/2 with an origin, one socket carries at most one active stream.

## 2. Download Lifecycle

1. **Probe (`GET Range: bytes=0-0`)**:
   - Skipped when `expectedSizeHint < minSegmentedSize`.
   - If the server responds `206 Partial Content` with a valid `Content-Range`, `identity` (or absent) `Content-Encoding`, a strong validator (strong `ETag` or `Last-Modified`), and `total >= minSegmentedSize`, LaneShunt enters **segmented mode**.
   - Otherwise (e.g., `200 OK`, small file, missing strong validator, or non-empty `416`), LaneShunt falls back seamlessly to **single-stream mode** without wasting already-opened responses where applicable.
2. **Micro-Chunk Ledger (`256 KiB` immutable slices)**:
   - The file is partitioned into fixed `chunkSize` slices written directly at file offsets (`Darwin.pwrite` / `Glibc.pwrite` in Swift, `os.File.WriteAt` in Go) into a single preallocated `.laneshunt-*.tmp` file.
   - Progress is reported monotonically from unique committed bytes only and throttled to avoid UI/caller flooding.
3. **Adaptive Slow-Lane Shunting & Bounded Scouting**:
   - **Scenario A (Mixed fast & slow lanes)**: A decaying high-speed baseline (18s window) remembers recent fast lanes. Any lane stuck below `25%` of the baseline (and `< 512 KiB/s`) for `3s` after its `2s` warmup is cancelled and replaced with a fresh TCP socket, subject to per-slot (`8s`), global (`3s`), and per-download rotation caps.
   - **Scenario B (Uniform high packet loss)**: When no lane exceeds the high-speed threshold (`64 KiB/s`), LaneShunt runs at most `2` bounded single-slot scouts. If aggregate throughput stays `>= 48 KiB/s`, all lanes remain active without thrashing.
   - **Scenario C (True narrowband hotspot)**: After scouts exhaust and aggregate throughput remains `< 48 KiB/s`, LaneShunt shrinks active concurrency down to `2` lanes and disables further scouting.
4. **Incremental Tail Hedging**:
   - Once all unstarted chunks are claimed, idle fast slots hedge in-flight tail chunks starting from the chunk's committed offset (up to `maxConcurrentHedges = 2`).
   - Whichever attempt finishes commits the remaining bytes and immediately cancels the losing attempt.
5. **Backoff, Drift Protection & Cleanup**:
   - `429`, `502`, `503`, `504`: Honors `Retry-After` (integer seconds or HTTP-date, capped at `60s`) with global backoff and concurrency halving. Other `5xx` errors trigger per-chunk jittered exponential backoff.
   - Resource drift (`200`, `416`, changed strong validator, or mismatched `Content-Range` total): Aborts the current generation, waits for all workers to exit, closes and deletes the temp file, emits a reset progress event (`isReset = true`), and restarts from scratch within `maxFullResets`.
   - Cancellation / completion / error: All workers exit and close file descriptors before atomic rename or temp file deletion, leaving zero leaked sessions, timers, goroutines, or `.tmp` files.

## 3. Module Map

| Responsibility | Swift (`swift/Sources/LaneShunt/`) | Go (`go/`) |
| --- | --- | --- |
| Public config & errors | `LaneShuntConfig.swift` | `config.go` |
| Public entry & orchestration | `LaneShunt.swift` | `downloader.go` |
| HTTP validation & policy | `HTTPProbeAndPolicy.swift` | `http_policy.go` |
| Unified probe/single attempt | `ProbeSession.swift` | `http_attempt.go` |
| Single-stream download | `SingleStreamDownloader.swift` | `single_stream.go` |
| Segmented worker pool | `SegmentedDownloader.swift` | `segmented.go` |
| Micro-chunk ledger | `ChunkLedger.swift` | `ledger.go` |
| Speed tracking & scout | `SlotSpeedTracker.swift` | `speed_tracker.go` |
| Transport / File I/O / Sync | `IsolatedSessionDriver.swift`, `PosixOffsetFileWriter.swift`, `LockedState.swift`, `LedgerWaiterQueue.swift`, `ProgressReporter.swift` | Standard library (`os.File.WriteAt`, `sync.Mutex`, `http.Transport`) |
