import Foundation

// MARK: - 独立短生命周期探针会话（绝不复用作 Worker 槽位）

internal extension LaneShunt {
    enum ProbeExecutionOutcome {
        case completedOneByte(finalURL: URL, byte: UInt8)
        case completedEmptyFile(finalURL: URL)
        case completedSingleStream200(finalURL: URL, writtenBytes: Int64)
        case interruptedSingleStream200(
            finalURL: URL,
            writer: PosixOffsetFileWriter,
            writtenBytes: Int64,
            validator: StrongValidator?,
            expectedTotal: Int64?,
            errorDescription: String,
            isTimeout: Bool
        )
        case downgradeToSingleStream(finalURL: URL)
        case proceedSegmented(finalURL: URL, totalBytes: Int64, validator: StrongValidator)
        case retryableBackoff(statusCode: Int, retryAfter: TimeInterval?)
        case retryableTransient(description: String)
    }

    private struct ProbeStateData {
        var decision: ProbeDecision?
        var oneByteBuffer = Data()
        var reuseWriter: PosixOffsetFileWriter?
        var reuseWrittenBytes: Int64 = 0
        var reuseExpectedTotal: Int64?
        var reuseValidator: StrongValidator?
        var reuseFinalURL: URL?
    }

    /// 发起 `GET Range: bytes=0-0` 能力探测：支持 0/1 字节快路径、200 流直复用、无损降级与强校验器锁定
    static func executeProbeAttempt(
        url: URL,
        destinationURL: URL,
        config: LaneShuntConfig,
        overallDeadline: TimeInterval,
        progressReporter: ProgressReporter
    ) async throws -> ProbeExecutionOutcome {
        let probeDriver = IsolatedSessionDriver(
            label: "probe",
            config: config,
            requestTimeout: config.singleStreamIdleTimeout,
            resourceTimeout: config.totalTimeout
        )
        defer {
            probeDriver.invalidateAndCancel()
        }

        let request = makeGETRequest(url: url, userAgent: config.userAgent, range: "bytes=0-0")
        let state = LockedState(ProbeStateData())

        do {
            try await probeDriver.runTask(
                request: request,
                idleTimeout: config.singleStreamIdleTimeout,
                overallDeadline: overallDeadline,
                onResponse: { response, _ in
                    let finalURL = response.url ?? url
                    let decision = HTTPPolicy.evaluateProbeResponse(
                        response,
                        finalURL: finalURL,
                        config: config
                    )
                    state.withLock { $0.decision = decision }

                    switch decision {
                    case .oneByteFastPath:
                        return .allow

                    case .reuseSingleStream200(let resolvedURL, let expectedTotal, let validator):
                        let writer = try PosixOffsetFileWriter(near: destinationURL)
                        state.withLock {
                            $0.reuseWriter = writer
                            $0.reuseExpectedTotal = expectedTotal
                            $0.reuseValidator = validator
                            $0.reuseFinalURL = resolvedURL
                        }
                        return .allow

                    case .failImmediately(let err):
                        throw err

                    case .emptyFile, .segmented, .downgradeSingleStreamPlainGET, .retryableBackoff, .retryableTransient:
                        return .stopEarlySuccess
                    }
                },
                onData: { data in
                    let current = state.withLock {
                        (decision: $0.decision, writer: $0.reuseWriter, written: $0.reuseWrittenBytes, expectedTotal: $0.reuseExpectedTotal)
                    }
                    guard let currentDecision = current.decision else { return }

                    switch currentDecision {
                    case .oneByteFastPath:
                        try state.withLock {
                            let newCount = $0.oneByteBuffer.count + data.count
                            if newCount > 1 {
                                throw LaneShuntError.sizeLimitExceeded(limit: 1, actual: Int64(newCount))
                            }
                            $0.oneByteBuffer.append(data)
                        }

                    case .reuseSingleStream200:
                        guard let writer = current.writer else { return }
                        let nextTotal = current.written + Int64(data.count)
                        if nextTotal > config.maxBytes {
                            throw LaneShuntError.sizeLimitExceeded(limit: config.maxBytes, actual: nextTotal)
                        }
                        try writer.write(data, atOffset: current.written)
                        state.withLock { $0.reuseWrittenBytes = nextTotal }
                        progressReporter.report(
                            bytesReceived: nextTotal,
                            totalBytes: current.expectedTotal ?? config.expectedSizeHint,
                            force: false
                        )

                    default:
                        break
                    }
                }
            )
        } catch is CancellationError {
            let writer = state.withLock { data -> PosixOffsetFileWriter? in
                let w = data.reuseWriter
                data.reuseWriter = nil
                return w
            }
            writer?.closeAndCleanup()
            throw CancellationError()
        } catch let err as LaneShuntError {
            let writer = state.withLock { data -> PosixOffsetFileWriter? in
                let w = data.reuseWriter
                data.reuseWriter = nil
                return w
            }
            writer?.closeAndCleanup()
            throw err
        } catch {
            let snap = state.withLock { data in
                let writer = data.reuseWriter
                data.reuseWriter = nil
                return (
                    decision: data.decision,
                    writer: writer,
                    written: data.reuseWrittenBytes,
                    expectedTotal: data.reuseExpectedTotal,
                    validator: data.reuseValidator,
                    finalURL: data.reuseFinalURL ?? url
                )
            }
            if case .reuseSingleStream200 = snap.decision,
               let writer = snap.writer,
               HTTPPolicy.isTransientNetworkError(error)
            {
                return .interruptedSingleStream200(
                    finalURL: snap.finalURL,
                    writer: writer,
                    writtenBytes: snap.written,
                    validator: snap.validator,
                    expectedTotal: snap.expectedTotal,
                    errorDescription: error.localizedDescription,
                    isTimeout: isTimeoutError(error)
                )
            }
            snap.writer?.closeAndCleanup()
            throw error
        }

        let snap = state.withLock { data in
            let writer = data.reuseWriter
            data.reuseWriter = nil
            return (
                decision: data.decision,
                oneByte: data.oneByteBuffer,
                writer: writer,
                written: data.reuseWrittenBytes,
                expectedTotal: data.reuseExpectedTotal,
                validator: data.reuseValidator,
                finalURL: data.reuseFinalURL ?? url
            )
        }
        guard let finalDecision = snap.decision else {
            snap.writer?.closeAndCleanup()
            return .retryableTransient(description: "Probe finished without HTTP response")
        }

        switch finalDecision {
        case .oneByteFastPath(let finalURL):
            guard snap.oneByte.count == 1, let byte = snap.oneByte.first else {
                return .retryableTransient(description: "Probe 206 bytes 0-0/1 returned \(snap.oneByte.count) bytes")
            }
            return .completedOneByte(finalURL: finalURL, byte: byte)

        case .emptyFile(let finalURL):
            return .completedEmptyFile(finalURL: finalURL)

        case .segmented(let finalURL, let totalBytes, let strongValidator):
            return .proceedSegmented(finalURL: finalURL, totalBytes: totalBytes, validator: strongValidator)

        case .reuseSingleStream200:
            guard let writer = snap.writer else {
                return .retryableTransient(description: "Missing file writer for 200 OK stream reuse")
            }
            if let expectedTotal = snap.expectedTotal, snap.written < expectedTotal {
                return .interruptedSingleStream200(
                    finalURL: snap.finalURL,
                    writer: writer,
                    writtenBytes: snap.written,
                    validator: snap.validator,
                    expectedTotal: expectedTotal,
                    errorDescription: "Unexpected EOF at \(snap.written)/\(expectedTotal) bytes",
                    isTimeout: false
                )
            }
            do {
                let finalized = try writer.finalize(expectedSize: snap.written, destinationURL: destinationURL)
                return .completedSingleStream200(finalURL: snap.finalURL, writtenBytes: finalized)
            } catch {
                writer.closeAndCleanup()
                throw error
            }

        case .downgradeSingleStreamPlainGET(let finalURL):
            return .downgradeToSingleStream(finalURL: finalURL)

        case .failImmediately(let err):
            throw err

        case .retryableBackoff(let statusCode, let retryAfter):
            return .retryableBackoff(statusCode: statusCode, retryAfter: retryAfter)

        case .retryableTransient(let desc):
            return .retryableTransient(description: desc)
        }
    }
}
