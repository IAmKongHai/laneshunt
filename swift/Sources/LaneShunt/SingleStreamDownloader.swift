import Foundation

// MARK: - 单流可续传下载（小文件直通、无 Range 或降级路径）

internal extension LaneShunt {
    private enum SingleAttemptOutcome: Sendable {
        case streaming
        case resetAndRetry(String)
        case retryableBackoff(Int, TimeInterval?)
        case retryableTransient(String)
        case emptyFile(URL)
    }

    private struct SingleAttemptStateData {
        var outcome: SingleAttemptOutcome = .streaming
        var finalURL: URL
        var written: Int64
        var expectedTotal: Int64?
        var segmentHardEnd: Int64?
        var validator: StrongValidator?
    }

    /// 执行单流可续传下载（持有强校验器时支持 Range + If-Range 断点续传，遇漂移或 416 自动归零重下）
    static func runSingleStreamDownload(
        url: URL,
        destinationURL: URL,
        config: LaneShuntConfig,
        startingAttempt: Int,
        existingWriter: PosixOffsetFileWriter?,
        initialWrittenBytes: Int64,
        initialValidator: StrongValidator?,
        initialTotalBytes: Int64?,
        overallDeadline: TimeInterval,
        progressReporter: ProgressReporter
    ) async throws -> DownloadResult {
        let writer = try existingWriter ?? PosixOffsetFileWriter(near: destinationURL)
        var writerFinalized = false
        defer {
            if !writerFinalized {
                writer.closeAndCleanup()
            }
        }

        var attempt = startingAttempt
        var writtenBytes = initialWrittenBytes
        var lockedValidator = initialValidator
        var lockedTotalBytes = initialTotalBytes
        var currentURL = url
        var resetsUsed = 0

        // 若没有强校验器但已有已写字节，安全起见归零重来避免拼接两代文件
        try resetSingleStreamIfUnvalidated(
            writtenBytes: &writtenBytes,
            lockedValidator: lockedValidator,
            writer: writer,
            progressReporter: progressReporter
        )

        while true {
            try checkCancellationAndDeadline(overallDeadline: overallDeadline, config: config)

            let driver = IsolatedSessionDriver(
                label: "single-\(attempt)",
                config: config,
                requestTimeout: config.singleStreamIdleTimeout,
                resourceTimeout: config.totalTimeout
            )
            defer {
                driver.invalidateAndCancel()
            }

            let attemptURL = currentURL
            let attemptStartOffset = writtenBytes
            let attemptLockedValidator = lockedValidator
            let attemptLockedTotal = lockedTotalBytes
            let sendingRange = attemptStartOffset > 0 && attemptLockedValidator != nil
            let request = makeGETRequest(
                url: attemptURL,
                userAgent: config.userAgent,
                range: sendingRange ? "bytes=\(attemptStartOffset)-" : nil,
                ifRange: sendingRange ? attemptLockedValidator?.ifRangeHeaderValue : nil
            )

            let attemptState = LockedState(
                SingleAttemptStateData(
                    finalURL: attemptURL,
                    written: attemptStartOffset,
                    expectedTotal: attemptLockedTotal,
                    segmentHardEnd: nil,
                    validator: attemptLockedValidator
                )
            )

            do {
                try await driver.runTask(
                    request: request,
                    idleTimeout: config.singleStreamIdleTimeout,
                    overallDeadline: overallDeadline,
                    onResponse: { response, didCrossOrigin in
                        let resolvedURL = response.url ?? attemptURL
                        let code = response.statusCode

                        if code == 200 {
                            let identity = HTTPPolicy.isIdentityContentEncoding(response)
                            let contentLength = identity ? HTTPPolicy.parseContentLength(response) : nil
                            if let cl = contentLength, cl > config.maxBytes {
                                throw LaneShuntError.sizeLimitExceeded(limit: config.maxBytes, actual: cl)
                            }
                            if sendingRange {
                                try writer.truncateToZero()
                                progressReporter.reportReset()
                            }
                            let extractedValidator = HTTPPolicy.extractStrongValidator(from: response)
                            attemptState.withLock {
                                $0.finalURL = resolvedURL
                                $0.written = 0
                                $0.expectedTotal = contentLength
                                $0.segmentHardEnd = contentLength.map { $0 - 1 }
                                $0.validator = extractedValidator
                                $0.outcome = .streaming
                            }
                            return .allow
                        }

                        if code == 206 {
                            guard sendingRange else {
                                // 未请求 Range 却返回 206，视为异常协议响应
                                throw LaneShuntError.httpStatus(206)
                            }
                            let validEncoding = HTTPPolicy.isIdentityContentEncoding(response) &&
                                !HTTPPolicy.isMultipartByteranges(response)
                            let parsed = HTTPPolicy.parseContentRange(HTTPPolicy.headerValue(response, "Content-Range"))
                            guard validEncoding,
                                  case .range(let start, let end, let totalOpt) = parsed,
                                  start == attemptStartOffset
                            else {
                                attemptState.withLock {
                                    $0.outcome = .resetAndRetry("Invalid 206 Content-Range on single-stream resume")
                                }
                                return .stopEarlySuccess
                            }
                            if let total = totalOpt, total > config.maxBytes {
                                throw LaneShuntError.sizeLimitExceeded(limit: config.maxBytes, actual: total)
                            }
                            if end >= config.maxBytes {
                                let actualBytes: Int64 = (end == Int64.max) ? Int64.max : (end + 1)
                                throw LaneShuntError.sizeLimitExceeded(limit: config.maxBytes, actual: actualBytes)
                            }
                            if let lockedTotal = attemptLockedTotal, let total = totalOpt, total != lockedTotal {
                                attemptState.withLock {
                                    $0.outcome = .resetAndRetry("Total length drifted on single-stream resume")
                                }
                                return .stopEarlySuccess
                            }
                            if let validator = attemptLockedValidator,
                               (didCrossOrigin || HTTPPolicy.headerValue(response, "ETag") != nil || HTTPPolicy.headerValue(response, "Last-Modified") != nil),
                               !HTTPPolicy.verifyChunkValidator(response: response, locked: validator)
                            {
                                attemptState.withLock {
                                    $0.outcome = .resetAndRetry("Locked validator drifted on single-stream 206 resume")
                                }
                                return .stopEarlySuccess
                            }

                            attemptState.withLock {
                                $0.finalURL = resolvedURL
                                $0.expectedTotal = totalOpt ?? attemptLockedTotal
                                $0.segmentHardEnd = end
                                $0.outcome = .streaming
                            }
                            return .allow
                        }

                        if code == 416 {
                            if sendingRange {
                                attemptState.withLock {
                                    $0.outcome = .resetAndRetry("HTTP 416 on single-stream resume")
                                }
                                return .stopEarlySuccess
                            }
                            if let parsed = HTTPPolicy.parseContentRange(HTTPPolicy.headerValue(response, "Content-Range")),
                               case .unsatisfied(let total) = parsed,
                               total == 0
                            {
                                attemptState.withLock { $0.outcome = .emptyFile(resolvedURL) }
                                return .stopEarlySuccess
                            }
                            throw LaneShuntError.httpStatus(416)
                        }

                        switch HTTPPolicy.classifyNonSuccessStatus(response, maxRetryAfterDelay: config.maxRetryAfterDelay) {
                        case .rateLimitBackoff(let statusCode, let retryAfter):
                            attemptState.withLock { $0.outcome = .retryableBackoff(statusCode, retryAfter) }
                            return .stopEarlySuccess
                        case .retryableServerError(let statusCode):
                            attemptState.withLock { $0.outcome = .retryableTransient("HTTP \(statusCode)") }
                            return .stopEarlySuccess
                        case .deterministicFailure(let err):
                            throw err
                        }
                    },
                    onData: { data in
                        let current = attemptState.withLock {
                            (offset: $0.written, hardEnd: $0.segmentHardEnd, expectedTotal: $0.expectedTotal)
                        }
                        let dataCount = Int64(data.count)
                        if dataCount > config.maxBytes - current.offset {
                            let (sum, overflow) = current.offset.addingReportingOverflow(dataCount)
                            throw LaneShuntError.sizeLimitExceeded(
                                limit: config.maxBytes,
                                actual: overflow ? Int64.max : sum
                            )
                        }
                        let nextEnd = current.offset + dataCount
                        if let hardEnd = current.hardEnd, hardEnd < Int64.max, nextEnd > hardEnd + 1 {
                            throw LaneShuntError.sizeLimitExceeded(limit: hardEnd + 1, actual: nextEnd)
                        }

                        try writer.write(data, atOffset: current.offset)
                        attemptState.withLock { $0.written = nextEnd }

                        progressReporter.report(
                            bytesReceived: nextEnd,
                            totalBytes: current.expectedTotal ?? config.expectedSizeHint,
                            force: false
                        )
                    }
                )
            } catch is CancellationError {
                throw CancellationError()
            } catch let err as LaneShuntError {
                throw err
            } catch {
                if Task.isCancelled {
                    throw CancellationError()
                }
                let snap = attemptState.withLock { $0 }
                writtenBytes = snap.written
                lockedValidator = snap.validator
                lockedTotalBytes = snap.expectedTotal
                currentURL = snap.finalURL

                if HTTPPolicy.isTransientNetworkError(error), attempt < config.maxAttempts {
                    try resetSingleStreamIfUnvalidated(
                        writtenBytes: &writtenBytes,
                        lockedValidator: lockedValidator,
                        writer: writer,
                        progressReporter: progressReporter
                    )
                    attempt += 1
                    try await cancellableSleep(seconds: config.retryDelay, overallDeadline: overallDeadline, config: config)
                    continue
                }
                throw LaneShuntError.retriesExhausted(
                    attempts: attempt,
                    underlyingDescription: error.localizedDescription,
                    isTimeout: isTimeoutError(error)
                )
            }

            let snap = attemptState.withLock { $0 }
            let outcome = snap.outcome
            writtenBytes = snap.written
            lockedValidator = snap.validator
            lockedTotalBytes = snap.expectedTotal
            let finalURL = snap.finalURL
            let expectedSegmentEnd = snap.segmentHardEnd

            switch outcome {
            case .emptyFile(let resolvedURL):
                try writer.truncateToZero()
                let size = try writer.finalize(expectedSize: 0, destinationURL: destinationURL)
                writerFinalized = true
                progressReporter.report(bytesReceived: 0, totalBytes: 0, force: true)
                return DownloadResult(
                    finalURL: resolvedURL,
                    bytesWritten: size,
                    totalBytes: 0,
                    attemptsUsed: attempt,
                    usedSegmented: false
                )

            case .resetAndRetry(let reason):
                try writer.truncateToZero()
                writtenBytes = 0
                lockedValidator = nil
                lockedTotalBytes = nil
                currentURL = url
                progressReporter.reportReset()

                if resetsUsed < config.maxFullResets && attempt < config.maxAttempts {
                    resetsUsed += 1
                    attempt += 1
                    continue
                }
                throw LaneShuntError.retriesExhausted(
                    attempts: attempt,
                    underlyingDescription: reason,
                    isTimeout: false
                )

            case .retryableBackoff(let code, let retryAfter):
                if attempt < config.maxAttempts {
                    attempt += 1
                    let wait = min(config.maxRetryAfterDelay, retryAfter ?? config.retryDelay)
                    try await cancellableSleep(seconds: wait, overallDeadline: overallDeadline, config: config)
                    continue
                }
                throw LaneShuntError.retriesExhausted(
                    attempts: attempt,
                    underlyingDescription: "HTTP \(code)",
                    isTimeout: false
                )

            case .retryableTransient(let desc):
                if attempt < config.maxAttempts {
                    attempt += 1
                    try await cancellableSleep(seconds: config.retryDelay, overallDeadline: overallDeadline, config: config)
                    continue
                }
                throw LaneShuntError.retriesExhausted(
                    attempts: attempt,
                    underlyingDescription: desc,
                    isTimeout: false
                )

            case .streaming:
                if let expectedTotal = lockedTotalBytes, writtenBytes < expectedTotal {
                    if attempt < config.maxAttempts {
                        try resetSingleStreamIfUnvalidated(
                            writtenBytes: &writtenBytes,
                            lockedValidator: lockedValidator,
                            writer: writer,
                            progressReporter: progressReporter
                        )
                        attempt += 1
                        try await cancellableSleep(seconds: config.retryDelay, overallDeadline: overallDeadline, config: config)
                        continue
                    }
                    throw LaneShuntError.retriesExhausted(
                        attempts: attempt,
                        underlyingDescription: "Incomplete response body (\(writtenBytes)/\(expectedTotal) bytes)",
                        isTimeout: false
                    )
                }
                if let expectedSegmentEnd {
                    let expectedEndCount: Int64 = expectedSegmentEnd < Int64.max ? (expectedSegmentEnd + 1) : Int64.max
                    if writtenBytes < expectedEndCount {
                        if attempt < config.maxAttempts {
                            attempt += 1
                            try await cancellableSleep(seconds: config.retryDelay, overallDeadline: overallDeadline, config: config)
                            continue
                        }
                        throw LaneShuntError.retriesExhausted(
                            attempts: attempt,
                            underlyingDescription: "Truncated range response (\(writtenBytes)/\(expectedEndCount) bytes)",
                            isTimeout: false
                        )
                    }
                }

                let finalizedSize = try writer.finalize(expectedSize: writtenBytes, destinationURL: destinationURL)
                writerFinalized = true
                progressReporter.report(bytesReceived: finalizedSize, totalBytes: finalizedSize, force: true)
                return DownloadResult(
                    finalURL: finalURL,
                    bytesWritten: finalizedSize,
                    totalBytes: finalizedSize,
                    attemptsUsed: attempt,
                    usedSegmented: false
                )
            }
        }
    }

    private static func resetSingleStreamIfUnvalidated(
        writtenBytes: inout Int64,
        lockedValidator: StrongValidator?,
        writer: PosixOffsetFileWriter,
        progressReporter: ProgressReporter
    ) throws {
        guard writtenBytes > 0, lockedValidator == nil else { return }
        try writer.truncateToZero()
        writtenBytes = 0
        progressReporter.reportReset()
    }
}
