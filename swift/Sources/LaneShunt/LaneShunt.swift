import Foundation

/// 零外部依赖、零业务耦合的原生多连接动态分片 HTTP 下载引擎
public enum LaneShunt {
    /// 下载目标文件至 `destinationURL`（先写入同目录独占临时文件，校验完整后原子替换落位）
    public static func download(
        from url: URL,
        to destinationURL: URL,
        config: LaneShuntConfig = LaneShuntConfig(),
        onProgress: (@Sendable (DownloadProgress) -> Void)? = nil
    ) async throws -> DownloadResult {
        try HTTPPolicy.validateURL(url, requireHTTPS: config.requireHTTPS)
        guard config.maxBytes >= 0 else {
            throw LaneShuntError.sizeLimitExceeded(limit: config.maxBytes, actual: 0)
        }
        guard !Task.isCancelled else {
            throw CancellationError()
        }

        let effectiveConfig = sanitizeConfig(config)
        let overallDeadline = monotonicNow() + effectiveConfig.totalTimeout
        let progressReporter = ProgressReporter(
            minInterval: effectiveConfig.progressMinInterval,
            handler: onProgress
        )
        defer {
            progressReporter.drain()
        }

        // 小于分片阈值或单连接模式：跳过探针直走单流可续传下载，避免额外请求
        let skipProbe: Bool
        if effectiveConfig.maxConnections <= 1 {
            skipProbe = true
        } else if let hint = effectiveConfig.expectedSizeHint,
                  hint > 0,
                  hint < effectiveConfig.minSegmentedSize
        {
            skipProbe = true
        } else {
            skipProbe = false
        }

        if skipProbe {
            return try await runSingleStreamDownload(
                url: url,
                destinationURL: destinationURL,
                config: effectiveConfig,
                startingAttempt: 1,
                existingWriter: nil,
                initialWrittenBytes: 0,
                initialValidator: nil,
                initialTotalBytes: effectiveConfig.expectedSizeHint,
                overallDeadline: overallDeadline,
                progressReporter: progressReporter
            )
        }

        return try await runProbedDownload(
            url: url,
            destinationURL: destinationURL,
            config: effectiveConfig,
            overallDeadline: overallDeadline,
            progressReporter: progressReporter
        )
    }

    // MARK: - 探针分流与全量重置主循环

    private static func runProbedDownload(
        url: URL,
        destinationURL: URL,
        config: LaneShuntConfig,
        overallDeadline: TimeInterval,
        progressReporter: ProgressReporter
    ) async throws -> DownloadResult {
        var attempt = 1
        var fullResetsUsed = 0

        while true {
            try checkCancellationAndDeadline(overallDeadline: overallDeadline, config: config)

            let probeResult: ProbeExecutionOutcome
            do {
                probeResult = try await executeProbeAttempt(
                    url: url,
                    destinationURL: destinationURL,
                    config: config,
                    overallDeadline: overallDeadline,
                    progressReporter: progressReporter
                )
            } catch is CancellationError {
                throw CancellationError()
            } catch let err as LaneShuntError {
                throw err
            } catch {
                if Task.isCancelled {
                    throw CancellationError()
                }
                if HTTPPolicy.isTransientNetworkError(error), attempt < config.maxAttempts {
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

            switch probeResult {
            case .completedOneByte(let finalURL, let byte):
                let writer = try PosixOffsetFileWriter(near: destinationURL)
                do {
                    try writer.write(Data([byte]), atOffset: 0)
                    let written = try writer.finalize(expectedSize: 1, destinationURL: destinationURL)
                    progressReporter.report(bytesReceived: 1, totalBytes: 1, force: true)
                    return DownloadResult(
                        finalURL: finalURL,
                        bytesWritten: written,
                        totalBytes: 1,
                        attemptsUsed: attempt,
                        usedSegmented: false
                    )
                } catch {
                    writer.closeAndCleanup()
                    throw error
                }

            case .completedEmptyFile(let finalURL):
                let writer = try PosixOffsetFileWriter(near: destinationURL)
                do {
                    let written = try writer.finalize(expectedSize: 0, destinationURL: destinationURL)
                    progressReporter.report(bytesReceived: 0, totalBytes: 0, force: true)
                    return DownloadResult(
                        finalURL: finalURL,
                        bytesWritten: written,
                        totalBytes: 0,
                        attemptsUsed: attempt,
                        usedSegmented: false
                    )
                } catch {
                    writer.closeAndCleanup()
                    throw error
                }

            case .completedSingleStream200(let finalURL, let writtenBytes):
                progressReporter.report(bytesReceived: writtenBytes, totalBytes: writtenBytes, force: true)
                return DownloadResult(
                    finalURL: finalURL,
                    bytesWritten: writtenBytes,
                    totalBytes: writtenBytes,
                    attemptsUsed: attempt,
                    usedSegmented: false
                )

            case .interruptedSingleStream200(let finalURL, let writer, let writtenBytes, let validator, let expectedTotal, let errorDescription, let isTimeout):
                if attempt < config.maxAttempts {
                    try await cancellableSleep(seconds: config.retryDelay, overallDeadline: overallDeadline, config: config)
                    return try await runSingleStreamDownload(
                        url: finalURL,
                        destinationURL: destinationURL,
                        config: config,
                        startingAttempt: attempt + 1,
                        existingWriter: writer,
                        initialWrittenBytes: writtenBytes,
                        initialValidator: validator,
                        initialTotalBytes: expectedTotal ?? config.expectedSizeHint,
                        overallDeadline: overallDeadline,
                        progressReporter: progressReporter
                    )
                }
                writer.closeAndCleanup()
                throw LaneShuntError.retriesExhausted(
                    attempts: attempt,
                    underlyingDescription: errorDescription,
                    isTimeout: isTimeout
                )

            case .downgradeToSingleStream(let finalURL):
                // 不合格 206 在同一次 attempt 内零成本降级至普通无 Range 单流 GET
                return try await runSingleStreamDownload(
                    url: finalURL,
                    destinationURL: destinationURL,
                    config: config,
                    startingAttempt: attempt,
                    existingWriter: nil,
                    initialWrittenBytes: 0,
                    initialValidator: nil,
                    initialTotalBytes: config.expectedSizeHint,
                    overallDeadline: overallDeadline,
                    progressReporter: progressReporter
                )

            case .proceedSegmented(let finalURL, let totalBytes, let validator):
                let segOutcome = try await runSegmentedDownload(
                    finalURL: finalURL,
                    destinationURL: destinationURL,
                    totalBytes: totalBytes,
                    validator: validator,
                    config: config,
                    overallDeadline: overallDeadline,
                    progressReporter: progressReporter
                )
                switch segOutcome {
                case .completed(let bytesWritten):
                    progressReporter.report(bytesReceived: bytesWritten, totalBytes: totalBytes, force: true)
                    return DownloadResult(
                        finalURL: finalURL,
                        bytesWritten: bytesWritten,
                        totalBytes: totalBytes,
                        attemptsUsed: attempt,
                        usedSegmented: true
                    )

                case .driftReset(let reason):
                    progressReporter.reportReset()
                    if fullResetsUsed < config.maxFullResets {
                        fullResetsUsed += 1
                        continue
                    }
                    throw LaneShuntError.retriesExhausted(
                        attempts: attempt,
                        underlyingDescription: "Resource changed repeatedly during segmented download (\(reason))",
                        isTimeout: false
                    )
                }

            case .retryableBackoff(let statusCode, let retryAfter):
                if attempt < config.maxAttempts {
                    attempt += 1
                    let wait = min(config.maxRetryAfterDelay, retryAfter ?? config.retryDelay)
                    try await cancellableSleep(seconds: wait, overallDeadline: overallDeadline, config: config)
                    continue
                }
                throw LaneShuntError.retriesExhausted(
                    attempts: attempt,
                    underlyingDescription: "HTTP \(statusCode)",
                    isTimeout: false
                )

            case .retryableTransient(let description):
                if attempt < config.maxAttempts {
                    attempt += 1
                    try await cancellableSleep(seconds: config.retryDelay, overallDeadline: overallDeadline, config: config)
                    continue
                }
                throw LaneShuntError.retriesExhausted(
                    attempts: attempt,
                    underlyingDescription: description,
                    isTimeout: false
                )
            }
        }
    }

    // MARK: - 内部通用辅助函数

    internal static func makeGETRequest(
        url: URL,
        userAgent: String?,
        range: String? = nil,
        ifRange: String? = nil
    ) -> URLRequest {
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
        if let userAgent {
            request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        }
        if let range {
            request.setValue(range, forHTTPHeaderField: "Range")
        }
        if let ifRange {
            request.setValue(ifRange, forHTTPHeaderField: "If-Range")
        }
        return request
    }

    internal static func isTimeoutError(_ error: Error) -> Bool {
        if let urlError = error as? URLError, urlError.code == .timedOut {
            return true
        }
        if case .timeout = error as? LaneShuntError {
            return true
        }
        return false
    }

    internal static func sanitizeConfig(_ raw: LaneShuntConfig) -> LaneShuntConfig {
        var cfg = raw
        cfg.maxConnections = max(1, cfg.maxConnections)
        cfg.chunkSize = max(1, cfg.chunkSize)
        cfg.minSegmentedSize = max(1, cfg.minSegmentedSize)
        cfg.maxAttempts = max(1, cfg.maxAttempts)
        cfg.maxFullResets = max(0, cfg.maxFullResets)
        cfg.maxRedirects = max(0, cfg.maxRedirects)
        cfg.retryDelay = max(0, cfg.retryDelay)
        cfg.singleStreamIdleTimeout = max(0.05, cfg.singleStreamIdleTimeout)
        cfg.chunkStallTimeout = max(0.05, cfg.chunkStallTimeout)
        cfg.totalTimeout = max(0.1, cfg.totalTimeout)
        cfg.watchdogInterval = max(0.02, cfg.watchdogInterval)
        cfg.maxConcurrentHedges = max(0, cfg.maxConcurrentHedges)
        cfg.maxChunkRetries = max(0, cfg.maxChunkRetries)
        return cfg
    }

    internal static func monotonicNow() -> TimeInterval {
        ProcessInfo.processInfo.systemUptime
    }

    internal static func checkCancellationAndDeadline(
        overallDeadline: TimeInterval,
        config: LaneShuntConfig
    ) throws {
        if Task.isCancelled {
            throw CancellationError()
        }
        if monotonicNow() >= overallDeadline {
            throw LaneShuntError.timeout("Download exceeded total timeout of \(Int(config.totalTimeout))s")
        }
    }

    internal static func cancellableSleep(
        seconds: TimeInterval,
        overallDeadline: TimeInterval,
        config: LaneShuntConfig
    ) async throws {
        let now = monotonicNow()
        if now >= overallDeadline {
            throw LaneShuntError.timeout("Download exceeded total timeout of \(Int(config.totalTimeout))s")
        }
        let clamped = min(seconds, max(0, overallDeadline - now))
        guard clamped > 0 else { return }
        let ns = UInt64(clamped * 1_000_000_000)
        try await Task.sleep(nanoseconds: ns)
        try checkCancellationAndDeadline(overallDeadline: overallDeadline, config: config)
    }
}
