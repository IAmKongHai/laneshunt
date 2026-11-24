import Foundation

// MARK: - 多连接动态分片下载池（每槽独立 URLSession + 慢流看门狗）

internal extension LaneShunt {
    enum SegmentedRunOutcome {
        case completed(bytesWritten: Int64)
        case driftReset(reason: String)
    }

    private struct BenignCancelSignal: Error {}

    /// 多连接分片下载在各槽位之间共享的不可变执行上下文
    private struct SegmentedDownloadContext: Sendable {
        let url: URL
        let totalBytes: Int64
        let validator: StrongValidator
        let config: LaneShuntConfig
        let overallDeadline: TimeInterval
        let ledger: ChunkLedger
        let writer: PosixOffsetFileWriter
        let progressReporter: ProgressReporter
    }

    private struct ChunkAttemptStateData {
        var responseEnd: Int64
        var streamCursor: Int64
        var receivedInRequest: Int64 = 0
        var madeProgress: Bool = false
        var earlyOutcome: ChunkAttemptOutcome?
    }

    /// 编排多连接分片下载：预分配临时文件、启动独立连接槽位池与看门狗，全部退出后校验并原子落盘
    static func runSegmentedDownload(
        finalURL: URL,
        destinationURL: URL,
        totalBytes: Int64,
        validator: StrongValidator,
        config: LaneShuntConfig,
        overallDeadline: TimeInterval,
        progressReporter: ProgressReporter
    ) async throws -> SegmentedRunOutcome {
        let writer = try PosixOffsetFileWriter(near: destinationURL)
        var writerFinalized = false
        defer {
            if !writerFinalized {
                writer.closeAndCleanup()
            }
        }

        try writer.preallocate(totalSize: totalBytes, maxBytes: config.maxBytes)

        let startedAt = monotonicNow()
        let ledger = ChunkLedger(totalBytes: totalBytes, config: config, startedAt: startedAt)
        let workerCount = max(1, min(config.maxConnections, ledger.chunkCount))
        let context = SegmentedDownloadContext(
            url: finalURL,
            totalBytes: totalBytes,
            validator: validator,
            config: config,
            overallDeadline: overallDeadline,
            ledger: ledger,
            writer: writer,
            progressReporter: progressReporter
        )

        let watchdogQueue = DispatchQueue(label: "com.laneshunt.watchdog", qos: .utility)
        let watchdogTimer = DispatchSource.makeTimerSource(queue: watchdogQueue)
        let intervalMs = max(20, Int(config.watchdogInterval * 1000))
        watchdogTimer.schedule(
            deadline: .now() + .milliseconds(intervalMs),
            repeating: .milliseconds(intervalMs)
        )
        watchdogTimer.setEventHandler {
            let now = monotonicNow()
            if now >= overallDeadline {
                let cancels = ledger.abort(
                    .fatalError(.timeout("Download exceeded total timeout of \(Int(config.totalTimeout))s"))
                )
                for cancel in cancels { cancel() }
                return
            }
            for cancel in ledger.evaluateWatchdog(now: now) {
                cancel()
            }
        }
        watchdogTimer.resume()
        defer {
            watchdogTimer.cancel()
        }

        // 所有 Worker 在同一个 TaskGroup 中运行，退出前保证全部 Worker 完成并释放各自的 URLSession
        await withTaskCancellationHandler {
            await withTaskGroup(of: Void.self) { group in
                for slotID in 0..<workerCount {
                    group.addTask {
                        await runWorkerSlot(slotID: slotID, context: context)
                    }
                }
                for await _ in group {}
            }
        } onCancel: {
            let cancels = ledger.abort(.cancelled)
            for cancel in cancels { cancel() }
        }

        watchdogTimer.cancel()
        config.onDiagnostics?(ledger.diagnosticsSnapshot())

        // 严格退出顺序：全部 Worker 已退出 -> 检查结果 -> 验尺寸/sync/关句柄/原子落位（非成功路径由 defer 清理）
        if Task.isCancelled {
            throw CancellationError()
        }

        if let abortReason = ledger.currentAbortReason() {
            switch abortReason {
            case .cancelled:
                throw CancellationError()
            case .driftReset(let reason):
                return .driftReset(reason: reason)
            case .fatalError(let err):
                throw err
            }
        }

        guard ledger.isCompleted() else {
            throw LaneShuntError.retriesExhausted(
                attempts: 1,
                underlyingDescription: "Segmented download ended before all chunks completed",
                isTimeout: false
            )
        }

        let finalizedSize = try writer.finalize(expectedSize: totalBytes, destinationURL: destinationURL)
        writerFinalized = true
        return .completed(bytesWritten: finalizedSize)
    }

    private static func runWorkerSlot(
        slotID: Int,
        context: SegmentedDownloadContext
    ) async {
        let config = context.config
        let ledger = context.ledger
        var generation: UInt64 = 1
        var driver = IsolatedSessionDriver(
            label: "slot-\(slotID)-g\(generation)",
            config: config,
            requestTimeout: max(config.effectiveChunkStallTimeout * 2, config.singleStreamIdleTimeout),
            resourceTimeout: config.totalTimeout
        )
        ledger.markSlotSessionCreated(slotID: slotID, now: monotonicNow())

        defer {
            driver.invalidateAndCancel()
        }

        func rebuildSlotSession() {
            driver.invalidateAndCancel()
            generation += 1
            driver = IsolatedSessionDriver(
                label: "slot-\(slotID)-g\(generation)",
                config: config,
                requestTimeout: max(config.effectiveChunkStallTimeout * 2, config.singleStreamIdleTimeout),
                resourceTimeout: config.totalTimeout
            )
            ledger.markSlotSessionCreated(slotID: slotID, now: monotonicNow())
        }

        while !Task.isCancelled {
            if ledger.consumeNeedsSessionRotation(slotID: slotID) {
                rebuildSlotSession()
            }

            let now = monotonicNow()
            if now >= context.overallDeadline {
                let cancels = ledger.abort(
                    .fatalError(.timeout("Download exceeded total timeout of \(Int(config.totalTimeout))s"))
                )
                for cancel in cancels { cancel() }
                break
            }

            switch ledger.claimWork(slotID: slotID, now: now) {
            case .allDone, .aborted:
                return

            case .wait(let deadline, let version):
                do {
                    try await ledger.waitForWakeup(sinceVersion: version, until: min(deadline, context.overallDeadline))
                } catch {
                    return
                }

            case .work(let claimed):
                await executeChunkWork(
                    claimed: claimed,
                    slotID: slotID,
                    driver: driver,
                    context: context
                )
            }
        }
    }

    private static func executeChunkWork(
        claimed: ClaimedChunkWork,
        slotID: Int,
        driver: IsolatedSessionDriver,
        context: SegmentedDownloadContext
    ) async {
        let request = makeGETRequest(
            url: context.url,
            userAgent: context.config.userAgent,
            range: "bytes=\(claimed.startOffset)-\(claimed.endOffset)",
            ifRange: context.validator.ifRangeHeaderValue
        )

        let state = LockedState(
            ChunkAttemptStateData(
                responseEnd: claimed.endOffset,
                streamCursor: claimed.startOffset
            )
        )
        var finalOutcome: ChunkAttemptOutcome = .completedCleanly

        do {
            try await driver.runTask(
                request: request,
                idleTimeout: context.config.effectiveChunkStallTimeout,
                overallDeadline: context.overallDeadline,
                onTaskCreated: { cancelCurrentTask in
                    let attached = context.ledger.attachCancelHandler(
                        chunkIndex: claimed.chunkIndex,
                        attemptSeq: claimed.attemptSeq,
                        handler: cancelCurrentTask
                    )
                    if !attached {
                        cancelCurrentTask()
                    }
                },
                onResponse: { response, _ in
                    let evaluation = HTTPPolicy.evaluateChunkResponse(
                        response,
                        requestedStart: claimed.startOffset,
                        requestedEnd: claimed.endOffset,
                        lockedTotal: context.totalBytes,
                        lockedValidator: context.validator,
                        maxRetryAfterDelay: context.config.maxRetryAfterDelay
                    )
                    switch evaluation {
                    case .valid(let respEnd):
                        state.withLock { $0.responseEnd = respEnd }
                        return .allow

                    case .driftReset(let reason):
                        state.withLock { $0.earlyOutcome = .driftReset(reason: reason) }
                        return .stopEarlySuccess

                    case .rateLimitBackoff(let statusCode, let retryAfter):
                        state.withLock {
                            $0.earlyOutcome = .transientFailure(
                                description: "HTTP \(statusCode)",
                                retryAfter: retryAfter,
                                isRateLimit: true,
                                rotateSession: false
                            )
                        }
                        return .stopEarlySuccess

                    case .deterministicFailure(let err):
                        throw err

                    case .transientFailure(let desc):
                        state.withLock {
                            $0.earlyOutcome = .transientFailure(
                                description: desc,
                                retryAfter: nil,
                                isRateLimit: false,
                                rotateSession: true
                            )
                        }
                        return .stopEarlySuccess
                    }
                },
                onData: { data in
                    let current = state.withLock {
                        (cursor: $0.streamCursor, respEnd: $0.responseEnd, received: $0.receivedInRequest)
                    }
                    let segmentLen = current.respEnd - claimed.startOffset + 1
                    let nextReceived = current.received + Int64(data.count)
                    if nextReceived > segmentLen {
                        throw LaneShuntError.sizeLimitExceeded(limit: segmentLen, actual: nextReceived)
                    }

                    let commit = try context.ledger.commitData(
                        chunkIndex: claimed.chunkIndex,
                        attemptSeq: claimed.attemptSeq,
                        streamOffset: current.cursor,
                        data: data,
                        writer: context.writer,
                        now: monotonicNow()
                    )

                    state.withLock {
                        $0.streamCursor = current.cursor + Int64(data.count)
                        $0.receivedInRequest = nextReceived
                        if commit.uniqueBytesWritten > 0 {
                            $0.madeProgress = true
                        }
                    }

                    for loserCancel in commit.loserCancelHandlers {
                        loserCancel()
                    }
                    if commit.uniqueBytesWritten > 0 {
                        context.progressReporter.report(
                            bytesReceived: commit.totalCommittedBytes,
                            totalBytes: context.totalBytes,
                            force: commit.chunkCompleted && commit.totalCommittedBytes >= context.totalBytes
                        )
                    }
                    if commit.wasBenignlyCancelled {
                        throw BenignCancelSignal()
                    }
                }
            )

            if let early = state.withLock({ $0.earlyOutcome }) {
                finalOutcome = early
            }
        } catch is BenignCancelSignal {
            finalOutcome = .completedCleanly
        } catch is CancellationError {
            finalOutcome = .taskCancelled
        } catch let err as LaneShuntError {
            finalOutcome = .fatalError(err)
        } catch {
            if Task.isCancelled {
                finalOutcome = .taskCancelled
            } else {
                let isCancelledURL = (error as? URLError)?.code == .cancelled
                if isCancelledURL || HTTPPolicy.isTransientNetworkError(error) {
                    // 瞬态网络故障及看门狗轮换/对冲落败引发的取消统一交给账本按 attemptSeq 精准识别
                    finalOutcome = .transientFailure(
                        description: error.localizedDescription,
                        retryAfter: nil,
                        isRateLimit: false,
                        rotateSession: true,
                        isTimeout: isTimeoutError(error)
                    )
                } else {
                    // 证书校验失败等非瞬态底层错误直接快速失败，避免在分片重试配额上反复空转
                    finalOutcome = .fatalError(
                        .retriesExhausted(
                            attempts: 1,
                            underlyingDescription: error.localizedDescription,
                            isTimeout: isTimeoutError(error)
                        )
                    )
                }
            }
        }

        let siblingCancels = context.ledger.finishAttempt(
            chunkIndex: claimed.chunkIndex,
            slotID: slotID,
            attemptSeq: claimed.attemptSeq,
            madeProgress: state.withLock { $0.madeProgress },
            outcome: finalOutcome,
            now: monotonicNow()
        )
        for cancel in siblingCancels {
            cancel()
        }
    }
}
