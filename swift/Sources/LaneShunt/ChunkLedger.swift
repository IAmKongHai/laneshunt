import Foundation

/// 不可变微切片的单次拉取任务描述
struct ClaimedChunkWork: Sendable {
    let chunkIndex: Int
    let attemptSeq: UInt64
    let startOffset: Int64
    let endOffset: Int64
    let isHedge: Bool
}

/// Worker 向账本领取任务时的调度结果
enum ChunkClaimDecision: Sendable {
    case work(ClaimedChunkWork)
    case wait(until: TimeInterval, stateVersion: UInt64)
    case allDone
    case aborted
}

/// 单个微切片尝试结束时的结果分类
enum ChunkAttemptOutcome: Sendable {
    case completedCleanly
    case transientFailure(
        description: String,
        retryAfter: TimeInterval?,
        isRateLimit: Bool,
        rotateSession: Bool,
        isTimeout: Bool = false
    )
    case driftReset(reason: String)
    case fatalError(LaneShuntError)
    case taskCancelled
}

/// 增量写盘提交后的状态反馈
struct ChunkCommitResult: Sendable {
    let uniqueBytesWritten: Int64
    let totalCommittedBytes: Int64
    let chunkCompleted: Bool
    let wasBenignlyCancelled: Bool
    let loserCancelHandlers: [@Sendable () -> Void]
}

/// 分段下载中止原因
enum LedgerAbortReason: Sendable {
    case driftReset(String)
    case fatalError(LaneShuntError)
    case cancelled
}

/// 中心化并发分块账本：管理不可变微切片、尾块对冲、零字节停滞与限流退避
final class ChunkLedger: @unchecked Sendable {
    private enum RotationTrigger {
        case stall
        case slowOrScout
    }

    private struct ActiveAttempt {
        let attemptSeq: UInt64
        let slotID: Int
        let isHedge: Bool
        let startedAt: TimeInterval
        var lastByteAt: TimeInterval
        var receivedCursor: Int64
        var deliveredBytes: Int64
        var cancelHandler: (@Sendable () -> Void)?
    }

    private struct ChunkState {
        let index: Int
        let end: Int64
        var committedOffset: Int64
        var retryCount: Int
        var notBefore: TimeInterval
        var isQueued: Bool
        var activeAttempts: [UInt64: ActiveAttempt]

        var isComplete: Bool { committedOffset > end }
    }

    let totalBytes: Int64
    let chunkSize: Int64
    let chunkCount: Int

    private let config: LaneShuntConfig
    private let maxTotalTransientFailures: Int
    private let lock = NSLock()
    private let waiterQueue: LedgerWaiterQueue

    /// 块级串行提交锁：仅在被对冲的单个微切片内串行化 `pwrite` 与 `committedOffset` 推进，锁顺序严格为 `chunkCommitLock -> lock`
    private let chunkCommitLocks: [NSLock]

    private var chunks: [ChunkState]
    private var nextUnclaimedChunkIndex: Int = 0
    private var requeuedChunks: [Int] = []
    private var inFlightChunkIndices: Set<Int> = []
    private var completedChunkCount: Int = 0
    private var totalCommittedBytes: Int64 = 0
    private var nextAttemptSeq: UInt64 = 1

    private var speedTracker: SlotSpeedTracker
    private var activeHedgeCount: Int = 0
    private var totalHedgesLaunched: Int = 0
    private var peakConcurrentHedges: Int = 0

    /// 良性取消集合（尾块对冲落败或块已完成）与主动轮换触发原因映射（不误计入故障）
    private var benignlyCancelledSeqs: Set<UInt64> = []
    private var rotatedAttemptTriggers: [UInt64: RotationTrigger] = [:]

    /// 限流全局退避与瞬态失败预算
    private var retryNotBefore: TimeInterval = 0
    private var lastBackoffWindowEnd: TimeInterval = 0
    private var backoffWaveCount: Int = 0
    private var totalTransientFailures: Int = 0

    /// 终止状态
    private var abortReason: LedgerAbortReason?
    private var isAllDoneFlag: Bool = false

    init(
        totalBytes: Int64,
        config: LaneShuntConfig,
        startedAt: TimeInterval = ProcessInfo.processInfo.systemUptime
    ) {
        self.totalBytes = max(0, totalBytes)
        let effectiveChunkSize = max(1, config.chunkSize)
        self.chunkSize = effectiveChunkSize
        self.config = config
        self.waiterQueue = LedgerWaiterQueue(lock: self.lock)

        let count = totalBytes <= 0 ? 0 : Int((totalBytes + effectiveChunkSize - 1) / effectiveChunkSize)
        self.chunkCount = count
        self.maxTotalTransientFailures = max(12, count * 2)

        var builtChunks: [ChunkState] = []
        builtChunks.reserveCapacity(count)
        for index in 0..<count {
            let start = Int64(index) * effectiveChunkSize
            let end = min(start + effectiveChunkSize - 1, totalBytes - 1)
            builtChunks.append(
                ChunkState(
                    index: index,
                    end: end,
                    committedOffset: start,
                    retryCount: 0,
                    notBefore: 0,
                    isQueued: true,
                    activeAttempts: [:]
                )
            )
        }
        self.chunks = builtChunks

        let slotCount = max(1, config.maxConnections)
        let stripeCount = max(16, slotCount * 4)
        self.chunkCommitLocks = (0..<stripeCount).map { _ in NSLock() }
        self.speedTracker = SlotSpeedTracker(slotCount: slotCount, config: config, startedAt: startedAt)
        self.isAllDoneFlag = (count == 0)
    }

    // MARK: - 槽位与任务领取

    /// 槽位重建全新 `URLSession` 后调用，刷新预热起算时间并清除旧速度样本
    func markSlotSessionCreated(slotID: Int, now: TimeInterval) {
        lock.lock()
        defer { lock.unlock() }
        speedTracker.markSlotSessionCreated(slotID: slotID, now: now)
    }

    /// 检查槽位是否已被看门狗标记需要重建独立会话
    func consumeNeedsSessionRotation(slotID: Int) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return speedTracker.consumeNeedsSessionRotation(slotID: slotID)
    }

    /// 槽位尝试领取下一个不可变微切片或有上限尾块对冲任务
    func claimWork(slotID: Int, now: TimeInterval) -> ChunkClaimDecision {
        lock.lock()
        defer { lock.unlock() }

        if abortReason != nil {
            return .aborted
        }
        if isAllDoneFlag || completedChunkCount >= chunkCount {
            isAllDoneFlag = true
            return .allDone
        }
        guard speedTracker.containsSlot(slotID) else {
            return .aborted
        }

        if !speedTracker.canSlotStartWork(slotID: slotID) {
            return .wait(
                until: now + max(0.05, config.watchdogInterval),
                stateVersion: waiterQueue.stateVersion
            )
        }

        if now < retryNotBefore {
            return .wait(until: retryNotBefore, stateVersion: waiterQueue.stateVersion)
        }

        var earliestRetryAt: TimeInterval?
        switch popNextPendingChunkLocked(now: now) {
        case .ready(let chunkIndex):
            let claimed = registerClaimLocked(chunkIndex: chunkIndex, slotID: slotID, isHedge: false, now: now)
            return .work(claimed)
        case .delayed(let readyAt):
            earliestRetryAt = readyAt
        case .none:
            break
        }

        if let hedgeChunkIndex = selectTailHedgeCandidateLocked(forSlotID: slotID, now: now) {
            let claimed = registerClaimLocked(chunkIndex: hedgeChunkIndex, slotID: slotID, isHedge: true, now: now)
            activeHedgeCount += 1
            totalHedgesLaunched += 1
            if activeHedgeCount > peakConcurrentHedges {
                peakConcurrentHedges = activeHedgeCount
            }
            return .work(claimed)
        }

        let defaultWaitUntil = now + max(0.05, config.watchdogInterval)
        let waitUntil: TimeInterval
        if let earliestRetryAt {
            waitUntil = inFlightChunkIndices.isEmpty
                ? earliestRetryAt
                : min(earliestRetryAt, defaultWaitUntil)
        } else {
            waitUntil = defaultWaitUntil
        }
        return .wait(
            until: waitUntil,
            stateVersion: waiterQueue.stateVersion
        )
    }

    private enum PendingChunkLookup {
        case ready(Int)
        case delayed(earliestReadyAt: TimeInterval)
        case none
    }

    /// 优先弹出已到就绪时间的重试块，跳过仍在退避窗口内的块；若重试队列均在退避中则先派发未领取新分片
    private func popNextPendingChunkLocked(now: TimeInterval) -> PendingChunkLookup {
        var earliestDelayedAt: TimeInterval?
        var idx = requeuedChunks.count - 1
        while idx >= 0 {
            let chunkIndex = requeuedChunks[idx]
            if chunks[chunkIndex].isComplete || !chunks[chunkIndex].activeAttempts.isEmpty {
                chunks[chunkIndex].isQueued = false
                requeuedChunks.remove(at: idx)
                idx -= 1
                continue
            }
            let readyAt = chunks[chunkIndex].notBefore
            if readyAt <= now {
                chunks[chunkIndex].isQueued = false
                requeuedChunks.remove(at: idx)
                return .ready(chunkIndex)
            }
            if let existing = earliestDelayedAt {
                earliestDelayedAt = min(existing, readyAt)
            } else {
                earliestDelayedAt = readyAt
            }
            idx -= 1
        }
        while nextUnclaimedChunkIndex < chunkCount {
            let chunkIndex = nextUnclaimedChunkIndex
            nextUnclaimedChunkIndex += 1
            chunks[chunkIndex].isQueued = false
            if !chunks[chunkIndex].isComplete && chunks[chunkIndex].activeAttempts.isEmpty {
                return .ready(chunkIndex)
            }
        }
        if let earliestDelayedAt {
            return .delayed(earliestReadyAt: earliestDelayedAt)
        }
        return .none
    }

    private func registerClaimLocked(
        chunkIndex: Int,
        slotID: Int,
        isHedge: Bool,
        now: TimeInterval
    ) -> ClaimedChunkWork {
        let seq = nextAttemptSeq
        nextAttemptSeq += 1

        chunks[chunkIndex].notBefore = 0
        let startOffset = chunks[chunkIndex].committedOffset
        let endOffset = chunks[chunkIndex].end

        chunks[chunkIndex].activeAttempts[seq] = ActiveAttempt(
            attemptSeq: seq,
            slotID: slotID,
            isHedge: isHedge,
            startedAt: now,
            lastByteAt: now,
            receivedCursor: startOffset,
            deliveredBytes: 0,
            cancelHandler: nil
        )
        inFlightChunkIndices.insert(chunkIndex)
        speedTracker.registerSlotWorking(slotID: slotID, chunkIndex: chunkIndex, attemptSeq: seq)

        return ClaimedChunkWork(
            chunkIndex: chunkIndex,
            attemptSeq: seq,
            startOffset: startOffset,
            endOffset: endOffset,
            isHedge: isHedge
        )
    }

    /// 绑定活跃尝试的取消句柄；若该尝试已被提前取消或账本已中止，返回 `false` 供调用方立刻取消
    @discardableResult
    func attachCancelHandler(
        chunkIndex: Int,
        attemptSeq: UInt64,
        handler: @escaping @Sendable () -> Void
    ) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard abortReason == nil,
              chunks.indices.contains(chunkIndex),
              chunks[chunkIndex].activeAttempts[attemptSeq] != nil
        else {
            return false
        }
        chunks[chunkIndex].activeAttempts[attemptSeq]?.cancelHandler = handler
        return true
    }

    // MARK: - 块级串行 First-Writer-Wins 增量落盘

    /// 串行化单分片写盘与唯一字节推进，先到者提交后返回需在锁外触发的落败对冲流取消句柄
    func commitData(
        chunkIndex: Int,
        attemptSeq: UInt64,
        streamOffset: Int64,
        data: Data,
        writer: PosixOffsetFileWriter,
        now: TimeInterval
    ) throws -> ChunkCommitResult {
        guard !data.isEmpty else {
            return ChunkCommitResult(
                uniqueBytesWritten: 0,
                totalCommittedBytes: currentCommittedBytes(),
                chunkCompleted: false,
                wasBenignlyCancelled: false,
                loserCancelHandlers: []
            )
        }

        let commitLock = chunkCommitLocks[chunkIndex % chunkCommitLocks.count]
        commitLock.lock()
        defer { commitLock.unlock() }

        let writeStart: Int64
        let dropPrefix: Int
        let writeCount: Int
        let slotID: Int

        lock.lock()
        if abortReason != nil {
            let committed = totalCommittedBytes
            lock.unlock()
            return ChunkCommitResult(
                uniqueBytesWritten: 0,
                totalCommittedBytes: committed,
                chunkCompleted: false,
                wasBenignlyCancelled: true,
                loserCancelHandlers: []
            )
        }

        guard var attempt = chunks[chunkIndex].activeAttempts[attemptSeq] else {
            let committed = totalCommittedBytes
            let alreadyDone = chunks[chunkIndex].isComplete
            lock.unlock()
            return ChunkCommitResult(
                uniqueBytesWritten: 0,
                totalCommittedBytes: committed,
                chunkCompleted: alreadyDone,
                wasBenignlyCancelled: true,
                loserCancelHandlers: []
            )
        }

        slotID = attempt.slotID
        let dataCount = Int64(data.count)
        attempt.lastByteAt = now
        attempt.receivedCursor = max(attempt.receivedCursor, streamOffset + dataCount)
        attempt.deliveredBytes += dataCount
        chunks[chunkIndex].activeAttempts[attemptSeq] = attempt

        speedTracker.recordSlotSample(slotID: slotID, bytes: dataCount, now: now)

        let chunk = chunks[chunkIndex]
        if chunk.isComplete {
            let committed = totalCommittedBytes
            lock.unlock()
            return ChunkCommitResult(
                uniqueBytesWritten: 0,
                totalCommittedBytes: committed,
                chunkCompleted: true,
                wasBenignlyCancelled: true,
                loserCancelHandlers: []
            )
        }

        let bufStart = streamOffset
        let bufEnd = streamOffset + dataCount - 1
        if bufEnd < chunk.committedOffset {
            let committed = totalCommittedBytes
            lock.unlock()
            return ChunkCommitResult(
                uniqueBytesWritten: 0,
                totalCommittedBytes: committed,
                chunkCompleted: false,
                wasBenignlyCancelled: false,
                loserCancelHandlers: []
            )
        }

        writeStart = max(bufStart, chunk.committedOffset)
        let writeEnd = min(bufEnd, chunk.end)
        guard writeStart <= writeEnd else {
            let committed = totalCommittedBytes
            lock.unlock()
            return ChunkCommitResult(
                uniqueBytesWritten: 0,
                totalCommittedBytes: committed,
                chunkCompleted: false,
                wasBenignlyCancelled: false,
                loserCancelHandlers: []
            )
        }
        dropPrefix = Int(writeStart - bufStart)
        writeCount = Int(writeEnd - writeStart + 1)
        lock.unlock()

        let sliceStart = data.index(data.startIndex, offsetBy: dropPrefix)
        let sliceEnd = data.index(sliceStart, offsetBy: writeCount)
        try writer.write(data[sliceStart..<sliceEnd], atOffset: writeStart)

        lock.lock()
        let newCommitted = writeStart + Int64(writeCount)
        if newCommitted > chunks[chunkIndex].committedOffset {
            let actualDelta = newCommitted - chunks[chunkIndex].committedOffset
            chunks[chunkIndex].committedOffset = newCommitted
            totalCommittedBytes += actualDelta
            speedTracker.recordGlobalCommittedBytes(actualDelta, at: now)
        }

        let justCompleted = chunks[chunkIndex].isComplete
        var loserCancels: [@Sendable () -> Void] = []

        if justCompleted {
            completedChunkCount += 1
            if let winningAttempt = chunks[chunkIndex].activeAttempts[attemptSeq] {
                let elapsed = max(0.005, now - winningAttempt.startedAt)
                let bytesDelivered = max(Int64(writeCount), winningAttempt.deliveredBytes)
                let speed = Double(bytesDelivered) / elapsed
                speedTracker.recordChunkCompleted(slotID: slotID, speed: speed, now: now)
            }

            let otherSeqs = chunks[chunkIndex].activeAttempts.keys.filter { $0 != attemptSeq }
            loserCancels = evictAttemptsLocked(chunkIndex: chunkIndex, seqs: otherSeqs)
            if completedChunkCount >= chunkCount {
                isAllDoneFlag = true
            }
            waiterQueue.notifyAllLocked()
        } else if chunks[chunkIndex].activeAttempts.count > 1 {
            // First-Writer-Wins：已提交水位严格领先兄弟对冲流时立刻良性取消落败流
            let committedNow = chunks[chunkIndex].committedOffset
            let loserSeqs = chunks[chunkIndex].activeAttempts.compactMap { seq, other -> UInt64? in
                guard seq != attemptSeq else { return nil }
                return other.receivedCursor < committedNow ? seq : nil
            }
            loserCancels = evictAttemptsLocked(chunkIndex: chunkIndex, seqs: loserSeqs)
        }

        let committedSnapshot = totalCommittedBytes
        lock.unlock()

        return ChunkCommitResult(
            uniqueBytesWritten: Int64(writeCount),
            totalCommittedBytes: committedSnapshot,
            chunkCompleted: justCompleted,
            wasBenignlyCancelled: false,
            loserCancelHandlers: loserCancels
        )
    }

    /// 结束单次分片尝试，更新失败/退避/重置状态并返回需要广播取消的兄弟句柄列表
    func finishAttempt(
        chunkIndex: Int,
        slotID: Int,
        attemptSeq: UInt64,
        madeProgress: Bool,
        outcome: ChunkAttemptOutcome,
        now: TimeInterval
    ) -> [@Sendable () -> Void] {
        lock.lock()
        var cancelHandlersToInvoke: [@Sendable () -> Void] = []

        if let removed = chunks[chunkIndex].activeAttempts.removeValue(forKey: attemptSeq) {
            if removed.isHedge {
                activeHedgeCount = max(0, activeHedgeCount - 1)
            }
            if chunks[chunkIndex].activeAttempts.isEmpty {
                inFlightChunkIndices.remove(chunkIndex)
            }
        }

        speedTracker.releaseSlotWorking(slotID: slotID, attemptSeq: attemptSeq)

        let wasBenign = benignlyCancelledSeqs.remove(attemptSeq) != nil
        let rotationTrigger = rotatedAttemptTriggers.removeValue(forKey: attemptSeq)
        if rotationTrigger != nil {
            speedTracker.markNeedsSessionRotation(slotID: slotID)
        }

        if abortReason != nil {
            waiterQueue.notifyAllLocked()
            lock.unlock()
            return []
        }

        // 终态结果（漂移重置、确定性错误、任务取消）优先于良性取消与看门狗轮换标记，避免误吞终止信号
        switch outcome {
        case .driftReset(let reason):
            cancelHandlersToInvoke = setAbortLocked(.driftReset(reason))
            waiterQueue.notifyAllLocked()
            lock.unlock()
            return cancelHandlersToInvoke

        case .fatalError(let error):
            cancelHandlersToInvoke = setAbortLocked(.fatalError(error))
            waiterQueue.notifyAllLocked()
            lock.unlock()
            return cancelHandlersToInvoke

        case .taskCancelled:
            cancelHandlersToInvoke = setAbortLocked(.cancelled)
            waiterQueue.notifyAllLocked()
            lock.unlock()
            return cancelHandlersToInvoke

        case .completedCleanly, .transientFailure:
            break
        }

        if wasBenign {
            requeueIfNeededLocked(chunkIndex: chunkIndex)
            waiterQueue.notifyAllLocked()
            lock.unlock()
            return []
        }

        // 若该微切片已提交完毕（例如末包刚好在停滞看门狗触发后落盘），直接视为完成且不记瞬态失败
        if chunks[chunkIndex].isComplete {
            if completedChunkCount >= chunkCount {
                isAllDoneFlag = true
            }
            waiterQueue.notifyAllLocked()
            lock.unlock()
            return []
        }

        if let trigger = rotationTrigger {
            switch trigger {
            case .stall:
                cancelHandlersToInvoke = recordTransientFailureLocked(
                    chunkIndex: chunkIndex,
                    reason: "Chunk \(chunkIndex) stalled repeatedly with zero bytes",
                    isTimeout: true,
                    applyBackoff: true,
                    now: now
                )
            case .slowOrScout:
                // 主动慢流轮换与有限侦察属于健康连接的优化切换，不消耗瞬态故障预算
                requeueIfNeededLocked(chunkIndex: chunkIndex)
            }
            waiterQueue.notifyAllLocked()
            lock.unlock()
            return cancelHandlersToInvoke
        }

        switch outcome {
        case .completedCleanly:
            if madeProgress {
                requeueIfNeededLocked(chunkIndex: chunkIndex)
            } else {
                cancelHandlersToInvoke = recordTransientFailureLocked(
                    chunkIndex: chunkIndex,
                    reason: "Chunk \(chunkIndex) completed without making byte progress",
                    isTimeout: false,
                    applyBackoff: true,
                    now: now
                )
            }

        case .transientFailure(let desc, let retryAfter, let isRateLimit, let rotateSession, let isTimeout):
            if rotateSession {
                speedTracker.markNeedsSessionRotation(slotID: slotID)
            }
            if isRateLimit {
                recordRateLimitBackoffLocked(retryAfter: retryAfter, now: now)
            }
            cancelHandlersToInvoke = recordTransientFailureLocked(
                chunkIndex: chunkIndex,
                reason: desc,
                isTimeout: isTimeout,
                applyBackoff: !isRateLimit,
                now: now
            )

        case .driftReset, .fatalError, .taskCancelled:
            break
        }

        waiterQueue.notifyAllLocked()
        lock.unlock()
        return cancelHandlersToInvoke
    }

    // MARK: - 看门狗巡检

    /// 看门狗定期巡检：返回需要立刻取消/轮换的句柄列表（由调用方在锁外执行）
    func evaluateWatchdog(now: TimeInterval) -> [@Sendable () -> Void] {
        lock.lock()
        defer { lock.unlock() }

        guard abortReason == nil, !isAllDoneFlag else { return [] }

        var actedSlotIDs: Set<Int> = []
        var actions = scanStalledAttemptsLocked(now: now, actedSlotIDs: &actedSlotIDs)

        if now < retryNotBefore {
            return actions
        }

        let (refHigh, aggregateSpeed) = speedTracker.refreshSpeedMetrics(now: now)

        if speedTracker.evaluateActiveScout(now: now, aggregateSpeed: aggregateSpeed) {
            waiterQueue.notifyAllLocked()
        }

        let lookupCancel: (Int, UInt64) -> (@Sendable () -> Void)? = { [chunks] chunkIdx, seq in
            chunks[chunkIdx].activeAttempts[seq]?.cancelHandler
        }

        if refHigh >= config.scoutHighSpeedThresholdBytesPerSec {
            if let rotated = speedTracker.selectRelativeSlowRotation(
                now: now,
                refHigh: refHigh,
                actedSlotIDs: &actedSlotIDs,
                cancelHandlerForAttempt: lookupCancel
            ) {
                rotatedAttemptTriggers[rotated.attemptSeq] = .slowOrScout
                actions.append(rotated.cancel)
            }
        } else if let scouted = speedTracker.evaluateBoundedScout(
            now: now,
            refHigh: refHigh,
            actedSlotIDs: actedSlotIDs,
            cancelHandlerForAttempt: lookupCancel
        ) {
            rotatedAttemptTriggers[scouted.attemptSeq] = .slowOrScout
            actions.append(scouted.cancel)
        }

        return actions
    }

    /// 扫描全部在途微切片，回收超过停滞阈值且零字节推进的尝试
    private func scanStalledAttemptsLocked(
        now: TimeInterval,
        actedSlotIDs: inout Set<Int>
    ) -> [@Sendable () -> Void] {
        var actions: [@Sendable () -> Void] = []
        let stallLimit = config.effectiveChunkStallTimeout
        for chunkIdx in inFlightChunkIndices {
            for attempt in chunks[chunkIdx].activeAttempts.values where now - attempt.lastByteAt >= stallLimit {
                rotatedAttemptTriggers[attempt.attemptSeq] = .stall
                speedTracker.markNeedsSessionRotation(slotID: attempt.slotID, clearSlowSince: true)
                actedSlotIDs.insert(attempt.slotID)
                if let cancel = attempt.cancelHandler {
                    actions.append(cancel)
                }
            }
        }
        return actions
    }

    // MARK: - 外部中止、状态查询与可取消等待

    /// 主动中止账本（例如外部取消或触及硬总超时），返回全部在途取消句柄
    func abort(_ reason: LedgerAbortReason) -> [@Sendable () -> Void] {
        lock.lock()
        let handlers = setAbortLocked(reason)
        waiterQueue.notifyAllLocked()
        lock.unlock()
        return handlers
    }

    func currentAbortReason() -> LedgerAbortReason? {
        lock.lock()
        defer { lock.unlock() }
        return abortReason
    }

    func isCompleted() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return isAllDoneFlag && abortReason == nil
    }

    func currentCommittedBytes() -> Int64 {
        lock.lock()
        defer { lock.unlock() }
        return totalCommittedBytes
    }

    func diagnosticsSnapshot() -> DownloaderDiagnosticsSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return DownloaderDiagnosticsSnapshot(
            activeSlotLimit: speedTracker.activeSlotLimit,
            totalRotations: speedTracker.totalRotations,
            totalScoutsUsed: speedTracker.totalScoutsUsed,
            scoutingPermanentlyDisabled: speedTracker.scoutingPermanentlyDisabled,
            totalHedgesLaunched: totalHedgesLaunched,
            peakConcurrentHedges: peakConcurrentHedges,
            lastReferenceHighSpeed: speedTracker.lastRefHighSpeed,
            lastAggregateSpeed: speedTracker.lastAggregateSpeed,
            backoffWaveCount: backoffWaveCount
        )
    }

    /// 可被 Swift Task 取消立即唤醒的事件/截止时间等待（基于 stateVersion 避免唤醒丢失）
    func waitForWakeup(sinceVersion expectedVersion: UInt64, until deadline: TimeInterval) async throws {
        try await waiterQueue.waitForWakeup(sinceVersion: expectedVersion, until: deadline) {
            abortReason != nil || isAllDoneFlag
        }
    }

    // MARK: - 内部私有辅助（调用前必须持有 `lock`）

    private func evictAttemptsLocked(chunkIndex: Int, seqs: [UInt64]) -> [@Sendable () -> Void] {
        var cancels: [@Sendable () -> Void] = []
        for otherSeq in seqs {
            if let removed = chunks[chunkIndex].activeAttempts.removeValue(forKey: otherSeq) {
                if removed.isHedge {
                    activeHedgeCount = max(0, activeHedgeCount - 1)
                }
                benignlyCancelledSeqs.insert(otherSeq)
                if let cancel = removed.cancelHandler {
                    cancels.append(cancel)
                }
            }
        }
        if chunks[chunkIndex].activeAttempts.isEmpty {
            inFlightChunkIndices.remove(chunkIndex)
        }
        return cancels
    }

    private func recordTransientFailureLocked(
        chunkIndex: Int,
        reason: String,
        isTimeout: Bool,
        applyBackoff: Bool,
        now: TimeInterval
    ) -> [@Sendable () -> Void] {
        chunks[chunkIndex].retryCount += 1
        totalTransientFailures += 1
        if chunks[chunkIndex].retryCount > config.maxChunkRetries ||
            totalTransientFailures > maxTotalTransientFailures
        {
            return setAbortLocked(
                .fatalError(
                    .retriesExhausted(
                        attempts: totalTransientFailures,
                        underlyingDescription: reason,
                        isTimeout: isTimeout
                    )
                )
            )
        }
        if applyBackoff {
            let backoff = chunkRetryBackoffDelay(chunkIndex: chunkIndex, retryCount: chunks[chunkIndex].retryCount)
            if backoff > 0 {
                chunks[chunkIndex].notBefore = max(chunks[chunkIndex].notBefore, now + backoff)
            }
        }
        requeueIfNeededLocked(chunkIndex: chunkIndex)
        return []
    }

    /// 计算单个分片非限流瞬态失败的指数退避时长（附有界确定性抖动，避免短暂网络抖动在毫秒内耗尽重试配额）
    private func chunkRetryBackoffDelay(chunkIndex: Int, retryCount: Int) -> TimeInterval {
        guard config.retryDelay > 0 else { return 0 }
        let base = min(config.retryDelay, 0.5)
        let cap = max(0, min(config.maxRetryAfterDelay, 4.0))
        let exponent = min(10, max(0, retryCount - 1))
        let raw = min(cap, base * pow(2.0, Double(exponent)))
        guard raw > 0 else { return 0 }
        let jitterSlot = (chunkIndex &* 31 &+ retryCount &* 17) % 7
        let jitterFactor = 0.85 + (Double(jitterSlot) / 6.0) * 0.30
        return min(cap, raw * jitterFactor)
    }

    private func selectTailHedgeCandidateLocked(forSlotID slotID: Int, now: TimeInterval) -> Int? {
        guard activeHedgeCount < config.maxConcurrentHedges else { return nil }
        guard speedTracker.containsSlot(slotID) else { return nil }

        // 仅允许已证明吞吐正常（完成过分片或最近分片速率达到参考基准 50% 以上）的空闲槽位发起尾块对冲
        let refHigh = speedTracker.computeReferenceHighSpeed(now: now)
        guard speedTracker.isSlotProvenForHedge(slotID: slotID, refHigh: refHigh) else { return nil }

        let fastChunkDuration: TimeInterval = refHigh > 0 ? (Double(chunkSize) / refHigh) : 0.25
        let minLagDuration = max(0.08, min(config.warmupGracePeriod, max(fastChunkDuration * 1.5, 0.08)))
        let stallLagThreshold = max(0.12, min(1.0, config.effectiveChunkStallTimeout * 0.25))

        var bestCandidate: (chunkIndex: Int, score: Double)?

        for chunkIdx in inFlightChunkIndices {
            let chunk = chunks[chunkIdx]
            guard !chunk.isComplete, chunk.activeAttempts.count == 1,
                  let primary = chunk.activeAttempts.values.first
            else {
                continue
            }
            if primary.slotID == slotID { continue }

            let idleSinceByte = now - primary.lastByteAt
            let elapsed = now - primary.startedAt
            let primaryRate = speedTracker.slotCurrentSpeed(slotID: primary.slotID, now: now)

            let isStalling = idleSinceByte >= stallLagThreshold
            let isSlowLagging = elapsed >= minLagDuration && (refHigh <= 0 || primaryRate < refHigh * 0.5)
            guard isStalling || isSlowLagging else { continue }

            let score = idleSinceByte * 10.0 + elapsed - (primaryRate / max(1.0, refHigh))
            if bestCandidate == nil || score > bestCandidate!.score {
                bestCandidate = (chunk.index, score)
            }
        }

        return bestCandidate?.chunkIndex
    }

    private func recordRateLimitBackoffLocked(retryAfter: TimeInterval?, now: TimeInterval) {
        let baseDelay: TimeInterval
        if let explicit = retryAfter {
            baseDelay = min(config.maxRetryAfterDelay, max(0, explicit))
        } else {
            baseDelay = min(config.maxRetryAfterDelay, max(0.05, config.retryDelay))
        }
        let targetUntil = now + baseDelay
        if now >= lastBackoffWindowEnd {
            speedTracker.halveActiveSlotLimit()
            backoffWaveCount += 1
            lastBackoffWindowEnd = max(targetUntil, now + 0.05)
        }
        retryNotBefore = max(retryNotBefore, targetUntil)
    }

    private func requeueIfNeededLocked(chunkIndex: Int) {
        guard chunks.indices.contains(chunkIndex) else { return }
        if !chunks[chunkIndex].isComplete &&
            chunks[chunkIndex].activeAttempts.isEmpty &&
            !chunks[chunkIndex].isQueued
        {
            chunks[chunkIndex].isQueued = true
            requeuedChunks.append(chunkIndex)
        }
    }

    private func setAbortLocked(_ reason: LedgerAbortReason) -> [@Sendable () -> Void] {
        if abortReason == nil {
            abortReason = reason
        }
        var handlers: [@Sendable () -> Void] = []
        for idx in inFlightChunkIndices {
            for (_, attempt) in chunks[idx].activeAttempts {
                if let cancel = attempt.cancelHandler {
                    handlers.append(cancel)
                }
            }
        }
        return handlers
    }
}
