import Foundation

/// 均摊 O(1) 滑动字节采样窗口，通过游标推进与惰性压缩避免每包数组搬移
internal struct SlidingByteWindow {
    private struct SpeedSample {
        let timestamp: TimeInterval
        let bytes: Int64
    }

    private var samples: [SpeedSample] = []
    private var head: Int = 0
    private var sumBytes: Int64 = 0

    mutating func append(bytes: Int64, at now: TimeInterval, window: TimeInterval) {
        guard bytes > 0 else { return }
        samples.append(SpeedSample(timestamp: now, bytes: bytes))
        sumBytes += bytes
        prune(before: now - window)
    }

    mutating func prune(before cutoff: TimeInterval) {
        while head < samples.count && samples[head].timestamp < cutoff {
            sumBytes -= samples[head].bytes
            head += 1
        }
        if head == samples.count {
            if !samples.isEmpty {
                samples.removeAll(keepingCapacity: true)
                head = 0
                sumBytes = 0
            }
        } else if head >= 64 && head * 2 >= samples.count {
            samples.removeFirst(head)
            head = 0
        }
    }

    mutating func currentRate(
        since origin: TimeInterval,
        now: TimeInterval,
        window: TimeInterval,
        minWindow: TimeInterval
    ) -> Double {
        prune(before: now - window)
        let effectiveWindow = max(minWindow, min(window, now - origin))
        return Double(sumBytes) / effectiveWindow
    }

    mutating func removeAll() {
        samples.removeAll(keepingCapacity: true)
        head = 0
        sumBytes = 0
    }
}

/// 单槽位连接遥测状态（在 `ChunkLedger` 持锁期间读写）
internal struct SlotTelemetry {
    var sessionCreatedAt: TimeInterval
    var lastRotationAt: TimeInterval?
    var window = SlidingByteWindow()
    var slowSince: TimeInterval?
    var completedChunksCount: Int = 0
    var lastChunkSpeed: Double = 0
    var isWorking: Bool = false
    var needsSessionRotation: Bool = false
    var activeChunkIndex: Int?
    var activeAttemptSeq: UInt64?
    var scoutPeakSpeed: Double = 0
}

/// 槽位吞吐跟踪、衰减高速参考基准、相对慢槽轮换与聚合感知有限侦察状态机（由 `ChunkLedger` 持锁拥有）
internal struct SlotSpeedTracker {
    private struct CompletedSpeedSample {
        let timestamp: TimeInterval
        let bytesPerSec: Double
    }

    private let config: LaneShuntConfig
    private let downloadStartedAt: TimeInterval

    private(set) var slots: [SlotTelemetry]
    private(set) var activeSlotLimit: Int
    private(set) var activeWorkingSlotCount: Int = 0

    private var recentCompletedSpeeds: [CompletedSpeedSample] = []
    private var globalWindow = SlidingByteWindow()
    private var lastGlobalRotationAt: TimeInterval?
    private(set) var totalRotations: Int = 0
    private var lowRefSpeedSince: TimeInterval?
    private var activeScoutSlotID: Int?
    private var scoutLaunchedAt: TimeInterval = 0
    private var scoutBaselineSpeed: Double = 0
    private(set) var totalScoutsUsed: Int = 0
    private var consecutiveFailedScouts: Int = 0
    private var lastScoutAt: TimeInterval?
    private(set) var scoutingPermanentlyDisabled: Bool = false
    private(set) var lastRefHighSpeed: Double = 0
    private(set) var lastAggregateSpeed: Double = 0

    private var minSampleWindow: TimeInterval {
        min(0.25, max(0.05, config.warmupGracePeriod))
    }

    init(slotCount: Int, config: LaneShuntConfig, startedAt: TimeInterval) {
        let safeSlotCount = max(1, slotCount)
        self.config = config
        self.downloadStartedAt = startedAt
        self.activeSlotLimit = safeSlotCount
        self.slots = (0..<safeSlotCount).map { _ in
            SlotTelemetry(sessionCreatedAt: startedAt)
        }
    }

    func containsSlot(_ slotID: Int) -> Bool {
        slots.indices.contains(slotID)
    }

    /// 判断槽位是否受当前并发上限约束（非工作态且活跃槽位数已达上限时返回 `false`）
    func canSlotStartWork(slotID: Int) -> Bool {
        guard slots.indices.contains(slotID) else { return false }
        return slots[slotID].isWorking || activeWorkingSlotCount < activeSlotLimit
    }

    /// 槽位重建全新 `URLSession` 后调用，刷新预热起算时间并清除旧速度样本
    mutating func markSlotSessionCreated(slotID: Int, now: TimeInterval) {
        guard slots.indices.contains(slotID) else { return }
        slots[slotID].sessionCreatedAt = now
        slots[slotID].window.removeAll()
        slots[slotID].slowSince = nil
        slots[slotID].needsSessionRotation = false
        if activeScoutSlotID == slotID {
            slots[slotID].scoutPeakSpeed = 0
        }
    }

    /// 检查并消费槽位的会话重建标记
    mutating func consumeNeedsSessionRotation(slotID: Int) -> Bool {
        guard slots.indices.contains(slotID) else { return false }
        let needed = slots[slotID].needsSessionRotation
        slots[slotID].needsSessionRotation = false
        return needed
    }

    /// 标记槽位在下一次循环前需要重建独立会话
    mutating func markNeedsSessionRotation(slotID: Int, clearSlowSince: Bool = false) {
        guard slots.indices.contains(slotID) else { return }
        slots[slotID].needsSessionRotation = true
        if clearSlowSince {
            slots[slotID].slowSince = nil
        }
    }

    /// 登记槽位进入工作态并绑定当前尝试
    mutating func registerSlotWorking(slotID: Int, chunkIndex: Int, attemptSeq: UInt64) {
        guard slots.indices.contains(slotID) else { return }
        if !slots[slotID].isWorking {
            slots[slotID].isWorking = true
            activeWorkingSlotCount += 1
        }
        slots[slotID].activeChunkIndex = chunkIndex
        slots[slotID].activeAttemptSeq = attemptSeq
    }

    /// 尝试结束时释放槽位工作态
    mutating func releaseSlotWorking(slotID: Int, attemptSeq: UInt64) {
        guard slots.indices.contains(slotID), slots[slotID].activeAttemptSeq == attemptSeq else {
            return
        }
        if slots[slotID].isWorking {
            slots[slotID].isWorking = false
            activeWorkingSlotCount = max(0, activeWorkingSlotCount - 1)
        }
        slots[slotID].activeChunkIndex = nil
        slots[slotID].activeAttemptSeq = nil
    }

    /// 记录槽位收到的原始字节样本，并在该槽处于侦察观察期时刷新其峰值速率
    mutating func recordSlotSample(slotID: Int, bytes: Int64, now: TimeInterval) {
        guard slots.indices.contains(slotID), bytes > 0 else { return }
        slots[slotID].window.append(bytes: bytes, at: now, window: config.speedSampleWindow)
        if activeScoutSlotID == slotID {
            let speed = slotCurrentSpeed(slotID: slotID, now: now)
            slots[slotID].scoutPeakSpeed = max(slots[slotID].scoutPeakSpeed, speed)
        }
    }

    /// 记录全局唯一已提交字节，用于计算全槽聚合总吞吐
    mutating func recordGlobalCommittedBytes(_ bytes: Int64, at now: TimeInterval) {
        globalWindow.append(bytes: bytes, at: now, window: config.speedSampleWindow)
    }

    /// 记录分片完成时的有效吞吐样本，维护衰减高速参考基准与槽位历史速率
    mutating func recordChunkCompleted(slotID: Int, speed: Double, now: TimeInterval) {
        recentCompletedSpeeds.append(CompletedSpeedSample(timestamp: now, bytesPerSec: speed))
        pruneCompletedSpeeds(now: now)
        if slots.indices.contains(slotID) {
            slots[slotID].completedChunksCount += 1
            slots[slotID].lastChunkSpeed = speed
            if activeScoutSlotID == slotID {
                slots[slotID].scoutPeakSpeed = max(slots[slotID].scoutPeakSpeed, speed)
            }
        }
    }

    /// 判断空闲槽位是否已证明具备正常吞吐（允许发起尾块对冲）
    func isSlotProvenForHedge(slotID: Int, refHigh: Double) -> Bool {
        guard slots.indices.contains(slotID) else { return false }
        return slots[slotID].completedChunksCount > 0 ||
            slots[slotID].lastChunkSpeed >= max(1.0, refHigh * 0.5)
    }

    /// 限流退避波次触发时将并发槽位上限减半（最低保留 1）
    mutating func halveActiveSlotLimit() {
        activeSlotLimit = max(1, activeSlotLimit / 2)
    }

    /// 计算单个槽位在滑动窗口内的实时速率（B/s）
    mutating func slotCurrentSpeed(slotID: Int, now: TimeInterval) -> Double {
        guard slots.indices.contains(slotID) else { return 0 }
        let origin = slots[slotID].sessionCreatedAt
        return slots[slotID].window.currentRate(
            since: origin,
            now: now,
            window: config.speedSampleWindow,
            minWindow: minSampleWindow
        )
    }

    /// 刷新衰减高速参考基准与全局聚合吞吐快照
    mutating func refreshSpeedMetrics(now: TimeInterval) -> (refHigh: Double, aggregateSpeed: Double) {
        let refHigh = computeReferenceHighSpeed(now: now)
        let aggregateSpeed = computeAggregateThroughput(now: now)
        lastRefHighSpeed = refHigh
        lastAggregateSpeed = aggregateSpeed
        return (refHigh, aggregateSpeed)
    }

    /// 计算衰减高速参考基准：综合当前活跃槽位与最近窗口内已完成分片速率，单趟零分配取 Top-2 衰减均值（不足 4 样本取最大值）
    mutating func computeReferenceHighSpeed(now: TimeInterval) -> Double {
        pruneCompletedSpeeds(now: now)
        var top1: Double = 0
        var top2: Double = 0
        var sampleCount = 0

        func feed(_ speed: Double) {
            sampleCount += 1
            if speed >= top1 {
                top2 = top1
                top1 = speed
            } else if speed > top2 {
                top2 = speed
            }
        }

        let warmupHalf = min(0.1, config.warmupGracePeriod * 0.5)
        for slotID in slots.indices where slots[slotID].isWorking {
            if now - slots[slotID].sessionCreatedAt >= warmupHalf {
                let speed = slotCurrentSpeed(slotID: slotID, now: now)
                if speed > 0 {
                    feed(speed)
                }
            }
        }

        let window = max(1.0, config.refSpeedWindow)
        for sample in recentCompletedSpeeds {
            let age = max(0, now - sample.timestamp)
            let decay = max(0.5, 1.0 - 0.35 * (age / window))
            feed(sample.bytesPerSec * decay)
        }

        guard sampleCount > 0 else { return 0 }
        return sampleCount < 4 ? top1 : (top1 + top2) / 2.0
    }

    /// 计算全部槽位的聚合总吞吐（用于区分真窄带与高丢包多流聚合有效场景）
    mutating func computeAggregateThroughput(now: TimeInterval) -> Double {
        globalWindow.currentRate(
            since: downloadStartedAt,
            now: now,
            window: config.speedSampleWindow,
            minWindow: minSampleWindow
        )
    }

    /// 评估处于观察期的单槽侦察是否显著提速；连续无效后停用侦察并按聚合吞吐决定是否收缩并发
    /// - Returns: 若触发了侦察停用/并发上限变更需唤醒等待者，返回 `true`
    mutating func evaluateActiveScout(now: TimeInterval, aggregateSpeed: Double) -> Bool {
        guard let scoutSlot = activeScoutSlotID else { return false }
        let evalDuration = config.warmupGracePeriod + min(1.0, max(0.15, config.speedSampleWindow * 0.5))
        guard now - scoutLaunchedAt >= evalDuration else { return false }

        let currentSlotSpeed = slotCurrentSpeed(slotID: scoutSlot, now: now)
        let observedScoutSpeed = max(currentSlotSpeed, slots[scoutSlot].scoutPeakSpeed)
        let requiredSpeed = max(
            scoutBaselineSpeed * config.scoutSuccessMinRatio,
            config.scoutSuccessMinSpeedBytesPerSec
        )

        activeScoutSlotID = nil
        if observedScoutSpeed >= requiredSpeed {
            consecutiveFailedScouts = 0
            lowRefSpeedSince = nil
            return false
        }

        consecutiveFailedScouts += 1
        if consecutiveFailedScouts >= config.maxScoutRotations ||
            totalScoutsUsed >= config.maxScoutRotations
        {
            scoutingPermanentlyDisabled = true
            // 仅当全槽聚合总吞吐低于窄带阈值时收缩并发；高丢包多流聚合有效时保持原并发
            if aggregateSpeed < config.narrowbandAggregateThresholdBytesPerSec {
                activeSlotLimit = min(
                    activeSlotLimit,
                    max(1, min(config.narrowbandReducedConnections, config.maxConnections))
                )
            }
            return true
        }
        return false
    }

    /// 基于衰减高速参考基准筛选相对最慢的已预热工作槽位执行主动轮换
    mutating func selectRelativeSlowRotation(
        now: TimeInterval,
        refHigh: Double,
        actedSlotIDs: inout Set<Int>,
        cancelHandlerForAttempt: (_ chunkIndex: Int, _ attemptSeq: UInt64) -> (@Sendable () -> Void)?
    ) -> (attemptSeq: UInt64, cancel: @Sendable () -> Void)? {
        lowRefSpeedSince = nil
        let canGloballyRotate = totalRotations < config.maxTotalRotations &&
            (lastGlobalRotationAt == nil || now - lastGlobalRotationAt! >= config.globalRotationCooldown)
        let slowThreshold = min(
            refHigh * config.slowRelativeRatio,
            config.slowAbsoluteCeilingBytesPerSec
        )

        var slowestCandidate: (slotID: Int, speed: Double, attemptSeq: UInt64, cancel: @Sendable () -> Void)?

        for slotID in slots.indices {
            guard slots[slotID].isWorking else {
                slots[slotID].slowSince = nil
                continue
            }
            guard !actedSlotIDs.contains(slotID),
                  let chunkIdx = slots[slotID].activeChunkIndex,
                  let seq = slots[slotID].activeAttemptSeq,
                  let cancel = cancelHandlerForAttempt(chunkIdx, seq)
            else {
                continue
            }

            if now - slots[slotID].sessionCreatedAt < config.warmupGracePeriod {
                slots[slotID].slowSince = nil
                continue
            }

            let rate = slotCurrentSpeed(slotID: slotID, now: now)
            if rate < slowThreshold {
                if slots[slotID].slowSince == nil {
                    slots[slotID].slowSince = now
                }
                if canGloballyRotate,
                   now - slots[slotID].slowSince! >= config.slowSustainDuration,
                   slots[slotID].lastRotationAt == nil ||
                    now - slots[slotID].lastRotationAt! >= config.slotRotationCooldown
                {
                    if slowestCandidate == nil || rate < slowestCandidate!.speed {
                        slowestCandidate = (slotID, rate, seq, cancel)
                    }
                }
            } else {
                slots[slotID].slowSince = nil
            }
        }

        guard let candidate = slowestCandidate else { return nil }
        slots[candidate.slotID].needsSessionRotation = true
        slots[candidate.slotID].lastRotationAt = now
        slots[candidate.slotID].slowSince = nil
        lastGlobalRotationAt = now
        totalRotations += 1
        actedSlotIDs.insert(candidate.slotID)
        return (candidate.attemptSeq, candidate.cancel)
    }

    /// 整体低速时执行有上限的单槽侦察（最多尝试 `maxScoutRotations` 次，避免真窄带下反复抖动）
    mutating func evaluateBoundedScout(
        now: TimeInterval,
        refHigh: Double,
        actedSlotIDs: Set<Int>,
        cancelHandlerForAttempt: (_ chunkIndex: Int, _ attemptSeq: UInt64) -> (@Sendable () -> Void)?
    ) -> (attemptSeq: UInt64, cancel: @Sendable () -> Void)? {
        for slotID in slots.indices {
            slots[slotID].slowSince = nil
        }

        let hasWarmedWorkingSlot = slots.contains {
            $0.isWorking && (now - $0.sessionCreatedAt >= config.warmupGracePeriod)
        }
        guard !scoutingPermanentlyDisabled,
              activeScoutSlotID == nil,
              totalScoutsUsed < config.maxScoutRotations,
              totalRotations < config.maxTotalRotations,
              hasWarmedWorkingSlot
        else {
            return nil
        }

        if lowRefSpeedSince == nil {
            lowRefSpeedSince = now
        }
        let sustainedLongEnough = now - lowRefSpeedSince! >= config.scoutSustainDuration
        let cooldownSatisfied = lastScoutAt == nil || (now - lastScoutAt! >= config.scoutCooldown)
        guard sustainedLongEnough && cooldownSatisfied else { return nil }

        var slowestSlot: (slotID: Int, speed: Double, attemptSeq: UInt64, cancel: @Sendable () -> Void)?
        for slotID in slots.indices {
            guard !actedSlotIDs.contains(slotID),
                  slots[slotID].isWorking,
                  now - slots[slotID].sessionCreatedAt >= config.warmupGracePeriod,
                  let chunkIdx = slots[slotID].activeChunkIndex,
                  let seq = slots[slotID].activeAttemptSeq,
                  let cancel = cancelHandlerForAttempt(chunkIdx, seq)
            else {
                continue
            }
            let rate = slotCurrentSpeed(slotID: slotID, now: now)
            if slowestSlot == nil || rate < slowestSlot!.speed {
                slowestSlot = (slotID, rate, seq, cancel)
            }
        }

        guard let target = slowestSlot else { return nil }
        slots[target.slotID].needsSessionRotation = true
        slots[target.slotID].lastRotationAt = now
        slots[target.slotID].scoutPeakSpeed = 0
        activeScoutSlotID = target.slotID
        scoutLaunchedAt = now
        scoutBaselineSpeed = max(refHigh, target.speed)
        totalScoutsUsed += 1
        lastScoutAt = now
        lastGlobalRotationAt = now
        totalRotations += 1
        return (target.attemptSeq, target.cancel)
    }

    private mutating func pruneCompletedSpeeds(now: TimeInterval) {
        let cutoff = now - config.refSpeedWindow
        recentCompletedSpeeds.removeAll { $0.timestamp < cutoff }
    }
}
