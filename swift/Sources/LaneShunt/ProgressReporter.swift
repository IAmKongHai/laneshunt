import Foundation

/// 后台串行节流进度上报器（确保永不在主线程执行且严格 FIFO 单调保序）
internal final class ProgressReporter: @unchecked Sendable {
    private let lock = NSLock()
    private let minInterval: TimeInterval
    private let handler: (@Sendable (DownloadProgress) -> Void)?
    private let queue: DispatchQueue?

    private var highWaterBytes: Int64 = 0
    private var lastReportedBytes: Int64 = -1
    private var lastReportAt: TimeInterval = 0

    init(minInterval: TimeInterval, handler: (@Sendable (DownloadProgress) -> Void)?) {
        self.minInterval = max(0, minInterval)
        self.handler = handler
        if handler != nil {
            self.queue = DispatchQueue(
                label: "com.laneshunt.progress",
                qos: .utility
            )
        } else {
            self.queue = nil
        }
    }

    /// 按最小时间间隔节流上报单调递增进度（`force == true` 或完成时无条件立即入队）
    func report(bytesReceived: Int64, totalBytes: Int64?, force: Bool) {
        guard let handler, let queue else { return }
        let now = ProcessInfo.processInfo.systemUptime

        lock.lock()
        defer { lock.unlock() }

        var bounded = max(0, bytesReceived)
        if let totalBytes, totalBytes >= 0 {
            bounded = min(bounded, totalBytes)
        }
        let clamped = max(highWaterBytes, bounded)
        highWaterBytes = clamped

        let isCompletion = (totalBytes != nil && clamped >= totalBytes!)
        let shouldEmit: Bool
        if force || isCompletion || lastReportedBytes < 0 {
            shouldEmit = (clamped != lastReportedBytes) || force
        } else if clamped > lastReportedBytes && (now - lastReportAt) >= minInterval {
            shouldEmit = true
        } else {
            shouldEmit = false
        }

        guard shouldEmit else { return }
        lastReportedBytes = clamped
        lastReportAt = now

        let snapshot = DownloadProgress(
            bytesReceived: clamped,
            totalBytes: totalBytes,
            isReset: false
        )
        // 在持锁期间向串行 DispatchQueue 异步入队，保证回调执行顺序与单调高水位更新顺序严格一致，且回调本身在锁外后台执行
        queue.async {
            handler(snapshot)
        }
    }

    /// 远端资源漂移触发全量重置时，复位高水位并上报 `isReset == true`
    func reportReset() {
        guard let handler, let queue else { return }
        lock.lock()
        defer { lock.unlock() }

        highWaterBytes = 0
        lastReportedBytes = 0
        lastReportAt = 0

        let snapshot = DownloadProgress(bytesReceived: 0, totalBytes: nil, isReset: true)
        queue.async {
            handler(snapshot)
        }
    }

    /// 等待串行进度队列中已入队的回调全部执行完毕
    func drain() {
        queue?.sync {}
    }
}
