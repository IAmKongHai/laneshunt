import Foundation

/// 账本异步等待唤醒队列：基于单调递增 `stateVersion` 消除唤醒丢失，并支持 Swift Task 取消立即唤醒
internal final class LedgerWaiterQueue: @unchecked Sendable {
    private final class PendingWaiter {
        var continuation: CheckedContinuation<Void, Error>?
        var timer: DispatchSourceTimer?

        init(continuation: CheckedContinuation<Void, Error>) {
            self.continuation = continuation
        }
    }

    private let lock: NSLock
    private let timerQueue = DispatchQueue(label: "com.laneshunt.waiters", qos: .utility)

    /// 当前账本状态版本号（调用方必须在持有 `lock` 时读取）
    private(set) var stateVersion: UInt64 = 0
    private var nextWaiterID: UInt64 = 1
    private var waiters: [UInt64: PendingWaiter] = [:]

    init(lock: NSLock) {
        self.lock = lock
    }

    /// 递增状态版本号并唤醒全部等待中的 Worker（调用前必须已持有 `lock`）
    func notifyAllLocked() {
        stateVersion &+= 1
        let drained = Array(waiters.values)
        waiters.removeAll()
        for waiter in drained {
            let timer = waiter.timer
            let cont = waiter.continuation
            waiter.timer = nil
            waiter.continuation = nil
            timer?.cancel()
            cont?.resume(returning: ())
        }
    }

    /// 可被 Swift Task 取消立即唤醒的事件/截止时间等待（基于 `stateVersion` 避免唤醒丢失）
    func waitForWakeup(
        sinceVersion expectedVersion: UInt64,
        until deadline: TimeInterval,
        shouldReturnImmediatelyLocked: () -> Bool
    ) async throws {
        if Task.isCancelled {
            throw CancellationError()
        }

        let waiterIDBox = LockedState<UInt64?>(nil)

        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                lock.lock()
                if shouldReturnImmediatelyLocked() || stateVersion != expectedVersion {
                    lock.unlock()
                    continuation.resume(returning: ())
                    return
                }
                if Task.isCancelled {
                    lock.unlock()
                    continuation.resume(throwing: CancellationError())
                    return
                }

                let now = ProcessInfo.processInfo.systemUptime
                let remaining = deadline - now
                if remaining <= 0 {
                    lock.unlock()
                    continuation.resume(returning: ())
                    return
                }

                let id = nextWaiterID
                nextWaiterID += 1
                waiterIDBox.withLock { $0 = id }

                let waiter = PendingWaiter(continuation: continuation)
                let timer = DispatchSource.makeTimerSource(queue: timerQueue)
                let delayNs = max(1_000_000, Int64(remaining * 1_000_000_000))
                timer.schedule(deadline: .now() + .nanoseconds(Int(min(delayNs, Int64(Int.max)))))
                timer.setEventHandler { [weak self] in
                    self?.resumeWaiter(id: id, result: .success(()))
                }
                waiter.timer = timer
                waiters[id] = waiter
                lock.unlock()

                timer.resume()
            }
        } onCancel: { [weak self] in
            if let id = waiterIDBox.withLock({ $0 }) {
                self?.resumeWaiter(id: id, result: .failure(CancellationError()))
            }
        }
    }

    private func resumeWaiter(id: UInt64, result: Result<Void, Error>) {
        lock.lock()
        guard let waiter = waiters.removeValue(forKey: id) else {
            lock.unlock()
            return
        }
        let timer = waiter.timer
        let cont = waiter.continuation
        waiter.timer = nil
        waiter.continuation = nil
        lock.unlock()

        timer?.cancel()
        cont?.resume(with: result)
    }
}
