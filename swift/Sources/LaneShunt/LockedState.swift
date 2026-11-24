import Foundation

/// 基于 `NSLock` 的轻量级线程安全状态容器，统一替代各模块内联锁包装类
internal final class LockedState<State>: @unchecked Sendable {
    private let lock = NSLock()
    private var state: State

    init(_ initialState: State) {
        self.state = initialState
    }

    /// 在持锁临界区内读写内部状态，支持抛出错误并自动释放锁
    @discardableResult
    func withLock<R>(_ body: (inout State) throws -> R) rethrows -> R {
        lock.lock()
        defer { lock.unlock() }
        return try body(&state)
    }
}
