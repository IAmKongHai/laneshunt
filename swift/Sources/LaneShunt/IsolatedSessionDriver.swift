import Foundation

// MARK: - 独立隔离 URLSession 驱动（每槽位独占连接池，彻底避开 HTTP/2 合并）

internal extension LaneShunt {
    enum ResponseHandlingDisposition {
        case allow
        case stopEarlySuccess
    }

    final class IsolatedSessionDriver: @unchecked Sendable {
        private let lock = NSLock()
        private let delegate: SessionDelegate
        private let session: URLSession
        private var isInvalidated: Bool = false

        init(
            label: String,
            config: LaneShuntConfig,
            requestTimeout: TimeInterval,
            resourceTimeout: TimeInterval
        ) {
            let sessionConfig = LaneShunt.makeIsolatedSessionConfiguration(
                from: config.baseSessionConfiguration,
                requestTimeout: requestTimeout,
                resourceTimeout: resourceTimeout
            )
            sessionConfig.httpMaximumConnectionsPerHost = 1

            let delegateQueue = OperationQueue()
            delegateQueue.name = "com.laneshunt.\(label)"
            delegateQueue.maxConcurrentOperationCount = 1
            delegateQueue.qualityOfService = .userInitiated

            let delegate = SessionDelegate(config: config)
            let session = URLSession(configuration: sessionConfig, delegate: delegate, delegateQueue: delegateQueue)

            self.delegate = delegate
            self.session = session
        }

        /// 立即取消在途请求并销毁底层 `URLSession`（幂等）
        func invalidateAndCancel() {
            lock.lock()
            if isInvalidated {
                lock.unlock()
                return
            }
            isInvalidated = true
            lock.unlock()

            delegate.cancelActiveTask(forTaskID: nil, withError: nil)
            session.invalidateAndCancel()
        }

        /// 在该独立连接槽位上执行单次 HTTP GET 流式请求，支持空闲超时、总超时与 taskID 精确取消
        func runTask(
            request: URLRequest,
            idleTimeout: TimeInterval,
            overallDeadline: TimeInterval,
            onTaskCreated: ((@escaping @Sendable () -> Void) -> Void)? = nil,
            onResponse: @escaping @Sendable (HTTPURLResponse, Bool) throws -> ResponseHandlingDisposition,
            onData: @escaping @Sendable (Data) throws -> Void
        ) async throws {
            if Task.isCancelled {
                throw CancellationError()
            }

            let task = session.dataTask(with: request)
            let taskID = task.taskIdentifier

            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                    let started = delegate.begin(
                        task: task,
                        initialRequest: request,
                        idleTimeout: idleTimeout,
                        overallDeadline: overallDeadline,
                        continuation: continuation,
                        onResponse: onResponse,
                        onData: onData
                    )
                    guard started else {
                        task.cancel()
                        continuation.resume(throwing: CancellationError())
                        return
                    }

                    // 取消闭包严格绑定本次 taskID，防止延迟触发的落败取消误伤复用同一会话的下一个分片任务
                    let cancelClosure: @Sendable () -> Void = { [weak delegate] in
                        delegate?.cancelActiveTask(forTaskID: taskID, withError: nil)
                    }
                    onTaskCreated?(cancelClosure)

                    if Task.isCancelled {
                        delegate.cancelActiveTask(forTaskID: taskID, withError: CancellationError())
                        return
                    }
                    task.resume()
                }
            } onCancel: { [weak delegate] in
                delegate?.cancelActiveTask(forTaskID: taskID, withError: CancellationError())
            }
        }
    }

    /// 串行后台队列上运行的 `URLSessionDataDelegate`：负责重定向守卫、惰性单次空闲超时与数据流转发
    private final class SessionDelegate: NSObject, URLSessionDataDelegate, @unchecked Sendable {
        private static let sharedTimerQueue = DispatchQueue(
            label: "com.laneshunt.idle-timer",
            qos: .utility
        )

        private let config: LaneShuntConfig
        private let lock = NSLock()

        private var activeTask: URLSessionDataTask?
        private var activeTaskID: Int?
        private var currentRequest: URLRequest?
        private var continuation: CheckedContinuation<Void, Error>?
        private var onResponse: (@Sendable (HTTPURLResponse, Bool) throws -> ResponseHandlingDisposition)?
        private var onData: (@Sendable (Data) throws -> Void)?

        private var redirectCount: Int = 0
        private var didCrossOriginRedirect: Bool = false
        private var forcedError: Error?
        private var stoppedEarlySuccess: Bool = false
        private var idleTimeout: TimeInterval = 0
        private var overallDeadline: TimeInterval = 0
        private var lastActivityAt: TimeInterval = 0
        private var idleTimer: DispatchSourceTimer?

        init(config: LaneShuntConfig) {
            self.config = config
            super.init()
        }

        func begin(
            task: URLSessionDataTask,
            initialRequest: URLRequest,
            idleTimeout: TimeInterval,
            overallDeadline: TimeInterval,
            continuation: CheckedContinuation<Void, Error>,
            onResponse: @escaping @Sendable (HTTPURLResponse, Bool) throws -> ResponseHandlingDisposition,
            onData: @escaping @Sendable (Data) throws -> Void
        ) -> Bool {
            lock.lock()
            guard activeTask == nil else {
                lock.unlock()
                return false
            }
            let startNow = LaneShunt.monotonicNow()
            let taskID = task.taskIdentifier
            self.activeTask = task
            self.activeTaskID = taskID
            self.currentRequest = initialRequest
            self.continuation = continuation
            self.onResponse = onResponse
            self.onData = onData
            self.redirectCount = 0
            self.didCrossOriginRedirect = false
            self.forcedError = nil
            self.stoppedEarlySuccess = false
            self.idleTimeout = idleTimeout
            self.overallDeadline = overallDeadline
            self.lastActivityAt = startNow

            let timer = DispatchSource.makeTimerSource(queue: Self.sharedTimerQueue)
            timer.setEventHandler { [weak self] in
                self?.handleIdleTimerFired(forTaskID: taskID)
            }
            self.idleTimer = timer
            rescheduleIdleTimerLocked(now: startNow)
            timer.resume()
            lock.unlock()
            return true
        }

        func cancelActiveTask(forTaskID expectedTaskID: Int? = nil, withError error: Error?) {
            lock.lock()
            if let expectedTaskID, activeTaskID != expectedTaskID {
                lock.unlock()
                return
            }
            if let error, forcedError == nil {
                forcedError = error
            }
            let task = activeTask
            lock.unlock()
            task?.cancel()
        }

        /// 按当前 `lastActivityAt + idleTimeout` 与 `overallDeadline` 较早者重设单次唤醒，传输活跃期零轮询
        private func rescheduleIdleTimerLocked(now: TimeInterval) {
            guard let timer = idleTimer else { return }
            let nextDeadline = min(lastActivityAt + idleTimeout, overallDeadline)
            let remaining = max(0.001, nextDeadline - now)
            let delayNs = min(Int64(Int.max), max(1_000_000, Int64(remaining * 1_000_000_000)))
            timer.schedule(deadline: .now() + .nanoseconds(Int(delayNs)), repeating: .never)
        }

        private func handleIdleTimerFired(forTaskID expectedTaskID: Int) {
            lock.lock()
            guard let task = activeTask,
                  activeTaskID == expectedTaskID,
                  forcedError == nil,
                  !stoppedEarlySuccess
            else {
                lock.unlock()
                return
            }
            let now = LaneShunt.monotonicNow()
            if now >= overallDeadline {
                forcedError = LaneShuntError.timeout("Download exceeded total timeout")
                lock.unlock()
                task.cancel()
                return
            }
            if now >= lastActivityAt + idleTimeout {
                forcedError = URLError(.timedOut)
                lock.unlock()
                task.cancel()
                return
            }
            rescheduleIdleTimerLocked(now: now)
            lock.unlock()
        }

        private func completeActiveTask(taskID: Int?, error: Error?) {
            lock.lock()
            if let taskID, let currentID = activeTaskID, taskID != currentID {
                lock.unlock()
                return
            }
            let cont = continuation
            let timer = idleTimer
            let overrideErr = forcedError
            let earlySuccess = stoppedEarlySuccess

            continuation = nil
            activeTask = nil
            activeTaskID = nil
            currentRequest = nil
            onResponse = nil
            onData = nil
            idleTimer = nil
            forcedError = nil
            stoppedEarlySuccess = false
            lock.unlock()

            timer?.cancel()

            guard let cont else { return }
            if let overrideErr {
                cont.resume(throwing: overrideErr)
            } else if earlySuccess {
                cont.resume(returning: ())
            } else if let error {
                cont.resume(throwing: error)
            } else {
                cont.resume(returning: ())
            }
        }

        // MARK: URLSessionTaskDelegate & URLSessionDataDelegate

        func urlSession(
            _ session: URLSession,
            task: URLSessionTask,
            willPerformHTTPRedirection response: HTTPURLResponse,
            newRequest request: URLRequest,
            completionHandler: @escaping (URLRequest?) -> Void
        ) {
            lock.lock()
            guard task.taskIdentifier == activeTaskID, let origRequest = currentRequest else {
                lock.unlock()
                completionHandler(nil)
                return
            }
            lastActivityAt = LaneShunt.monotonicNow()
            redirectCount += 1
            let count = redirectCount
            let fromURL = response.url ?? origRequest.url
            lock.unlock()

            guard let fromURL, let targetURL = request.url else {
                let err = LaneShuntError.insecureURL(request.url ?? URL(string: "about:blank")!)
                lock.lock()
                if forcedError == nil { forcedError = err }
                lock.unlock()
                completionHandler(nil)
                task.cancel()
                return
            }

            do {
                let sameOrigin = try HTTPPolicy.validateRedirect(
                    from: fromURL,
                    to: targetURL,
                    redirectCount: count,
                    maxRedirects: config.maxRedirects,
                    requireHTTPS: config.requireHTTPS
                )
                let rebuilt = HTTPPolicy.buildRedirectRequest(
                    originalRequest: origRequest,
                    proposedRequest: request,
                    isSameOrigin: sameOrigin,
                    userAgent: config.userAgent
                )
                lock.lock()
                if !sameOrigin {
                    didCrossOriginRedirect = true
                }
                currentRequest = rebuilt
                lock.unlock()
                completionHandler(rebuilt)
            } catch {
                // 拒绝重定向时先记录精确安全错误、回传 nil 并立刻 cancel，避免 URLSession 将 302 当成功响应交付
                lock.lock()
                if forcedError == nil {
                    forcedError = error
                }
                lock.unlock()
                completionHandler(nil)
                task.cancel()
            }
        }

        func urlSession(
            _ session: URLSession,
            dataTask: URLSessionDataTask,
            didReceive response: URLResponse,
            completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
        ) {
            lock.lock()
            guard dataTask.taskIdentifier == activeTaskID else {
                lock.unlock()
                completionHandler(.cancel)
                return
            }
            if forcedError != nil {
                lock.unlock()
                completionHandler(.cancel)
                return
            }
            lastActivityAt = LaneShunt.monotonicNow()
            let callback = onResponse
            let crossedOrigin = didCrossOriginRedirect
            lock.unlock()

            guard let httpResponse = response as? HTTPURLResponse else {
                lock.lock()
                if forcedError == nil {
                    forcedError = URLError(.badServerResponse)
                }
                lock.unlock()
                completionHandler(.cancel)
                return
            }

            do {
                let disposition = try callback?(httpResponse, crossedOrigin) ?? .allow
                switch disposition {
                case .allow:
                    completionHandler(.allow)
                case .stopEarlySuccess:
                    lock.lock()
                    stoppedEarlySuccess = true
                    lock.unlock()
                    completionHandler(.cancel)
                }
            } catch {
                lock.lock()
                if forcedError == nil {
                    forcedError = error
                }
                lock.unlock()
                completionHandler(.cancel)
            }
        }

        func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
            lock.lock()
            guard dataTask.taskIdentifier == activeTaskID, forcedError == nil, !stoppedEarlySuccess else {
                lock.unlock()
                return
            }
            lastActivityAt = LaneShunt.monotonicNow()
            let callback = onData
            lock.unlock()

            do {
                try callback?(data)
            } catch {
                lock.lock()
                if forcedError == nil {
                    forcedError = error
                }
                lock.unlock()
                dataTask.cancel()
            }
        }

        func urlSession(
            _ session: URLSession,
            task: URLSessionTask,
            didFinishCollecting metrics: URLSessionTaskMetrics
        ) {
            guard let observer = config.onTransactionMetrics else { return }
            for tx in metrics.transactionMetrics {
                observer(tx)
            }
        }

        func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
            completeActiveTask(taskID: task.taskIdentifier, error: error)
        }

        func urlSession(_ session: URLSession, didBecomeInvalidWithError error: Error?) {
            completeActiveTask(taskID: nil, error: error ?? CancellationError())
        }
    }
}
