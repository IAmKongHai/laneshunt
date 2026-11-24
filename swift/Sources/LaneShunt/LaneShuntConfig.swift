import Foundation

/// 弹性多连接下载引擎配置项
public struct LaneShuntConfig: @unchecked Sendable {
    // MARK: - 公开核心配置（15 项）

    /// 可选的预期文件总字节数提示（小于分片阈值时直接跳过探针走单流）
    public var expectedSizeHint: Int64?
    /// 允许下载与落盘的硬安全字节上限（默认 256 MiB）
    public var maxBytes: Int64
    /// 是否强制要求 HTTPS 传输并拦截明文降级重定向（默认开启）
    public var requireHTTPS: Bool
    /// 允许跟随的最大 HTTP 重定向跳数（默认 10）
    public var maxRedirects: Int
    /// 分片模式下的最大并发独立连接槽位数（默认 6）
    public var maxConnections: Int
    /// 不可变微切片大小（默认 256 KiB）
    public var chunkSize: Int64
    /// 启用多连接分片下载的最小文件体积阈值（默认 1 MiB）
    public var minSegmentedSize: Int64
    /// 外层探针与单流共享的最大尝试次数（默认 3）
    public var maxAttempts: Int
    /// 分片中途检测到远端内容漂移时的最大全量重置次数（默认 2）
    public var maxFullResets: Int
    /// 瞬态网络故障重试前的基础等待时长（默认 2 秒）
    public var retryDelay: TimeInterval
    /// 单流空闲无数据超时（默认 60 秒）
    public var singleStreamIdleTimeout: TimeInterval
    /// 分片零字节停滞看门狗超时（默认 15 秒）
    public var chunkStallTimeout: TimeInterval
    /// 整次下载的硬总超时上限（默认 10 分钟）
    public var totalTimeout: TimeInterval
    /// 可选自定义 User-Agent
    public var userAgent: String?
    /// 可选基础 URLSessionConfiguration（每个槽位独立拷贝并清空缓存与 Cookie）
    public var baseSessionConfiguration: URLSessionConfiguration?

    // MARK: - 内部启发式调度、看门狗、侦察、对冲与重试调优参数（22 项）

    /// 新建连接预热豁免期（默认 2 秒）
    internal var warmupGracePeriod: TimeInterval
    /// 实时吞吐滑动采样窗口（默认 2.5 秒）
    internal var speedSampleWindow: TimeInterval
    /// 近期高速参考基准衰减回溯窗口（默认 18 秒）
    internal var refSpeedWindow: TimeInterval
    /// 触发相对慢槽轮换的参考高速倍率阈值（默认 0.25）
    internal var slowRelativeRatio: Double
    /// 触发相对慢槽轮换的绝对速率上限（默认 512 KB/s）
    internal var slowAbsoluteCeilingBytesPerSec: Double
    /// 慢槽需持续低速多久才触发轮换（默认 3 秒）
    internal var slowSustainDuration: TimeInterval
    /// 单槽两次轮换之间的冷却时长（默认 8 秒）
    internal var slotRotationCooldown: TimeInterval
    /// 全局任意两次轮换之间的冷却时长（默认 3 秒）
    internal var globalRotationCooldown: TimeInterval
    /// 整次下载允许的最大总轮换次数（默认 24）
    internal var maxTotalRotations: Int
    /// 高速参考基准低于此值时进入低速侦察逻辑（默认 64 KB/s）
    internal var scoutHighSpeedThresholdBytesPerSec: Double
    /// 整体低速持续多久才发起单槽侦察（默认 8 秒）
    internal var scoutSustainDuration: TimeInterval
    /// 两次单槽侦察之间的冷却时长（默认 10 秒）
    internal var scoutCooldown: TimeInterval
    /// 整次下载允许的最大连续单槽侦察次数（默认 2）
    internal var maxScoutRotations: Int
    /// 侦察新连接被判定为改善所需的最小相对倍率（默认 2.0）
    internal var scoutSuccessMinRatio: Double
    /// 侦察新连接被判定为改善所需的最小绝对速率（默认 80 KB/s）
    internal var scoutSuccessMinSpeedBytesPerSec: Double
    /// 侦察耗尽后判定为真窄带并收缩并发的聚合吞吐阈值（默认 48 KB/s）
    internal var narrowbandAggregateThresholdBytesPerSec: Double
    /// 判定为真窄带后收缩的目标并发槽位数（默认 2）
    internal var narrowbandReducedConnections: Int
    /// 慢流与停滞看门狗巡检周期（默认 0.5 秒）
    internal var watchdogInterval: TimeInterval
    /// 队列排空后允许的全局最大并发尾块对冲数（默认 2）
    internal var maxConcurrentHedges: Int
    /// 尊重服务端 Retry-After 的最大封顶等待时长（默认 60 秒）
    internal var maxRetryAfterDelay: TimeInterval
    /// 单个微切片允许的最大瞬态失败重试次数（默认 4）
    internal var maxChunkRetries: Int
    /// 后台进度回调的最小时间节流间隔（默认 0.05 秒）
    internal var progressMinInterval: TimeInterval

    /// 供测试或只读诊断观测底层事务指标的内部回调
    internal var onTransactionMetrics: (@Sendable (URLSessionTaskTransactionMetrics) -> Void)?
    /// 供测试断言自适应调度状态的内部诊断回调
    internal var onDiagnostics: (@Sendable (DownloaderDiagnosticsSnapshot) -> Void)?

    /// 公开初始化方法，仅暴露 15 项核心配置，内部调度参数均使用经过验证的生产默认值
    public init(
        expectedSizeHint: Int64? = nil,
        maxBytes: Int64 = 256 * 1024 * 1024,
        requireHTTPS: Bool = true,
        maxRedirects: Int = 10,
        maxConnections: Int = 6,
        chunkSize: Int64 = 256 * 1024,
        minSegmentedSize: Int64 = 1024 * 1024,
        maxAttempts: Int = 3,
        maxFullResets: Int = 2,
        retryDelay: TimeInterval = 2.0,
        singleStreamIdleTimeout: TimeInterval = 60.0,
        chunkStallTimeout: TimeInterval = 15.0,
        totalTimeout: TimeInterval = 600.0,
        userAgent: String? = nil,
        baseSessionConfiguration: URLSessionConfiguration? = nil
    ) {
        self.expectedSizeHint = expectedSizeHint
        self.maxBytes = maxBytes
        self.requireHTTPS = requireHTTPS
        self.maxRedirects = maxRedirects
        self.maxConnections = maxConnections
        self.chunkSize = chunkSize
        self.minSegmentedSize = minSegmentedSize
        self.maxAttempts = maxAttempts
        self.maxFullResets = maxFullResets
        self.retryDelay = retryDelay
        self.singleStreamIdleTimeout = singleStreamIdleTimeout
        self.chunkStallTimeout = chunkStallTimeout
        self.totalTimeout = totalTimeout
        self.userAgent = userAgent
        self.baseSessionConfiguration = baseSessionConfiguration?.copy() as? URLSessionConfiguration
        self.warmupGracePeriod = 2.0
        self.speedSampleWindow = 2.5
        self.refSpeedWindow = 18.0
        self.slowRelativeRatio = 0.25
        self.slowAbsoluteCeilingBytesPerSec = 512 * 1024
        self.slowSustainDuration = 3.0
        self.slotRotationCooldown = 8.0
        self.globalRotationCooldown = 3.0
        self.maxTotalRotations = 24
        self.scoutHighSpeedThresholdBytesPerSec = 64 * 1024
        self.scoutSustainDuration = 8.0
        self.scoutCooldown = 10.0
        self.maxScoutRotations = 2
        self.scoutSuccessMinRatio = 2.0
        self.scoutSuccessMinSpeedBytesPerSec = 80 * 1024
        self.narrowbandAggregateThresholdBytesPerSec = 48 * 1024
        self.narrowbandReducedConnections = 2
        self.watchdogInterval = 0.5
        self.maxConcurrentHedges = 2
        self.maxRetryAfterDelay = 60.0
        self.maxChunkRetries = 4
        self.progressMinInterval = 0.05
        self.onTransactionMetrics = nil
        self.onDiagnostics = nil
    }

    /// 内部全参数初始化方法，供 `@testable import LaneShunt` 白盒测试自定义启发式与看门狗参数
    @_disfavoredOverload
    internal init(
        expectedSizeHint: Int64? = nil,
        maxBytes: Int64 = 256 * 1024 * 1024,
        requireHTTPS: Bool = true,
        maxRedirects: Int = 10,
        maxConnections: Int = 6,
        chunkSize: Int64 = 256 * 1024,
        minSegmentedSize: Int64 = 1024 * 1024,
        maxAttempts: Int = 3,
        maxFullResets: Int = 2,
        retryDelay: TimeInterval = 2.0,
        singleStreamIdleTimeout: TimeInterval = 60.0,
        chunkStallTimeout: TimeInterval = 15.0,
        totalTimeout: TimeInterval = 600.0,
        userAgent: String? = nil,
        baseSessionConfiguration: URLSessionConfiguration? = nil,
        warmupGracePeriod: TimeInterval = 2.0,
        speedSampleWindow: TimeInterval = 2.5,
        refSpeedWindow: TimeInterval = 18.0,
        slowRelativeRatio: Double = 0.25,
        slowAbsoluteCeilingBytesPerSec: Double = 512 * 1024,
        slowSustainDuration: TimeInterval = 3.0,
        slotRotationCooldown: TimeInterval = 8.0,
        globalRotationCooldown: TimeInterval = 3.0,
        maxTotalRotations: Int = 24,
        scoutHighSpeedThresholdBytesPerSec: Double = 64 * 1024,
        scoutSustainDuration: TimeInterval = 8.0,
        scoutCooldown: TimeInterval = 10.0,
        maxScoutRotations: Int = 2,
        scoutSuccessMinRatio: Double = 2.0,
        scoutSuccessMinSpeedBytesPerSec: Double = 80 * 1024,
        narrowbandAggregateThresholdBytesPerSec: Double = 48 * 1024,
        narrowbandReducedConnections: Int = 2,
        watchdogInterval: TimeInterval = 0.5,
        maxConcurrentHedges: Int = 2,
        maxRetryAfterDelay: TimeInterval = 60.0,
        maxChunkRetries: Int = 4,
        progressMinInterval: TimeInterval = 0.05
    ) {
        self.expectedSizeHint = expectedSizeHint
        self.maxBytes = maxBytes
        self.requireHTTPS = requireHTTPS
        self.maxRedirects = maxRedirects
        self.maxConnections = maxConnections
        self.chunkSize = chunkSize
        self.minSegmentedSize = minSegmentedSize
        self.maxAttempts = maxAttempts
        self.maxFullResets = maxFullResets
        self.retryDelay = retryDelay
        self.singleStreamIdleTimeout = singleStreamIdleTimeout
        self.chunkStallTimeout = chunkStallTimeout
        self.totalTimeout = totalTimeout
        self.userAgent = userAgent
        self.baseSessionConfiguration = baseSessionConfiguration?.copy() as? URLSessionConfiguration
        self.warmupGracePeriod = warmupGracePeriod
        self.speedSampleWindow = speedSampleWindow
        self.refSpeedWindow = refSpeedWindow
        self.slowRelativeRatio = slowRelativeRatio
        self.slowAbsoluteCeilingBytesPerSec = slowAbsoluteCeilingBytesPerSec
        self.slowSustainDuration = slowSustainDuration
        self.slotRotationCooldown = slotRotationCooldown
        self.globalRotationCooldown = globalRotationCooldown
        self.maxTotalRotations = maxTotalRotations
        self.scoutHighSpeedThresholdBytesPerSec = scoutHighSpeedThresholdBytesPerSec
        self.scoutSustainDuration = scoutSustainDuration
        self.scoutCooldown = scoutCooldown
        self.maxScoutRotations = maxScoutRotations
        self.scoutSuccessMinRatio = scoutSuccessMinRatio
        self.scoutSuccessMinSpeedBytesPerSec = scoutSuccessMinSpeedBytesPerSec
        self.narrowbandAggregateThresholdBytesPerSec = narrowbandAggregateThresholdBytesPerSec
        self.narrowbandReducedConnections = narrowbandReducedConnections
        self.watchdogInterval = watchdogInterval
        self.maxConcurrentHedges = maxConcurrentHedges
        self.maxRetryAfterDelay = maxRetryAfterDelay
        self.maxChunkRetries = maxChunkRetries
        self.progressMinInterval = progressMinInterval
        self.onTransactionMetrics = nil
        self.onDiagnostics = nil
    }

    /// 实际生效的单分片零字节停滞超时（自动跟随更短的单流空闲超时）
    public var effectiveChunkStallTimeout: TimeInterval {
        min(max(0.05, chunkStallTimeout), max(0.05, singleStreamIdleTimeout))
    }
}

/// 供单元测试核验自适应调度与退避状态机的内部快照
internal struct DownloaderDiagnosticsSnapshot: Sendable, Equatable {
    let activeSlotLimit: Int
    let totalRotations: Int
    let totalScoutsUsed: Int
    let scoutingPermanentlyDisabled: Bool
    let totalHedgesLaunched: Int
    let peakConcurrentHedges: Int
    let lastReferenceHighSpeed: Double
    let lastAggregateSpeed: Double
    let backoffWaveCount: Int
}

/// 下载进度快照（由后台线程单调上报，全量重置时置位 `isReset`）
public struct DownloadProgress: Equatable, Sendable {
    public let bytesReceived: Int64
    public let totalBytes: Int64?
    public let isReset: Bool

    public init(bytesReceived: Int64, totalBytes: Int64?, isReset: Bool = false) {
        self.bytesReceived = bytesReceived
        self.totalBytes = totalBytes
        self.isReset = isReset
    }

    /// 归一化进度比例（仅在已知总大小且大于 0 时有值）
    public var fractionCompleted: Double? {
        guard let totalBytes, totalBytes > 0 else { return nil }
        return min(1.0, max(0.0, Double(bytesReceived) / Double(totalBytes)))
    }
}

/// 下载成功后的结构化结果
public struct DownloadResult: Equatable, Sendable {
    public let finalURL: URL
    public let bytesWritten: Int64
    public let totalBytes: Int64
    public let attemptsUsed: Int
    public let usedSegmented: Bool

    public init(
        finalURL: URL,
        bytesWritten: Int64,
        totalBytes: Int64,
        attemptsUsed: Int,
        usedSegmented: Bool
    ) {
        self.finalURL = finalURL
        self.bytesWritten = bytesWritten
        self.totalBytes = totalBytes
        self.attemptsUsed = attemptsUsed
        self.usedSegmented = usedSegmented
    }
}

/// 语言无关、零业务耦合的下载器类型化错误（原生 `CancellationError` 原样透传）
public enum LaneShuntError: Error, Sendable, Equatable, LocalizedError {
    case insecureURL(URL)
    case insecureRedirect(from: URL, to: URL)
    case tooManyRedirects(limit: Int)
    case httpStatus(Int)
    case timeout(String)
    case sizeLimitExceeded(limit: Int64, actual: Int64)
    case retriesExhausted(attempts: Int, underlyingDescription: String, isTimeout: Bool)
    case fileIO(String)

    public var errorDescription: String? {
        switch self {
        case .insecureURL(let url):
            return "Insecure or invalid download URL: \(url.absoluteString)"
        case .insecureRedirect(let from, let to):
            return "Blocked insecure redirect from \(from.absoluteString) to \(to.absoluteString)"
        case .tooManyRedirects(let limit):
            return "Too many HTTP redirects (limit: \(limit))"
        case .httpStatus(let code):
            return "Unexpected HTTP status \(code)"
        case .timeout(let detail):
            return "Download timed out: \(detail)"
        case .sizeLimitExceeded(let limit, let actual):
            return "Download size \(actual) exceeded limit \(limit)"
        case .retriesExhausted(let attempts, let underlyingDescription, _):
            return "Download failed after \(attempts) attempts: \(underlyingDescription)"
        case .fileIO(let detail):
            return "File I/O error: \(detail)"
        }
    }
}
