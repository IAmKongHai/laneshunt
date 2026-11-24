import Foundation

/// RFC 9110 §13.1.5 强校验器（非弱 ETag 或与 Date 间隔不少于 60 秒的 Last-Modified）
enum StrongValidator: Equatable, Sendable {
    case strongETag(String)
    case safeLastModified(String)

    var ifRangeHeaderValue: String {
        switch self {
        case .strongETag(let value), .safeLastModified(let value):
            return value
        }
    }
}

/// RFC 9110 §14.4 `Content-Range` 解析结果
enum ParsedContentRange: Equatable, Sendable {
    case range(start: Int64, end: Int64, total: Int64?)
    case unsatisfied(total: Int64)
}

/// `GET Range: bytes=0-0` 能力探测响应的分支决策
enum ProbeDecision: Equatable, Sendable {
    case oneByteFastPath(finalURL: URL)
    case emptyFile(finalURL: URL)
    case segmented(finalURL: URL, totalBytes: Int64, validator: StrongValidator)
    case reuseSingleStream200(finalURL: URL, expectedTotalBytes: Int64?, validator: StrongValidator?)
    case downgradeSingleStreamPlainGET(finalURL: URL)
    case failImmediately(LaneShuntError)
    case retryableBackoff(statusCode: Int, retryAfter: TimeInterval?)
    case retryableTransient(description: String)
}

/// 逐分片 `206` 响应头的强校验结果
enum ChunkHeaderValidationResult: Equatable, Sendable {
    case valid(responseEnd: Int64)
    case driftReset(reason: String)
    case rateLimitBackoff(statusCode: Int, retryAfter: TimeInterval?)
    case deterministicFailure(LaneShuntError)
    case transientFailure(description: String)
}

/// 非 200/206/416 响应状态码的统一重试分类
enum NonSuccessStatusClassification: Equatable, Sendable {
    case rateLimitBackoff(statusCode: Int, retryAfter: TimeInterval?)
    case retryableServerError(statusCode: Int)
    case deterministicFailure(LaneShuntError)
}

/// 协议解析、强校验器锁定、重定向守卫与状态码分类工具
enum HTTPPolicy {
    private struct Origin: Equatable {
        let scheme: String
        let host: String
        let port: Int
    }

    /// 线程安全缓存的 RFC 9110 HTTP-date 解析器集合
    private final class HTTPDateParserCache: @unchecked Sendable {
        static let shared = HTTPDateParserCache()
        private let lock = NSLock()
        private let formatters: [DateFormatter]

        private init() {
            let formats = [
                "EEE, dd MMM yyyy HH:mm:ss 'GMT'", // IMF-fixdate
                "EEEE, dd-MMM-yy HH:mm:ss 'GMT'",  // obsolete RFC 850
                "EEE MMM d HH:mm:ss yyyy",         // ANSI C asctime()
                "EEE MMM  d HH:mm:ss yyyy"         // asctime() 单数字日期双空格
            ]
            self.formatters = formats.map { format in
                let df = DateFormatter()
                df.locale = Locale(identifier: "en_US_POSIX")
                df.timeZone = TimeZone(secondsFromGMT: 0)
                df.dateFormat = format
                return df
            }
        }

        func parse(_ raw: String) -> Date? {
            let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { return nil }
            lock.lock()
            defer { lock.unlock() }
            for formatter in formatters {
                if let date = formatter.date(from: trimmed) {
                    return date
                }
            }
            return nil
        }
    }

    // MARK: - URL 与同源重定向安全守卫

    /// 校验初始下载 URL：禁止 userinfo、要求有效主机名并按配置强制 HTTPS
    static func validateURL(_ url: URL, requireHTTPS: Bool) throws {
        guard hasValidSchemeAndHost(url, requireHTTPS: requireHTTPS),
              !containsUserInfo(url)
        else {
            throw LaneShuntError.insecureURL(url)
        }
    }

    /// 校验 HTTP 重定向：拦截超跳数、明文降级与 userinfo，并返回是否为同源跳转
    static func validateRedirect(
        from currentURL: URL,
        to targetURL: URL,
        redirectCount: Int,
        maxRedirects: Int,
        requireHTTPS: Bool
    ) throws -> Bool {
        if redirectCount > maxRedirects {
            throw LaneShuntError.tooManyRedirects(limit: maxRedirects)
        }
        guard hasValidSchemeAndHost(targetURL, requireHTTPS: requireHTTPS),
              !containsUserInfo(targetURL)
        else {
            throw LaneShuntError.insecureRedirect(from: currentURL, to: targetURL)
        }
        return isSameOrigin(currentURL, targetURL)
    }

    /// 判断两个 URL 是否满足严格同源（scheme + 小写 host + 有效端口）
    static func isSameOrigin(_ lhs: URL, _ rhs: URL) -> Bool {
        guard let leftOrigin = extractOrigin(lhs),
              let rightOrigin = extractOrigin(rhs)
        else {
            return false
        }
        return leftOrigin == rightOrigin
    }

    /// 跨源重定向时必须剥离的敏感请求头
    static let crossOriginSensitiveHeaders = ["if-range", "authorization", "cookie", "referer"]

    /// 构造合法重定向后的请求：恢复 Range/Accept-Encoding/User-Agent，仅同源保留 If-Range，跨源剥离敏感头
    static func buildRedirectRequest(
        originalRequest: URLRequest,
        proposedRequest: URLRequest,
        isSameOrigin: Bool,
        userAgent: String?
    ) -> URLRequest {
        var req = proposedRequest
        req.httpMethod = "GET"

        if let range = originalRequest.value(forHTTPHeaderField: "Range") {
            req.setValue(range, forHTTPHeaderField: "Range")
        }
        req.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
        if let ua = userAgent ?? originalRequest.value(forHTTPHeaderField: "User-Agent") {
            req.setValue(ua, forHTTPHeaderField: "User-Agent")
        }

        if isSameOrigin {
            if let ifRange = originalRequest.value(forHTTPHeaderField: "If-Range") {
                req.setValue(ifRange, forHTTPHeaderField: "If-Range")
            }
        } else {
            stripHeaders(&req, namesLowercased: crossOriginSensitiveHeaders)
        }
        return req
    }

    static func stripHeaders(_ request: inout URLRequest, namesLowercased: [String]) {
        for name in namesLowercased {
            request.setValue(nil, forHTTPHeaderField: name)
        }
    }

    private static func hasValidSchemeAndHost(_ url: URL, requireHTTPS: Bool) -> Bool {
        guard let scheme = url.scheme?.lowercased(),
              let host = url.host,
              !host.isEmpty
        else {
            return false
        }
        if requireHTTPS {
            return scheme == "https"
        }
        return scheme == "https" || scheme == "http"
    }

    private static func containsUserInfo(_ url: URL) -> Bool {
        if url.user != nil || url.password != nil {
            return true
        }
        if let components = URLComponents(url: url, resolvingAgainstBaseURL: true),
           components.user != nil || components.password != nil
        {
            return true
        }
        return false
    }

    private static func extractOrigin(_ url: URL) -> Origin? {
        guard let scheme = url.scheme?.lowercased(),
              let host = url.host?.lowercased(),
              !host.isEmpty
        else {
            return nil
        }
        let defaultPort: Int
        switch scheme {
        case "https":
            defaultPort = 443
        case "http":
            defaultPort = 80
        default:
            return nil
        }
        let port = url.port ?? defaultPort
        return Origin(scheme: scheme, host: host, port: port)
    }

    // MARK: - 响应头读取与编码/类型检查

    static func headerValue(_ response: HTTPURLResponse, _ field: String) -> String? {
        guard let value = response.value(forHTTPHeaderField: field) else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    /// 判断 `Content-Encoding` 是否为空或仅包含 `identity`
    static func isIdentityContentEncoding(_ response: HTTPURLResponse) -> Bool {
        guard let raw = headerValue(response, "Content-Encoding") else {
            return true
        }
        let tokens = raw
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
            .filter { !$0.isEmpty }
        guard !tokens.isEmpty else { return true }
        return tokens.allSatisfy { $0 == "identity" }
    }

    /// 判断 `Content-Type` 是否为 `multipart/byteranges`
    static func isMultipartByteranges(_ response: HTTPURLResponse) -> Bool {
        guard let raw = headerValue(response, "Content-Type") else {
            return false
        }
        let mediaType = raw
            .split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false)
            .first
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() } ?? ""
        return mediaType == "multipart/byteranges"
    }

    /// 解析 `Content-Length` 头（仅在严格非负 ASCII 数字时返回）
    static func parseContentLength(_ response: HTTPURLResponse) -> Int64? {
        guard let raw = headerValue(response, "Content-Length") else { return nil }
        return parseStrictNonNegativeInt64(raw)
    }

    // MARK: - RFC 9110 Content-Range、强校验器与 Retry-After

    /// 严格解析 RFC 9110 §14.4 `Content-Range` 头
    static func parseContentRange(_ header: String?) -> ParsedContentRange? {
        guard let raw = header?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty else {
            return nil
        }
        guard let spaceIndex = raw.firstIndex(where: { $0 == " " || $0 == "\t" }) else {
            return nil
        }
        let unit = raw[..<spaceIndex].lowercased()
        guard unit == "bytes" else { return nil }

        let remainder = raw[spaceIndex...].trimmingCharacters(in: .whitespaces)
        guard !remainder.isEmpty else { return nil }

        let slashParts = remainder.split(separator: "/", omittingEmptySubsequences: false)
        guard slashParts.count == 2 else { return nil }
        let rangePart = String(slashParts[0])
        let totalPart = String(slashParts[1])

        if rangePart == "*" {
            guard let total = parseStrictNonNegativeInt64(totalPart) else {
                return nil
            }
            return .unsatisfied(total: total)
        }

        let dashParts = rangePart.split(separator: "-", omittingEmptySubsequences: false)
        guard dashParts.count == 2,
              let start = parseStrictNonNegativeInt64(String(dashParts[0])),
              let end = parseStrictNonNegativeInt64(String(dashParts[1])),
              start <= end
        else {
            return nil
        }

        if totalPart == "*" {
            return .range(start: start, end: end, total: nil)
        }

        guard let total = parseStrictNonNegativeInt64(totalPart), end < total else {
            return nil
        }
        return .range(start: start, end: end, total: total)
    }

    /// 判断字符串是否为合法的 RFC 9110 强 ETag（非 `W/`/`w/` 开头且带双引号）
    static func isStrongETag(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count >= 2 else { return false }
        if trimmed.hasPrefix("W/") || trimmed.hasPrefix("w/") {
            return false
        }
        return trimmed.hasPrefix("\"") && trimmed.hasSuffix("\"")
    }

    /// 提取 RFC 9110 §13.1.5 强校验器：优先强 ETag，显式弱 ETag 直接拒绝；无 ETag 时校验 `Date - Last-Modified >= 60s`
    static func extractStrongValidator(from response: HTTPURLResponse) -> StrongValidator? {
        if let rawETag = headerValue(response, "ETag") {
            if isStrongETag(rawETag) {
                return .strongETag(rawETag)
            }
            // 显式返回弱 ETag 时不得绕过其弱校验语义去回退 Last-Modified
            return nil
        }

        guard let rawLastModified = headerValue(response, "Last-Modified"),
              let rawDate = headerValue(response, "Date"),
              let lastModifiedDate = parseHTTPDate(rawLastModified),
              let originDate = parseHTTPDate(rawDate)
        else {
            return nil
        }

        guard originDate.timeIntervalSince(lastModifiedDate) >= 60.0 else {
            return nil
        }
        return .safeLastModified(rawLastModified)
    }

    /// 逐片复检响应携带的强校验器是否与探针锁定的校验器严格一致
    static func verifyChunkValidator(response: HTTPURLResponse, locked: StrongValidator) -> Bool {
        let respETag = headerValue(response, "ETag")
        let respLastModified = headerValue(response, "Last-Modified")

        switch locked {
        case .strongETag(let expectedETag):
            guard let etag = respETag, isStrongETag(etag), etag == expectedETag else {
                return false
            }
            return true

        case .safeLastModified(let expectedLM):
            guard let actualLM = respLastModified else {
                return false
            }
            let lmMatches: Bool
            if actualLM == expectedLM {
                lmMatches = true
            } else if let d1 = parseHTTPDate(actualLM), let d2 = parseHTTPDate(expectedLM) {
                lmMatches = Int64(d1.timeIntervalSince1970) == Int64(d2.timeIntervalSince1970)
            } else {
                lmMatches = false
            }
            guard lmMatches else { return false }

            // 锁定安全 Last-Modified 时，若后续分片突然出现新的强 ETag，视为远端资源变化
            if let etag = respETag, isStrongETag(etag) {
                return false
            }
            return true
        }
    }

    /// 解析 RFC 9110 HTTP-date（支持 IMF-fixdate、RFC 850 与 asctime）
    static func parseHTTPDate(_ value: String) -> Date? {
        HTTPDateParserCache.shared.parse(value)
    }

    /// 解析 RFC 9110 §10.2.3 `Retry-After`（支持非负整数秒与 HTTP-date，并封顶至 `maxDelay`）
    static func parseRetryAfter(
        _ header: String?,
        now: Date = Date(),
        maxDelay: TimeInterval = 60.0
    ) -> TimeInterval? {
        guard let raw = header?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty else {
            return nil
        }
        let cap = max(0, maxDelay)
        if let seconds = parseStrictNonNegativeInt64(raw) {
            return min(cap, TimeInterval(seconds))
        }
        if let targetDate = parseHTTPDate(raw) {
            let delta = max(0, targetDate.timeIntervalSince(now))
            return min(cap, delta)
        }
        return nil
    }

    // MARK: - 探针与分片响应决策

    /// 评估 `GET Range: bytes=0-0` 探针响应头，决定快路径、分段、直复用 200 或零成本降级
    static func evaluateProbeResponse(
        _ response: HTTPURLResponse,
        finalURL: URL,
        config: LaneShuntConfig,
        now: Date = Date()
    ) -> ProbeDecision {
        let code = response.statusCode

        if code == 206 {
            if isMultipartByteranges(response) || !isIdentityContentEncoding(response) {
                return .downgradeSingleStreamPlainGET(finalURL: finalURL)
            }
            guard let parsed = parseContentRange(headerValue(response, "Content-Range")),
                  case .range(let start, let end, let totalOpt) = parsed,
                  start == 0, end == 0
            else {
                return .downgradeSingleStreamPlainGET(finalURL: finalURL)
            }
            guard let total = totalOpt else {
                return .downgradeSingleStreamPlainGET(finalURL: finalURL)
            }
            if total > config.maxBytes {
                return .failImmediately(.sizeLimitExceeded(limit: config.maxBytes, actual: total))
            }
            if total == 1 {
                return .oneByteFastPath(finalURL: finalURL)
            }
            if total < config.minSegmentedSize {
                return .downgradeSingleStreamPlainGET(finalURL: finalURL)
            }
            guard let validator = extractStrongValidator(from: response) else {
                return .downgradeSingleStreamPlainGET(finalURL: finalURL)
            }
            return .segmented(finalURL: finalURL, totalBytes: total, validator: validator)
        }

        if code == 200 {
            let identity = isIdentityContentEncoding(response)
            let contentLength = identity ? parseContentLength(response) : nil
            if let cl = contentLength, cl > config.maxBytes {
                return .failImmediately(.sizeLimitExceeded(limit: config.maxBytes, actual: cl))
            }
            let validator = extractStrongValidator(from: response)
            return .reuseSingleStream200(
                finalURL: finalURL,
                expectedTotalBytes: contentLength,
                validator: validator
            )
        }

        if code == 416 {
            if let parsed = parseContentRange(headerValue(response, "Content-Range")),
               case .unsatisfied(let total) = parsed,
               total == 0
            {
                return .emptyFile(finalURL: finalURL)
            }
            return .downgradeSingleStreamPlainGET(finalURL: finalURL)
        }

        switch classifyNonSuccessStatus(response, maxRetryAfterDelay: config.maxRetryAfterDelay, now: now) {
        case .rateLimitBackoff(let statusCode, let retryAfter):
            return .retryableBackoff(statusCode: statusCode, retryAfter: retryAfter)
        case .retryableServerError(let statusCode):
            return .retryableTransient(description: "HTTP \(statusCode)")
        case .deterministicFailure(let err):
            return .failImmediately(err)
        }
    }

    /// 评估分段下载中单个微切片的响应头（复检编码、multipart、区间、总长及锁定强校验器）
    static func evaluateChunkResponse(
        _ response: HTTPURLResponse,
        requestedStart: Int64,
        requestedEnd: Int64,
        lockedTotal: Int64,
        lockedValidator: StrongValidator,
        maxRetryAfterDelay: TimeInterval,
        now: Date = Date()
    ) -> ChunkHeaderValidationResult {
        let code = response.statusCode

        if code == 206 {
            if isMultipartByteranges(response) {
                return .driftReset(reason: "Chunk returned multipart/byteranges")
            }
            if !isIdentityContentEncoding(response) {
                return .driftReset(reason: "Chunk returned non-identity Content-Encoding")
            }
            guard let parsed = parseContentRange(headerValue(response, "Content-Range")),
                  case .range(let respStart, let respEnd, let respTotalOpt) = parsed,
                  let respTotal = respTotalOpt
            else {
                return .driftReset(reason: "Chunk returned missing or invalid Content-Range")
            }
            guard respTotal == lockedTotal else {
                return .driftReset(reason: "Remote total size changed from \(lockedTotal) to \(respTotal)")
            }
            guard respStart == requestedStart, respStart <= respEnd, respEnd <= requestedEnd else {
                return .driftReset(
                    reason: "Chunk Content-Range \(respStart)-\(respEnd) does not fit requested \(requestedStart)-\(requestedEnd)"
                )
            }
            guard verifyChunkValidator(response: response, locked: lockedValidator) else {
                return .driftReset(reason: "Locked strong validator missing or changed on chunk response")
            }
            return .valid(responseEnd: respEnd)
        }

        if code == 200 {
            return .driftReset(reason: "Server returned 200 OK instead of 206 Partial Content during segmented download")
        }

        if code == 416 {
            return .driftReset(reason: "Server returned 416 Range Not Satisfiable during segmented download")
        }

        switch classifyNonSuccessStatus(response, maxRetryAfterDelay: maxRetryAfterDelay, now: now) {
        case .rateLimitBackoff(let statusCode, let retryAfter):
            return .rateLimitBackoff(statusCode: statusCode, retryAfter: retryAfter)
        case .retryableServerError(let statusCode):
            return .transientFailure(description: "HTTP \(statusCode)")
        case .deterministicFailure(let err):
            return .deterministicFailure(err)
        }
    }

    /// 统一分类非成功 HTTP 状态码：限流/网关退避、可重试 5xx 与确定性失败
    static func classifyNonSuccessStatus(
        _ response: HTTPURLResponse,
        maxRetryAfterDelay: TimeInterval,
        now: Date = Date()
    ) -> NonSuccessStatusClassification {
        let code = response.statusCode
        if isRateLimitOrGatewayBackoff(code) {
            let retryAfter = parseRetryAfter(
                headerValue(response, "Retry-After"),
                now: now,
                maxDelay: maxRetryAfterDelay
            )
            return .rateLimitBackoff(statusCode: code, retryAfter: retryAfter)
        }
        if (500..<600).contains(code) {
            return .retryableServerError(statusCode: code)
        }
        return .deterministicFailure(.httpStatus(code))
    }

    static func isRateLimitOrGatewayBackoff(_ statusCode: Int) -> Bool {
        statusCode == 429 || statusCode == 502 || statusCode == 503 || statusCode == 504
    }

    /// 判定网络层错误是否属于可重试的临时故障（证书校验失败等安全错误绝不重试）
    static func isTransientNetworkError(_ error: Error) -> Bool {
        guard let urlError = error as? URLError else { return false }
        switch urlError.code {
        case .timedOut,
             .networkConnectionLost,
             .cannotConnectToHost,
             .cannotFindHost,
             .dnsLookupFailed,
             .notConnectedToInternet:
            return true
        default:
            return false
        }
    }

    private static func parseStrictNonNegativeInt64(_ raw: String) -> Int64? {
        guard !raw.isEmpty else { return nil }
        for scalar in raw.unicodeScalars {
            guard scalar.value >= 0x30 && scalar.value <= 0x39 else {
                return nil
            }
        }
        return Int64(raw)
    }
}

// MARK: - 对外复用的通用 HTTPS、重定向与会话隔离安全工具

public extension LaneShunt {
    /// 校验目标 URL 是否为合法 HTTPS 地址且不含 userinfo
    static func validateHTTPSURL(_ url: URL) throws {
        try HTTPPolicy.validateURL(url, requireHTTPS: true)
    }

    /// 校验 HTTP 重定向：拦截超跳数、明文降级与 userinfo，并返回是否为严格同源跳转
    static func validateRedirect(
        from currentURL: URL,
        to targetURL: URL,
        redirectCount: Int,
        maxRedirects: Int,
        requireHTTPS: Bool = true
    ) throws -> Bool {
        try HTTPPolicy.validateRedirect(
            from: currentURL,
            to: targetURL,
            redirectCount: redirectCount,
            maxRedirects: maxRedirects,
            requireHTTPS: requireHTTPS
        )
    }

    /// 剥离跨源重定向请求中的敏感头（If-Range / Authorization / Cookie / Referer）
    static func stripSensitiveCrossOriginHeaders(from request: inout URLRequest) {
        HTTPPolicy.stripHeaders(&request, namesLowercased: HTTPPolicy.crossOriginSensitiveHeaders)
    }

    /// 派生隔离的无状态 `.ephemeral` 会话配置：保留调用方注入的 `protocolClasses` 与代理设置，强制清空缓存与 Cookie
    static func makeIsolatedSessionConfiguration(
        from base: URLSessionConfiguration?,
        requestTimeout: TimeInterval,
        resourceTimeout: TimeInterval
    ) -> URLSessionConfiguration {
        let config: URLSessionConfiguration
        if let copied = base?.copy() as? URLSessionConfiguration {
            config = copied
        } else {
            config = URLSessionConfiguration.ephemeral
        }
        config.urlCache = nil
        config.httpCookieStorage = nil
        config.urlCredentialStorage = nil
        config.httpCookieAcceptPolicy = .never
        config.httpShouldSetCookies = false
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        config.waitsForConnectivity = false

        let reqCap = max(0.05, requestTimeout)
        if base != nil && config.timeoutIntervalForRequest > 0 {
            config.timeoutIntervalForRequest = min(config.timeoutIntervalForRequest, reqCap)
        } else {
            config.timeoutIntervalForRequest = reqCap
        }

        let resCap = max(0.1, resourceTimeout)
        if base != nil && config.timeoutIntervalForResource > 0 {
            config.timeoutIntervalForResource = min(config.timeoutIntervalForResource, resCap)
        } else {
            config.timeoutIntervalForResource = resCap
        }
        return config
    }
}
