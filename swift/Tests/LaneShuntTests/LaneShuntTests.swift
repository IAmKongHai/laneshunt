import CryptoKit
import Darwin
import Foundation
import XCTest
@testable import LaneShunt

final class LaneShuntTests: XCTestCase {
    private var tempDir: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("laneshunt-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        ConcurrentMockURLProtocol.reset()
    }

    override func tearDownWithError() throws {
        ConcurrentMockURLProtocol.reset()
        if let tempDir {
            try? FileManager.default.removeItem(at: tempDir)
        }
        try super.tearDownWithError()
    }

    // MARK: - 1. 协议解析、强校验器、Retry-After 与重定向策略单测

    func testContentRangeStrongValidatorAndRetryAfterParsing() {
        XCTAssertEqual(
            HTTPPolicy.parseContentRange("bytes 0-0/1048576"),
            .range(start: 0, end: 0, total: 1_048_576)
        )
        XCTAssertEqual(
            HTTPPolicy.parseContentRange("BYTES 100-199/*"),
            .range(start: 100, end: 199, total: nil)
        )
        XCTAssertEqual(
            HTTPPolicy.parseContentRange("bytes */0"),
            .unsatisfied(total: 0)
        )
        XCTAssertEqual(
            HTTPPolicy.parseContentRange("bytes */2048"),
            .unsatisfied(total: 2048)
        )
        XCTAssertNil(HTTPPolicy.parseContentRange("bytes 10-5/100"))
        XCTAssertNil(HTTPPolicy.parseContentRange("bytes 0-100/100"))
        XCTAssertNil(HTTPPolicy.parseContentRange("items 0-0/10"))
        XCTAssertNil(HTTPPolicy.parseContentRange("bytes */*"))
        XCTAssertNil(HTTPPolicy.parseContentRange("bytes -1-5/10"))

        let url = URL(string: "https://example.com/app.dmg")!
        let strongResp = HTTPURLResponse(
            url: url,
            statusCode: 206,
            httpVersion: "HTTP/1.1",
            headerFields: ["ETag": "\"v1-strong\""]
        )!
        XCTAssertEqual(HTTPPolicy.extractStrongValidator(from: strongResp), .strongETag("\"v1-strong\""))

        // 显式弱 ETag 即便附带较旧 Last-Modified 也不应被当作强校验器
        let weakResp = HTTPURLResponse(
            url: url,
            statusCode: 206,
            httpVersion: "HTTP/1.1",
            headerFields: [
                "ETag": "W/\"v1-weak\"",
                "Date": "Mon, 23 Nov 2026 12:10:00 GMT",
                "Last-Modified": "Mon, 23 Nov 2026 12:00:00 GMT"
            ]
        )!
        XCTAssertNil(HTTPPolicy.extractStrongValidator(from: weakResp))

        // 无 ETag 且 Date - Last-Modified >= 60s 时允许锁定安全 Last-Modified
        let safeLMResp = HTTPURLResponse(
            url: url,
            statusCode: 206,
            httpVersion: "HTTP/1.1",
            headerFields: [
                "Date": "Mon, 23 Nov 2026 12:05:00 GMT",
                "Last-Modified": "Mon, 23 Nov 2026 12:00:00 GMT"
            ]
        )!
        XCTAssertEqual(
            HTTPPolicy.extractStrongValidator(from: safeLMResp),
            .safeLastModified("Mon, 23 Nov 2026 12:00:00 GMT")
        )

        // Date - Last-Modified < 60s 不合格
        let freshLMResp = HTTPURLResponse(
            url: url,
            statusCode: 206,
            httpVersion: "HTTP/1.1",
            headerFields: [
                "Date": "Mon, 23 Nov 2026 12:00:30 GMT",
                "Last-Modified": "Mon, 23 Nov 2026 12:00:00 GMT"
            ]
        )!
        XCTAssertNil(HTTPPolicy.extractStrongValidator(from: freshLMResp))

        // 锁定 Last-Modified 时若后续分片出现新的强 ETag 应判漂移
        let injectedETagChunk = HTTPURLResponse(
            url: url,
            statusCode: 206,
            httpVersion: "HTTP/1.1",
            headerFields: [
                "Last-Modified": "Mon, 23 Nov 2026 12:00:00 GMT",
                "ETag": "\"newly-appeared\""
            ]
        )!
        XCTAssertFalse(
            HTTPPolicy.verifyChunkValidator(
                response: injectedETagChunk,
                locked: .safeLastModified("Mon, 23 Nov 2026 12:00:00 GMT")
            )
        )

        // Retry-After 整数秒、封顶与 HTTP-date 解析
        XCTAssertEqual(HTTPPolicy.parseRetryAfter("5", maxDelay: 60), 5.0)
        XCTAssertEqual(HTTPPolicy.parseRetryAfter("120", maxDelay: 60), 60.0)
        let anchor = HTTPPolicy.parseHTTPDate("Mon, 23 Nov 2026 12:00:00 GMT")!
        XCTAssertEqual(
            HTTPPolicy.parseRetryAfter("Mon, 23 Nov 2026 12:00:12 GMT", now: anchor, maxDelay: 60) ?? -1,
            12.0,
            accuracy: 0.01
        )
        XCTAssertEqual(
            HTTPPolicy.parseRetryAfter("Mon, 23 Nov 2026 12:05:00 GMT", now: anchor, maxDelay: 60) ?? -1,
            60.0,
            accuracy: 0.01
        )
    }

    func testRedirectSecurityPolicyAndHeaderSanitization() throws {
        let from = URL(string: "https://cdn-a.example.com/pkg.dmg")!
        let httpTarget = URL(string: "http://cdn-a.example.com/pkg.dmg")!
        XCTAssertThrowsError(
            try HTTPPolicy.validateRedirect(
                from: from,
                to: httpTarget,
                redirectCount: 1,
                maxRedirects: 10,
                requireHTTPS: true
            )
        ) { err in
            XCTAssertEqual(err as? LaneShuntError, .insecureRedirect(from: from, to: httpTarget))
        }

        let userInfoURL = URL(string: "https://user:pass@cdn-a.example.com/pkg.dmg")!
        XCTAssertThrowsError(try HTTPPolicy.validateURL(userInfoURL, requireHTTPS: true)) { err in
            XCTAssertEqual(err as? LaneShuntError, .insecureURL(userInfoURL))
        }

        XCTAssertThrowsError(
            try HTTPPolicy.validateRedirect(
                from: from,
                to: URL(string: "https://cdn-a.example.com/hop")!,
                redirectCount: 11,
                maxRedirects: 10,
                requireHTTPS: true
            )
        ) { err in
            XCTAssertEqual(err as? LaneShuntError, .tooManyRedirects(limit: 10))
        }

        let sameOrigin = URL(string: "https://CDN-A.example.com:443/v2/pkg.dmg")!
        XCTAssertTrue(
            try HTTPPolicy.validateRedirect(
                from: from,
                to: sameOrigin,
                redirectCount: 1,
                maxRedirects: 10,
                requireHTTPS: true
            )
        )

        let crossOrigin = URL(string: "https://cdn-b.example.com/pkg.dmg")!
        XCTAssertFalse(
            try HTTPPolicy.validateRedirect(
                from: from,
                to: crossOrigin,
                redirectCount: 1,
                maxRedirects: 10,
                requireHTTPS: true
            )
        )

        // 请求头清理与恢复校验
        var orig = URLRequest(url: from)
        orig.setValue("bytes=0-1023", forHTTPHeaderField: "Range")
        orig.setValue("\"etag-1\"", forHTTPHeaderField: "If-Range")
        orig.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
        orig.setValue("TestAgent/1.0", forHTTPHeaderField: "User-Agent")

        var proposedSame = URLRequest(url: sameOrigin)
        proposedSame.setValue("secret", forHTTPHeaderField: "Authorization")
        let rebuiltSame = HTTPPolicy.buildRedirectRequest(
            originalRequest: orig,
            proposedRequest: proposedSame,
            isSameOrigin: true,
            userAgent: "TestAgent/1.0"
        )
        XCTAssertEqual(rebuiltSame.value(forHTTPHeaderField: "Range"), "bytes=0-1023")
        XCTAssertEqual(rebuiltSame.value(forHTTPHeaderField: "If-Range"), "\"etag-1\"")
        XCTAssertEqual(rebuiltSame.value(forHTTPHeaderField: "Accept-Encoding"), "identity")

        var proposedCross = URLRequest(url: crossOrigin)
        proposedCross.setValue("Bearer token", forHTTPHeaderField: "Authorization")
        proposedCross.setValue("sid=1", forHTTPHeaderField: "Cookie")
        proposedCross.setValue("https://cdn-a.example.com/", forHTTPHeaderField: "Referer")
        proposedCross.setValue("\"etag-1\"", forHTTPHeaderField: "If-Range")
        let rebuiltCross = HTTPPolicy.buildRedirectRequest(
            originalRequest: orig,
            proposedRequest: proposedCross,
            isSameOrigin: false,
            userAgent: "TestAgent/1.0"
        )
        XCTAssertEqual(rebuiltCross.value(forHTTPHeaderField: "Range"), "bytes=0-1023")
        XCTAssertEqual(rebuiltCross.value(forHTTPHeaderField: "Accept-Encoding"), "identity")
        XCTAssertEqual(rebuiltCross.value(forHTTPHeaderField: "User-Agent"), "TestAgent/1.0")
        XCTAssertNil(rebuiltCross.value(forHTTPHeaderField: "If-Range"))
        XCTAssertNil(rebuiltCross.value(forHTTPHeaderField: "Authorization"))
        XCTAssertNil(rebuiltCross.value(forHTTPHeaderField: "Cookie"))
        XCTAssertNil(rebuiltCross.value(forHTTPHeaderField: "Referer"))
    }

    func testChunkLedgerPartitioningAndPosixOffsetWriter() throws {
        let config = LaneShuntConfig(chunkSize: 256 * 1024)
        let ledger = ChunkLedger(totalBytes: 1_048_576 + 10, config: config)
        XCTAssertEqual(ledger.chunkCount, 5)

        let dest = tempDir.appendingPathComponent("posix-out.bin")
        try Data("stale".utf8).write(to: dest)

        let writer = try PosixOffsetFileWriter(near: dest)
        // 超出 maxBytes 必须在 ftruncate 前拦截
        XCTAssertThrowsError(try writer.preallocate(totalSize: 2048, maxBytes: 1024)) { err in
            XCTAssertEqual(err as? LaneShuntError, .sizeLimitExceeded(limit: 1024, actual: 2048))
        }

        try writer.preallocate(totalSize: 16, maxBytes: 1024)
        // 乱序写入不同偏移区段
        try writer.write(Data("WORLD!!".utf8), atOffset: 9)
        try writer.write(Data("HELLO----".utf8), atOffset: 0)
        let writtenSize = try writer.finalize(expectedSize: 16, destinationURL: dest)
        XCTAssertEqual(writtenSize, 16)
        XCTAssertEqual(try Data(contentsOf: dest), Data("HELLO----WORLD!!".utf8))
        XCTAssertFalse(FileManager.default.fileExists(atPath: writer.tempFileURL.path))
    }

    // MARK: - 2. 本地回环真实多端口 HTTP/1.1 TCP 并发测试

    func testLoopbackRealMultiPortTCPConcurrentDownload() async throws {
        let payload = Self.deterministicPayload(size: 2 * 1024 * 1024, seed: 0x2A)
        let expectedSHA = Self.sha256Hex(payload)

        // 为每个分片响应注入微小延迟以保证 4 条独立 TCP 连接同时在途并发拉取
        let server = try LocalLoopbackHTTPServer(
            payload: payload,
            etag: "\"loopback-2mb\"",
            perChunkDelayMs: 25
        )
        defer { server.stop() }

        let metricsCollector = MetricsCollector()
        var config = LaneShuntConfig(
            maxBytes: 16 * 1024 * 1024,
            requireHTTPS: false,
            maxConnections: 4,
            chunkSize: 256 * 1024,
            minSegmentedSize: 1024 * 1024,
            retryDelay: 0.05
        )
        config.onTransactionMetrics = { tx in
            metricsCollector.record(tx)
        }

        let dest = tempDir.appendingPathComponent("loopback-2mb.bin")
        let result = try await LaneShunt.download(
            from: server.url,
            to: dest,
            config: config
        )

        XCTAssertTrue(result.usedSegmented)
        XCTAssertEqual(result.bytesWritten, Int64(payload.count))
        XCTAssertEqual(result.totalBytes, Int64(payload.count))

        let downloaded = try Data(contentsOf: dest)
        XCTAssertEqual(Self.sha256Hex(downloaded), expectedSHA)
        XCTAssertEqual(downloaded, payload)

        // 断言服务端观察到多个独立客户端 TCP 源端口，而非复用单一连接
        let distinctServerPorts = server.distinctClientPorts()
        XCTAssertGreaterThan(distinctServerPorts.count, 1, "应建立多条独立 TCP 套接字，实际源端口集合: \(distinctServerPorts)")

        // 断言客户端 URLSessionTaskTransactionMetrics 同样证实多条非复用底层套接字
        let metricsSummary = metricsCollector.summary()
        XCTAssertGreaterThan(metricsSummary.distinctLocalPorts.count, 1, "事务指标应记录多个本地源端口")
        XCTAssertGreaterThan(metricsSummary.nonReusedConnectionCount, 1, "事务指标应存在多条独立新建连接")
    }

    // MARK: - 3. 并发乱序完成与后台线程单调进度回调

    func testConcurrentOutOfOrderChunksAndOffMainThreadMonotonicProgress() async throws {
        let payload = Self.deterministicPayload(size: 1_536 * 1024, seed: 0x33)
        let url = URL(string: "https://mock.laneshunt.local/out-of-order.dmg")!
        let etag = "\"ooo-v1\""

        ConcurrentMockURLProtocol.handler = { request, emit in
            let range = Self.parseRangeHeader(request.value(forHTTPHeaderField: "Range"), total: payload.count)
            if let (start, end) = range {
                // 刻意让低编号分片延迟更久，迫使高编号分片先完成落盘
                let chunkIndex = start / (256 * 1024)
                let delayMs = max(5, (6 - chunkIndex) * 15)
                let slice = payload[start...end]
                let headers = [
                    "Content-Range": "bytes \(start)-\(end)/\(payload.count)",
                    "Content-Length": "\(slice.count)",
                    "Accept-Ranges": "bytes",
                    "ETag": etag
                ]
                let resp = HTTPURLResponse(url: request.url!, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: headers)!
                emit.sendPaced(response: resp, data: Data(slice), pieceSize: 32 * 1024, initialDelayMs: delayMs, pieceDelayMs: 5)
            } else {
                let resp = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: [
                    "Content-Length": "\(payload.count)",
                    "ETag": etag
                ])!
                emit.sendImmediate(response: resp, data: payload)
            }
        }

        let recorder = ProgressRecorder()
        let config = LaneShuntConfig(
            maxConnections: 4,
            chunkSize: 256 * 1024,
            minSegmentedSize: 1024 * 1024,
            baseSessionConfiguration: Self.makeMockSessionConfig(),
            progressMinInterval: 0.0
        )

        let dest = tempDir.appendingPathComponent("out-of-order.dmg")
        let result = try await LaneShunt.download(
            from: url,
            to: dest,
            config: config,
            onProgress: { progress in
                recorder.record(progress)
            }
        )

        XCTAssertTrue(result.usedSegmented)
        XCTAssertEqual(try Data(contentsOf: dest), payload)

        let snap = recorder.snapshot()
        XCTAssertFalse(snap.calledOnMainThread, "进度回调绝不能在主线程触发")
        XCTAssertFalse(snap.events.isEmpty)
        XCTAssertEqual(snap.events.last?.bytesReceived, Int64(payload.count))

        var previous: Int64 = 0
        for event in snap.events {
            XCTAssertFalse(event.isReset)
            XCTAssertGreaterThanOrEqual(event.bytesReceived, previous, "唯一已提交进度必须单调不减")
            XCTAssertLessThanOrEqual(event.bytesReceived, Int64(payload.count))
            previous = event.bytesReceived
        }
    }

    // MARK: - 4. 小载荷直通与未知大小探针 200 OK 流直接复用

    func testSmallPayloadSkipsProbeAndUnknownSize200ReusesStream() async throws {
        // 4A. 已知小载荷 (< 1 MiB) 跳过 Range 0-0 探针，首请求断线后二次请求单流完成（总请求恰为 2）
        let smallPayload = Self.deterministicPayload(size: 256 * 1024, seed: 0x41)
        let smallURL = URL(string: "https://mock.laneshunt.local/small.bin")!
        let counterA = AtomicCounter()
        let sawZeroZeroRange = AtomicFlag()

        ConcurrentMockURLProtocol.handler = { request, emit in
            let attempt = counterA.increment()
            if request.value(forHTTPHeaderField: "Range") == "bytes=0-0" {
                sawZeroZeroRange.set()
            }
            if attempt == 1 {
                emit.fail(URLError(.networkConnectionLost))
                return
            }
            let resp = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: [
                "Content-Length": "\(smallPayload.count)",
                "ETag": "\"small-v1\""
            ])!
            emit.sendImmediate(response: resp, data: smallPayload)
        }

        let smallDest = tempDir.appendingPathComponent("small.bin")
        let smallResult = try await LaneShunt.download(
            from: smallURL,
            to: smallDest,
            config: LaneShuntConfig(
                expectedSizeHint: Int64(smallPayload.count),
                retryDelay: 0.01,
                baseSessionConfiguration: Self.makeMockSessionConfig()
            )
        )
        XCTAssertFalse(smallResult.usedSegmented)
        XCTAssertFalse(sawZeroZeroRange.value, "已知小于分片阈值时不应发 Range: bytes=0-0 探针")
        XCTAssertEqual(counterA.value, 2)
        XCTAssertEqual(try Data(contentsOf: smallDest), smallPayload)

        // 4B. 未知大小探针收到 200 OK：直接复用响应流完成，总请求数恰为 1
        let unknownPayload = Self.deterministicPayload(size: 1_200_000, seed: 0x42)
        let unknownURL = URL(string: "https://mock.laneshunt.local/no-range-200.bin")!
        let counterB = AtomicCounter()

        ConcurrentMockURLProtocol.handler = { request, emit in
            _ = counterB.increment()
            let resp = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: [
                "Content-Length": "\(unknownPayload.count)"
            ])!
            emit.sendImmediate(response: resp, data: unknownPayload)
        }

        let dest200 = tempDir.appendingPathComponent("reuse-200.bin")
        let res200 = try await LaneShunt.download(
            from: unknownURL,
            to: dest200,
            config: LaneShuntConfig(
                expectedSizeHint: nil,
                retryDelay: 0.01,
                baseSessionConfiguration: Self.makeMockSessionConfig()
            )
        )
        XCTAssertFalse(res200.usedSegmented)
        XCTAssertEqual(counterB.value, 1, "200 OK 探针必须直接复用响应流，不得二次发请求")
        XCTAssertEqual(res200.bytesWritten, Int64(unknownPayload.count))
        XCTAssertEqual(try Data(contentsOf: dest200), unknownPayload)
    }

    // MARK: - 5. 边界用例：0 字节、1 字节快路径与服务端截短 206 自动补齐尾部

    func testZeroByteOneByteFastPathAndTruncated206TailCompletion() async throws {
        // 5A. 0 字节文件（探针返回 416 bytes */0）
        let emptyCounter = AtomicCounter()
        ConcurrentMockURLProtocol.handler = { request, emit in
            _ = emptyCounter.increment()
            let resp = HTTPURLResponse(url: request.url!, statusCode: 416, httpVersion: "HTTP/1.1", headerFields: [
                "Content-Range": "bytes */0"
            ])!
            emit.sendImmediate(response: resp, data: Data())
        }
        let emptyDest = tempDir.appendingPathComponent("empty.bin")
        let emptyRes = try await LaneShunt.download(
            from: URL(string: "https://mock.laneshunt.local/empty.bin")!,
            to: emptyDest,
            config: LaneShuntConfig(baseSessionConfiguration: Self.makeMockSessionConfig())
        )
        XCTAssertEqual(emptyCounter.value, 1)
        XCTAssertEqual(emptyRes.bytesWritten, 0)
        XCTAssertEqual(try Data(contentsOf: emptyDest), Data())

        // 5B. 1 字节快路径（探针返回 206 bytes 0-0/1，零额外请求）
        let oneCounter = AtomicCounter()
        ConcurrentMockURLProtocol.handler = { request, emit in
            _ = oneCounter.increment()
            let resp = HTTPURLResponse(url: request.url!, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: [
                "Content-Range": "bytes 0-0/1",
                "Content-Length": "1"
            ])!
            emit.sendImmediate(response: resp, data: Data([0x5A]))
        }
        let oneDest = tempDir.appendingPathComponent("one.bin")
        let oneRes = try await LaneShunt.download(
            from: URL(string: "https://mock.laneshunt.local/one.bin")!,
            to: oneDest,
            config: LaneShuntConfig(baseSessionConfiguration: Self.makeMockSessionConfig())
        )
        XCTAssertEqual(oneCounter.value, 1, "1 字节快路径应直接落盘探针字节，总请求数必须为 1")
        XCTAssertFalse(oneRes.usedSegmented)
        XCTAssertEqual(oneRes.bytesWritten, 1)
        XCTAssertEqual(try Data(contentsOf: oneDest), Data([0x5A]))

        // 5C. 截短 206：请求 256 KiB 时服务端每次最多只返回 64 KiB，下载器无缝补全所有尾段且不越界
        let truncPayload = Self.deterministicPayload(size: 1_280 * 1024, seed: 0x55)
        let truncURL = URL(string: "https://mock.laneshunt.local/truncated-206.bin")!
        ConcurrentMockURLProtocol.handler = { request, emit in
            guard let (reqStart, reqEnd) = Self.parseRangeHeader(request.value(forHTTPHeaderField: "Range"), total: truncPayload.count) else {
                emit.fail(URLError(.badServerResponse))
                return
            }
            let cappedEnd = (reqStart == 0 && reqEnd == 0) ? 0 : min(reqEnd, reqStart + 64 * 1024 - 1)
            let slice = truncPayload[reqStart...cappedEnd]
            let resp = HTTPURLResponse(url: request.url!, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: [
                "Content-Range": "bytes \(reqStart)-\(cappedEnd)/\(truncPayload.count)",
                "Content-Length": "\(slice.count)",
                "ETag": "\"trunc-v1\""
            ])!
            emit.sendImmediate(response: resp, data: Data(slice))
        }
        let truncDest = tempDir.appendingPathComponent("truncated-206.bin")
        let truncRes = try await LaneShunt.download(
            from: truncURL,
            to: truncDest,
            config: LaneShuntConfig(
                maxConnections: 4,
                chunkSize: 256 * 1024,
                minSegmentedSize: 1024 * 1024,
                baseSessionConfiguration: Self.makeMockSessionConfig()
            )
        )
        XCTAssertTrue(truncRes.usedSegmented)
        XCTAssertEqual(truncRes.bytesWritten, Int64(truncPayload.count))
        XCTAssertEqual(try Data(contentsOf: truncDest), truncPayload)
    }

    // MARK: - 6. 协议边界：零成本降级、体积超限、逐片编码/multipart 拦截、Last-Modified 与 404/403 立即失败

    func testProtocolEdgeCasesDowngradeLimitsValidatorsAndDeterministicErrors() async throws {
        let payload = Self.deterministicPayload(size: 1_100_000, seed: 0x61)

        // 6A. 弱 ETag 触发同次 attempt 零成本单流降级（1 次探针 + 1 次无 Range GET）
        let weakRequests = AtomicRequestLog()
        ConcurrentMockURLProtocol.handler = { request, emit in
            weakRequests.append(request)
            if request.value(forHTTPHeaderField: "Range") == "bytes=0-0" {
                let resp = HTTPURLResponse(url: request.url!, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: [
                    "Content-Range": "bytes 0-0/\(payload.count)",
                    "ETag": "W/\"weak-etag\""
                ])!
                emit.sendImmediate(response: resp, data: Data([payload[0]]))
            } else {
                let resp = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: [
                    "Content-Length": "\(payload.count)"
                ])!
                emit.sendImmediate(response: resp, data: payload)
            }
        }
        let weakDest = tempDir.appendingPathComponent("weak-downgrade.bin")
        let weakRes = try await LaneShunt.download(
            from: URL(string: "https://mock.laneshunt.local/weak.bin")!,
            to: weakDest,
            config: LaneShuntConfig(baseSessionConfiguration: Self.makeMockSessionConfig())
        )
        XCTAssertFalse(weakRes.usedSegmented)
        XCTAssertEqual(weakRes.attemptsUsed, 1, "弱 ETag 降级应在同一次 attempt 完成，不消耗重试预算")
        let weakLogged = weakRequests.all()
        XCTAssertEqual(weakLogged.count, 2)
        XCTAssertNil(weakLogged[1].value(forHTTPHeaderField: "Range"))
        XCTAssertEqual(try Data(contentsOf: weakDest), payload)

        // 6B. 新鲜 Last-Modified (< 60s) 同样触发同次 attempt 零成本单流降级
        let freshRequests = AtomicRequestLog()
        ConcurrentMockURLProtocol.handler = { request, emit in
            freshRequests.append(request)
            if request.value(forHTTPHeaderField: "Range") == "bytes=0-0" {
                let resp = HTTPURLResponse(url: request.url!, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: [
                    "Content-Range": "bytes 0-0/\(payload.count)",
                    "Date": "Mon, 23 Nov 2026 12:00:20 GMT",
                    "Last-Modified": "Mon, 23 Nov 2026 12:00:00 GMT"
                ])!
                emit.sendImmediate(response: resp, data: Data([payload[0]]))
            } else {
                let resp = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: [
                    "Content-Length": "\(payload.count)"
                ])!
                emit.sendImmediate(response: resp, data: payload)
            }
        }
        let freshDest = tempDir.appendingPathComponent("fresh-lm-downgrade.bin")
        let freshRes = try await LaneShunt.download(
            from: URL(string: "https://mock.laneshunt.local/fresh-lm.bin")!,
            to: freshDest,
            config: LaneShuntConfig(baseSessionConfiguration: Self.makeMockSessionConfig())
        )
        XCTAssertFalse(freshRes.usedSegmented)
        XCTAssertEqual(freshRes.attemptsUsed, 1)
        XCTAssertEqual(freshRequests.all().count, 2)

        // 6C. 安全 Last-Modified (>= 60s) 一致时正常分段；若中段缺失或变更则触发重置
        let safeLM = "Mon, 23 Nov 2026 12:00:00 GMT"
        let originDate = "Mon, 23 Nov 2026 12:05:00 GMT"
        ConcurrentMockURLProtocol.handler = { request, emit in
            let (start, end) = Self.parseRangeHeader(request.value(forHTTPHeaderField: "Range"), total: payload.count)!
            let resp = HTTPURLResponse(url: request.url!, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: [
                "Content-Range": "bytes \(start)-\(end)/\(payload.count)",
                "Date": originDate,
                "Last-Modified": safeLM
            ])!
            emit.sendImmediate(response: resp, data: Data(payload[start...end]))
        }
        let safeLMDest = tempDir.appendingPathComponent("safe-lm.bin")
        let safeLMRes = try await LaneShunt.download(
            from: URL(string: "https://mock.laneshunt.local/safe-lm.bin")!,
            to: safeLMDest,
            config: LaneShuntConfig(baseSessionConfiguration: Self.makeMockSessionConfig())
        )
        XCTAssertTrue(safeLMRes.usedSegmented)
        XCTAssertEqual(try Data(contentsOf: safeLMDest), payload)

        // 6C-2. 锁定 Last-Modified 后若分片缺失或变更 Last-Modified，必须触发重置并切至新版本
        let lmPayloadV2 = Self.deterministicPayload(size: 1_060_000, seed: 0x62)
        let lmDrifted = AtomicFlag()
        let lmChunkCounter = AtomicCounter()
        ConcurrentMockURLProtocol.handler = { request, emit in
            let rangeVal = request.value(forHTTPHeaderField: "Range")
            if !lmDrifted.value {
                let (start, end) = Self.parseRangeHeader(rangeVal, total: payload.count)!
                if start == 0 && end == 0 {
                    let resp = HTTPURLResponse(url: request.url!, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: [
                        "Content-Range": "bytes 0-0/\(payload.count)",
                        "Date": originDate,
                        "Last-Modified": safeLM
                    ])!
                    emit.sendImmediate(response: resp, data: Data([payload[0]]))
                    return
                }
                if lmChunkCounter.increment() == 1 {
                    let resp = HTTPURLResponse(url: request.url!, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: [
                        "Content-Range": "bytes \(start)-\(end)/\(payload.count)",
                        "Date": originDate,
                        "Last-Modified": safeLM
                    ])!
                    emit.sendImmediate(response: resp, data: Data(payload[start...end]))
                    return
                }
                // 第二个分片缺失 Last-Modified 触发漂移重置，随后切换到新版 Last-Modified
                lmDrifted.set()
                let resp = HTTPURLResponse(url: request.url!, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: [
                    "Content-Range": "bytes \(start)-\(end)/\(payload.count)"
                ])!
                emit.sendImmediate(response: resp, data: Data(payload[start...end]))
                return
            }
            let (start, end) = Self.parseRangeHeader(rangeVal, total: lmPayloadV2.count)!
            let resp = HTTPURLResponse(url: request.url!, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: [
                "Content-Range": "bytes \(start)-\(end)/\(lmPayloadV2.count)",
                "Date": "Mon, 23 Nov 2026 12:20:00 GMT",
                "Last-Modified": "Mon, 23 Nov 2026 12:15:00 GMT"
            ])!
            emit.sendImmediate(response: resp, data: Data(lmPayloadV2[start...end]))
        }
        let lmDriftDest = tempDir.appendingPathComponent("safe-lm-drift.bin")
        let lmDriftRes = try await LaneShunt.download(
            from: URL(string: "https://mock.laneshunt.local/safe-lm-drift.bin")!,
            to: lmDriftDest,
            config: LaneShuntConfig(maxConnections: 2, baseSessionConfiguration: Self.makeMockSessionConfig())
        )
        XCTAssertTrue(lmDriftRes.usedSegmented)
        XCTAssertEqual(try Data(contentsOf: lmDriftDest), lmPayloadV2)

        // 6D. 探针总长超 maxBytes 立即报 sizeLimitExceeded（零重试、无临时残留）
        let overLimitCounter = AtomicCounter()
        ConcurrentMockURLProtocol.handler = { request, emit in
            _ = overLimitCounter.increment()
            let resp = HTTPURLResponse(url: request.url!, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: [
                "Content-Range": "bytes 0-0/10485760",
                "ETag": "\"huge\""
            ])!
            emit.sendImmediate(response: resp, data: Data([0]))
        }
        let overDest = tempDir.appendingPathComponent("overlimit.bin")
        do {
            _ = try await LaneShunt.download(
                from: URL(string: "https://mock.laneshunt.local/overlimit.bin")!,
                to: overDest,
                config: LaneShuntConfig(
                    maxBytes: 2 * 1024 * 1024,
                    baseSessionConfiguration: Self.makeMockSessionConfig()
                )
            )
            XCTFail("总长超过 maxBytes 应立即失败")
        } catch let err as LaneShuntError {
            XCTAssertEqual(err, .sizeLimitExceeded(limit: 2 * 1024 * 1024, actual: 10_485_760))
            XCTAssertEqual(overLimitCounter.value, 1)
            XCTAssertTrue(Self.tempPartFiles(in: tempDir).isEmpty)
        }

        // 6E. 分片响应体超发超过 segmentLen 立即报 sizeLimitExceeded 不越界写盘
        ConcurrentMockURLProtocol.handler = { request, emit in
            let (start, end) = Self.parseRangeHeader(request.value(forHTTPHeaderField: "Range"), total: payload.count)!
            let resp = HTTPURLResponse(url: request.url!, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: [
                "Content-Range": "bytes \(start)-\(end)/\(payload.count)",
                "ETag": "\"oversend\""
            ])!
            if start == 0 && end == 0 {
                emit.sendImmediate(response: resp, data: Data([payload[0]]))
            } else {
                // 故意多发 128 字节
                let oversized = Data(repeating: 0xAA, count: (end - start + 1) + 128)
                emit.sendImmediate(response: resp, data: oversized)
            }
        }
        let overChunkDest = tempDir.appendingPathComponent("overchunk.bin")
        do {
            _ = try await LaneShunt.download(
                from: URL(string: "https://mock.laneshunt.local/overchunk.bin")!,
                to: overChunkDest,
                config: LaneShuntConfig(
                    maxConnections: 2,
                    chunkSize: 256 * 1024,
                    minSegmentedSize: 1024 * 1024,
                    baseSessionConfiguration: Self.makeMockSessionConfig()
                )
            )
            XCTFail("分片超发应立即抛出 sizeLimitExceeded")
        } catch let err as LaneShuntError {
            if case .sizeLimitExceeded = err {
                // 预期命中
            } else {
                XCTFail("预期 sizeLimitExceeded，实际 \(err)")
            }
            XCTAssertFalse(FileManager.default.fileExists(atPath: overChunkDest.path))
            XCTAssertTrue(Self.tempPartFiles(in: tempDir).isEmpty)
        }

        // 6F. 分片返回 Content-Encoding: gzip 与 multipart/byteranges 时必须拒绝错位写盘
        for badHeader in [("Content-Encoding", "gzip"), ("Content-Type", "multipart/byteranges; boundary=abc")] {
            let chunkBadSeen = AtomicCounter()
            ConcurrentMockURLProtocol.handler = { request, emit in
                let (start, end) = Self.parseRangeHeader(request.value(forHTTPHeaderField: "Range"), total: payload.count)!
                var headers = [
                    "Content-Range": "bytes \(start)-\(end)/\(payload.count)",
                    "ETag": "\"bad-chunk\""
                ]
                if !(start == 0 && end == 0) {
                    _ = chunkBadSeen.increment()
                    headers[badHeader.0] = badHeader.1
                }
                let resp = HTTPURLResponse(url: request.url!, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: headers)!
                emit.sendImmediate(response: resp, data: Data(payload[start...end]))
            }
            let badDest = tempDir.appendingPathComponent("bad-\(badHeader.0).bin")
            do {
                _ = try await LaneShunt.download(
                    from: URL(string: "https://mock.laneshunt.local/bad-chunk.bin")!,
                    to: badDest,
                    config: LaneShuntConfig(
                        maxConnections: 2,
                        maxFullResets: 1,
                        baseSessionConfiguration: Self.makeMockSessionConfig()
                    )
                )
                XCTFail("分片携带 \(badHeader.0): \(badHeader.1) 不应写入成功")
            } catch is LaneShuntError {
                XCTAssertGreaterThan(chunkBadSeen.value, 0)
                XCTAssertFalse(FileManager.default.fileExists(atPath: badDest.path))
                XCTAssertTrue(Self.tempPartFiles(in: tempDir).isEmpty)
            }
        }

        // 6G. 确定性 404 / 403 立即失败且仅发起 1 次请求
        for statusCode in [404, 403] {
            let errCounter = AtomicCounter()
            ConcurrentMockURLProtocol.handler = { request, emit in
                _ = errCounter.increment()
                let resp = HTTPURLResponse(url: request.url!, statusCode: statusCode, httpVersion: "HTTP/1.1", headerFields: nil)!
                emit.sendImmediate(response: resp, data: Data("err".utf8))
            }
            let errDest = tempDir.appendingPathComponent("err-\(statusCode).bin")
            do {
                _ = try await LaneShunt.download(
                    from: URL(string: "https://mock.laneshunt.local/err-\(statusCode)")!,
                    to: errDest,
                    config: LaneShuntConfig(baseSessionConfiguration: Self.makeMockSessionConfig())
                )
                XCTFail("HTTP \(statusCode) 应立即失败")
            } catch let err as LaneShuntError {
                XCTAssertEqual(err, .httpStatus(statusCode))
                XCTAssertEqual(errCounter.value, 1, "HTTP \(statusCode) 不得重试")
            }
        }
    }

    // MARK: - 7. 重定向安全守卫：HTTPS 降级硬拦截、超跳拦截与同源/跨源头处理

    func testRedirectDowngradeBlockingAndCrossOriginHeaderRevalidation() async throws {
        // 7A. 302 跳转 http:// 立即抛出 insecureRedirect，总请求数 == 1（绝不访问明文目标）
        let downgradeCounter = AtomicCounter()
        let startURL = URL(string: "https://origin.example.com/pkg.dmg")!
        let plainHTTPURL = URL(string: "http://origin.example.com/pkg.dmg")!

        ConcurrentMockURLProtocol.handler = { request, emit in
            _ = downgradeCounter.increment()
            XCTAssertEqual(request.url, startURL, "明文目标绝不应被实际请求")
            let resp = HTTPURLResponse(url: request.url!, statusCode: 302, httpVersion: "HTTP/1.1", headerFields: [
                "Location": plainHTTPURL.absoluteString
            ])!
            emit.redirect(to: plainHTTPURL, response: resp)
        }
        let downDest = tempDir.appendingPathComponent("downgrade.dmg")
        do {
            _ = try await LaneShunt.download(
                from: startURL,
                to: downDest,
                config: LaneShuntConfig(
                    requireHTTPS: true,
                    baseSessionConfiguration: Self.makeMockSessionConfig()
                )
            )
            XCTFail("HTTPS 降级重定向必须抛出 insecureRedirect")
        } catch let err as LaneShuntError {
            XCTAssertEqual(err, .insecureRedirect(from: startURL, to: plainHTTPURL))
            XCTAssertEqual(downgradeCounter.value, 1)
        }

        // 7B. 超过 maxRedirects 立即抛出 tooManyRedirects
        ConcurrentMockURLProtocol.handler = { request, emit in
            let nextHop = URL(string: "https://origin.example.com/loop/\(UUID().uuidString)")!
            let resp = HTTPURLResponse(url: request.url!, statusCode: 302, httpVersion: "HTTP/1.1", headerFields: [
                "Location": nextHop.absoluteString
            ])!
            emit.redirect(to: nextHop, response: resp)
        }
        do {
            _ = try await LaneShunt.download(
                from: startURL,
                to: tempDir.appendingPathComponent("loop.dmg"),
                config: LaneShuntConfig(
                    maxRedirects: 3,
                    baseSessionConfiguration: Self.makeMockSessionConfig()
                )
            )
            XCTFail("超过 maxRedirects 必须失败")
        } catch let err as LaneShuntError {
            XCTAssertEqual(err, .tooManyRedirects(limit: 3))
        }

        // 7C. 跨源 HTTPS 重定向：保留 Range 与 Accept-Encoding: identity，剥离 If-Range，且复检锁定强校验器（ETag 与 Last-Modified 均验证）
        let payload = Self.deterministicPayload(size: 1_100_000, seed: 0x73)
        let originURL = URL(string: "https://host-a.example.com/pkg.dmg")!
        let sameOriginURL = URL(string: "https://host-a.example.com/v2/pkg.dmg")!
        let crossOriginURL = URL(string: "https://host-b.example.com/cdn/pkg.dmg")!

        for useLastModified in [false, true] {
            let sameOriginRequests = AtomicRequestLog()
            let crossOriginRequests = AtomicRequestLog()
            let lockedLM = "Mon, 23 Nov 2026 12:00:00 GMT"
            let dateHeader = "Mon, 23 Nov 2026 12:10:00 GMT"
            let lockedETag = "\"cross-etag-v1\""

            ConcurrentMockURLProtocol.handler = { request, emit in
                let reqURL = request.url!
                let rangeVal = request.value(forHTTPHeaderField: "Range")
                if reqURL == originURL {
                    if rangeVal == "bytes=0-0" {
                        // 探针直接在源站返回 206 锁定强校验器
                        var headers = ["Content-Range": "bytes 0-0/\(payload.count)"]
                        if useLastModified {
                            headers["Date"] = dateHeader
                            headers["Last-Modified"] = lockedLM
                        } else {
                            headers["ETag"] = lockedETag
                        }
                        let resp = HTTPURLResponse(url: reqURL, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: headers)!
                        emit.sendImmediate(response: resp, data: Data([payload[0]]))
                        return
                    }
                    // 分片请求：偶数分片走同源 302，奇数分片走跨源 302
                    let (start, _) = Self.parseRangeHeader(rangeVal, total: payload.count)!
                    let target = ((start / (256 * 1024)) % 2 == 0) ? sameOriginURL : crossOriginURL
                    let resp = HTTPURLResponse(url: reqURL, statusCode: 302, httpVersion: "HTTP/1.1", headerFields: [
                        "Location": target.absoluteString
                    ])!
                    emit.redirect(to: target, response: resp)
                    return
                }

                if reqURL == sameOriginURL {
                    sameOriginRequests.append(request)
                } else if reqURL == crossOriginURL {
                    crossOriginRequests.append(request)
                }

                let (start, end) = Self.parseRangeHeader(rangeVal, total: payload.count)!
                var headers = [
                    "Content-Range": "bytes \(start)-\(end)/\(payload.count)",
                    "Content-Length": "\(end - start + 1)"
                ]
                if useLastModified {
                    headers["Date"] = dateHeader
                    headers["Last-Modified"] = lockedLM
                } else {
                    headers["ETag"] = lockedETag
                }
                let resp = HTTPURLResponse(url: reqURL, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: headers)!
                emit.sendImmediate(response: resp, data: Data(payload[start...end]))
            }

            let dest = tempDir.appendingPathComponent("redirect-\(useLastModified ? "lm" : "etag").dmg")
            let res = try await LaneShunt.download(
                from: originURL,
                to: dest,
                config: LaneShuntConfig(
                    maxConnections: 3,
                    chunkSize: 256 * 1024,
                    minSegmentedSize: 1024 * 1024,
                    userAgent: "LaneShunt-RedirectTest/1.0",
                    baseSessionConfiguration: Self.makeMockSessionConfig()
                )
            )
            XCTAssertTrue(res.usedSegmented)
            XCTAssertEqual(try Data(contentsOf: dest), payload)

            let sameReqs = sameOriginRequests.all()
            let crossReqs = crossOriginRequests.all()
            XCTAssertFalse(sameReqs.isEmpty)
            XCTAssertFalse(crossReqs.isEmpty)

            for req in sameReqs {
                XCTAssertNotNil(req.value(forHTTPHeaderField: "Range"))
                XCTAssertEqual(req.value(forHTTPHeaderField: "Accept-Encoding"), "identity")
                XCTAssertEqual(req.value(forHTTPHeaderField: "If-Range"), useLastModified ? lockedLM : lockedETag)
            }
            for req in crossReqs {
                XCTAssertNotNil(req.value(forHTTPHeaderField: "Range"))
                XCTAssertEqual(req.value(forHTTPHeaderField: "Accept-Encoding"), "identity")
                XCTAssertEqual(req.value(forHTTPHeaderField: "User-Agent"), "LaneShunt-RedirectTest/1.0")
                XCTAssertNil(req.value(forHTTPHeaderField: "If-Range"), "跨源重定向必须剥离 If-Range")
            }
        }
        // 7D. 跨源重定向后目标站返回不匹配的强校验器时，必须拒绝拼接并触发重置失败
        let crossMismatchDest = tempDir.appendingPathComponent("cross-mismatch.dmg")
        ConcurrentMockURLProtocol.handler = { request, emit in
            let reqURL = request.url!
            let rangeVal = request.value(forHTTPHeaderField: "Range")
            if reqURL == originURL {
                if rangeVal == "bytes=0-0" {
                    let resp = HTTPURLResponse(url: reqURL, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: [
                        "Content-Range": "bytes 0-0/\(payload.count)",
                        "ETag": "\"expected-etag\""
                    ])!
                    emit.sendImmediate(response: resp, data: Data([payload[0]]))
                    return
                }
                let resp = HTTPURLResponse(url: reqURL, statusCode: 302, httpVersion: "HTTP/1.1", headerFields: [
                    "Location": crossOriginURL.absoluteString
                ])!
                emit.redirect(to: crossOriginURL, response: resp)
                return
            }
            let (start, end) = Self.parseRangeHeader(rangeVal, total: payload.count)!
            let resp = HTTPURLResponse(url: reqURL, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: [
                "Content-Range": "bytes \(start)-\(end)/\(payload.count)",
                "ETag": "\"different-origin-etag\""
            ])!
            emit.sendImmediate(response: resp, data: Data(payload[start...end]))
        }
        do {
            _ = try await LaneShunt.download(
                from: originURL,
                to: crossMismatchDest,
                config: LaneShuntConfig(
                    maxConnections: 2,
                    maxFullResets: 1,
                    baseSessionConfiguration: Self.makeMockSessionConfig()
                )
            )
            XCTFail("跨源目标返回不匹配强校验器时必须阻止拼接")
        } catch let err as LaneShuntError {
            if case .retriesExhausted = err {
                XCTAssertFalse(FileManager.default.fileExists(atPath: crossMismatchDest.path))
            } else {
                XCTFail("预期重置耗尽 retriesExhausted，实际 \(err)")
            }
        }
    }

    // MARK: - 8. 中途远端换包全量重置与 416 无死循环保护

    func testMidDownloadResourceDriftResetAnd416NoInfiniteLoop() async throws {
        let payloadV1 = Self.deterministicPayload(size: 1_536 * 1024, seed: 0x11)
        let payloadV2 = Self.deterministicPayload(size: 1_280 * 1024, seed: 0x22)
        let url = URL(string: "https://mock.laneshunt.local/latest.dmg")!

        let servedV1Chunks = AtomicCounter()
        let swappedToV2 = AtomicFlag()

        ConcurrentMockURLProtocol.handler = { request, emit in
            let rangeHeader = request.value(forHTTPHeaderField: "Range")
            if !swappedToV2.value {
                let (start, end) = Self.parseRangeHeader(rangeHeader, total: payloadV1.count)!
                if start == 0 && end == 0 {
                    let resp = HTTPURLResponse(url: request.url!, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: [
                        "Content-Range": "bytes 0-0/\(payloadV1.count)",
                        "ETag": "\"release-v1\""
                    ])!
                    emit.sendImmediate(response: resp, data: Data([payloadV1[0]]))
                    return
                }
                let n = servedV1Chunks.increment()
                if n <= 3 {
                    // 前 50% 分片返回 v1
                    let resp = HTTPURLResponse(url: request.url!, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: [
                        "Content-Range": "bytes \(start)-\(end)/\(payloadV1.count)",
                        "ETag": "\"release-v1\""
                    ])!
                    emit.sendImmediate(response: resp, data: Data(payloadV1[start...end]))
                    return
                }
                // 过半后远端切换为 v2（新内容、新强 ETag、新总长）
                swappedToV2.set()
            }

            // 切换后按 v2 服务：若收到旧 If-Range 返回 200 OK（RFC 9110），触发全量重置
            if let ifRange = request.value(forHTTPHeaderField: "If-Range"), ifRange != "\"release-v2\"" {
                let resp = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: [
                    "Content-Length": "\(payloadV2.count)",
                    "ETag": "\"release-v2\""
                ])!
                emit.sendImmediate(response: resp, data: payloadV2)
                return
            }

            let (start, end) = Self.parseRangeHeader(rangeHeader, total: payloadV2.count)!
            let resp = HTTPURLResponse(url: request.url!, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: [
                "Content-Range": "bytes \(start)-\(end)/\(payloadV2.count)",
                "ETag": "\"release-v2\""
            ])!
            emit.sendImmediate(response: resp, data: Data(payloadV2[start...end]))
        }

        let recorder = ProgressRecorder()
        let dest = tempDir.appendingPathComponent("drift-reset.dmg")
        let result = try await LaneShunt.download(
            from: url,
            to: dest,
            config: LaneShuntConfig(
                maxConnections: 3,
                chunkSize: 256 * 1024,
                minSegmentedSize: 1024 * 1024,
                maxFullResets: 2,
                baseSessionConfiguration: Self.makeMockSessionConfig(),
                progressMinInterval: 0.0
            ),
            onProgress: { recorder.record($0) }
        )

        XCTAssertTrue(result.usedSegmented)
        XCTAssertEqual(result.totalBytes, Int64(payloadV2.count))
        XCTAssertEqual(try Data(contentsOf: dest), payloadV2, "最终落盘必须 100% 匹配新版本 v2，不得混入 v1 字节")

        let snap = recorder.snapshot()
        XCTAssertTrue(snap.events.contains(where: { $0.isReset && $0.bytesReceived == 0 }), "漂移重置必须上报 isReset == true 复位进度")
        // 核验最后一次重置之后进度严格单调推进到 v2 满长
        if let lastResetIdx = snap.events.lastIndex(where: { $0.isReset }) {
            let afterReset = snap.events[(lastResetIdx + 1)...]
            var prev: Int64 = 0
            for e in afterReset {
                XCTAssertGreaterThanOrEqual(e.bytesReceived, prev)
                prev = e.bytesReceived
            }
            XCTAssertEqual(afterReset.last?.bytesReceived, Int64(payloadV2.count))
        }

        // 8B. 416（无论是否带 Content-Range）绝不陷入死循环
        for includeContentRange in [true, false] {
            let reqCount = AtomicCounter()
            ConcurrentMockURLProtocol.handler = { request, emit in
                let n = reqCount.increment()
                if request.value(forHTTPHeaderField: "Range") == "bytes=0-0" {
                    let headers = includeContentRange ? ["Content-Range": "bytes */999999"] : [:]
                    let resp = HTTPURLResponse(url: request.url!, statusCode: 416, httpVersion: "HTTP/1.1", headerFields: headers)!
                    emit.sendImmediate(response: resp, data: Data())
                } else if n <= 5 {
                    let resp = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: [
                        "Content-Length": "16"
                    ])!
                    emit.sendImmediate(response: resp, data: Data(repeating: 0x42, count: 16))
                }
            }
            let dest416 = tempDir.appendingPathComponent("416-\(includeContentRange).bin")
            let res416 = try await LaneShunt.download(
                from: URL(string: "https://mock.laneshunt.local/416-\(includeContentRange)")!,
                to: dest416,
                config: LaneShuntConfig(baseSessionConfiguration: Self.makeMockSessionConfig())
            )
            XCTAssertEqual(res416.bytesWritten, 16)
            XCTAssertLessThanOrEqual(reqCount.value, 2)
        }
        // 8C. 单流中途断流通过 Range + If-Range 续传成功（精确 2 次请求）
        let resumePayload = Self.deterministicPayload(size: 128 * 1024, seed: 0x87)
        let resumeAttempt = AtomicCounter()
        let saw206Resume = AtomicFlag()
        ConcurrentMockURLProtocol.handler = { request, emit in
            let attempt = resumeAttempt.increment()
            if attempt == 1 {
                let resp = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: [
                    "Content-Length": "\(resumePayload.count)",
                    "ETag": "\"resume-v1\""
                ])!
                emit.sendPartialThenFail(
                    response: resp,
                    initialData: Data(resumePayload.prefix(64 * 1024)),
                    error: URLError(.networkConnectionLost)
                )
                return
            }
            XCTAssertEqual(request.value(forHTTPHeaderField: "Range"), "bytes=65536-")
            XCTAssertEqual(request.value(forHTTPHeaderField: "If-Range"), "\"resume-v1\"")
            saw206Resume.set()
            let tail = Data(resumePayload.dropFirst(64 * 1024))
            let resp = HTTPURLResponse(url: request.url!, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: [
                "Content-Range": "bytes 65536-\(resumePayload.count - 1)/\(resumePayload.count)",
                "Content-Length": "\(tail.count)",
                "ETag": "\"resume-v1\""
            ])!
            emit.sendImmediate(response: resp, data: tail)
        }
        let resume206Dest = tempDir.appendingPathComponent("single-206-resume.bin")
        let resume206Res = try await LaneShunt.download(
            from: URL(string: "https://mock.laneshunt.local/single-206.bin")!,
            to: resume206Dest,
            config: LaneShuntConfig(
                expectedSizeHint: Int64(resumePayload.count),
                maxAttempts: 3,
                retryDelay: 0.01,
                baseSessionConfiguration: Self.makeMockSessionConfig()
            )
        )
        XCTAssertTrue(saw206Resume.value)
        XCTAssertEqual(resumeAttempt.value, 2)
        XCTAssertEqual(resume206Res.bytesWritten, Int64(resumePayload.count))
        XCTAssertEqual(try Data(contentsOf: resume206Dest), resumePayload)

        // 8D. 单流中途断流后若续传遭遇 416（无 Content-Range）则归零重下不死循环
        let singlePayload = Self.deterministicPayload(size: 128 * 1024, seed: 0x88)
        let singleAttempt = AtomicCounter()
        let sawIfRangeResume = AtomicFlag()
        ConcurrentMockURLProtocol.handler = { request, emit in
            let attempt = singleAttempt.increment()
            if attempt == 1 {
                let resp = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: [
                    "Content-Length": "\(singlePayload.count)",
                    "ETag": "\"single-v1\""
                ])!
                // 发送前一半后断流
                emit.sendPartialThenFail(
                    response: resp,
                    initialData: Data(singlePayload.prefix(64 * 1024)),
                    error: URLError(.networkConnectionLost)
                )
                return
            }
            if attempt == 2,
               request.value(forHTTPHeaderField: "Range") == "bytes=65536-",
               request.value(forHTTPHeaderField: "If-Range") == "\"single-v1\""
            {
                sawIfRangeResume.set()
                // 模拟续传遇 416（无 Content-Range），强制归零重下
                let resp = HTTPURLResponse(url: request.url!, statusCode: 416, httpVersion: "HTTP/1.1", headerFields: nil)!
                emit.sendImmediate(response: resp, data: Data())
                return
            }
            // 第三次请求应已清零不带 Range，完整返回 200
            XCTAssertNil(request.value(forHTTPHeaderField: "Range"))
            let resp = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: [
                "Content-Length": "\(singlePayload.count)",
                "ETag": "\"single-v2\""
            ])!
            emit.sendImmediate(response: resp, data: singlePayload)
        }
        let singleResumeDest = tempDir.appendingPathComponent("single-416-reset.bin")
        let singleResumeRes = try await LaneShunt.download(
            from: URL(string: "https://mock.laneshunt.local/single-416.bin")!,
            to: singleResumeDest,
            config: LaneShuntConfig(
                expectedSizeHint: Int64(singlePayload.count),
                maxAttempts: 3,
                retryDelay: 0.01,
                baseSessionConfiguration: Self.makeMockSessionConfig()
            )
        )
        XCTAssertTrue(sawIfRangeResume.value)
        XCTAssertEqual(singleAttempt.value, 3)
        XCTAssertEqual(singleResumeRes.bytesWritten, Int64(singlePayload.count))
        XCTAssertEqual(try Data(contentsOf: singleResumeDest), singlePayload)
    }

    // MARK: - 9. 慢流轮换、聚合感知有限侦察（场景 A / B / C）与零字节停滞看门狗

    func testScenarioASlowStreamRelativeRotationAndTailHedging() async throws {
        // 场景 A：6 个槽位中前 4 条限速 ~10 KB/s，后 2 条跑通 >= 400 KB/s；轮换后的新连接与快连接跑通高速
        let payload = Self.deterministicPayload(size: 768 * 1024, seed: 0xA1)
        let url = URL(string: "https://mock.laneshunt.local/scenario-a.dmg")!
        let chunkRequestSeq = AtomicCounter()

        ConcurrentMockURLProtocol.handler = { request, emit in
            let (start, end) = Self.parseRangeHeader(request.value(forHTTPHeaderField: "Range"), total: payload.count)!
            let resp = HTTPURLResponse(url: request.url!, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: [
                "Content-Range": "bytes \(start)-\(end)/\(payload.count)",
                "ETag": "\"scenario-a\""
            ])!
            if start == 0 && end == 0 {
                emit.sendImmediate(response: resp, data: Data([payload[0]]))
                return
            }

            let seq = chunkRequestSeq.increment()
            let slice = Data(payload[start...end])
            if seq <= 4 {
                // 4 条初始慢槽：1 KB / 100ms ≈ 10 KB/s
                emit.sendPaced(response: resp, data: slice, pieceSize: 1024, initialDelayMs: 10, pieceDelayMs: 100)
            } else {
                // 2 条快槽与轮换/对冲后新连接：16 KB / 30ms ≈ 530 KB/s
                emit.sendPaced(response: resp, data: slice, pieceSize: 16 * 1024, initialDelayMs: 5, pieceDelayMs: 30)
            }
        }

        let diagBox = DiagnosticsBox()
        var config = LaneShuntConfig(
            maxConnections: 6,
            chunkSize: 64 * 1024,
            minSegmentedSize: 256 * 1024,
            baseSessionConfiguration: Self.makeMockSessionConfig(),
            warmupGracePeriod: 0.12,
            speedSampleWindow: 0.30,
            refSpeedWindow: 15.0,
            slowRelativeRatio: 0.25,
            slowAbsoluteCeilingBytesPerSec: 512 * 1024,
            slowSustainDuration: 0.20,
            slotRotationCooldown: 0.25,
            globalRotationCooldown: 0.15,
            watchdogInterval: 0.05,
            maxConcurrentHedges: 2
        )
        config.onDiagnostics = { diagBox.set($0) }

        let dest = tempDir.appendingPathComponent("scenario-a.dmg")
        let result = try await LaneShunt.download(from: url, to: dest, config: config)
        XCTAssertTrue(result.usedSegmented)
        XCTAssertEqual(try Data(contentsOf: dest), payload)

        let diag = try XCTUnwrap(diagBox.get())
        XCTAssertGreaterThanOrEqual(diag.lastReferenceHighSpeed, 64 * 1024, "快槽排空后仍应保持高位衰减参考基准")
        XCTAssertGreaterThan(diag.totalRotations, 0, "低速慢槽应触发相对慢流轮换")
        XCTAssertGreaterThan(diag.totalHedgesLaunched, 0, "队列排空后空闲快槽应对滞后慢块发起尾块对冲")
        XCTAssertLessThanOrEqual(diag.peakConcurrentHedges, 2, "并发对冲数不得突破全局上限")
    }

    func testScenarioBUniformPacketLossPreservesConcurrencyAfterTwoScouts() async throws {
        // 场景 B：6 条连接全部均匀受限于 25 KB/s（聚合 ~150 KB/s >= 48 KB/s），2 次侦察后停侦察且保持 6 并发不收缩
        let payload = Self.deterministicPayload(size: 384 * 1024, seed: 0xB2)
        let url = URL(string: "https://mock.laneshunt.local/scenario-b.dmg")!

        ConcurrentMockURLProtocol.handler = { request, emit in
            let (start, end) = Self.parseRangeHeader(request.value(forHTTPHeaderField: "Range"), total: payload.count)!
            let resp = HTTPURLResponse(url: request.url!, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: [
                "Content-Range": "bytes \(start)-\(end)/\(payload.count)",
                "ETag": "\"scenario-b\""
            ])!
            if start == 0 && end == 0 {
                emit.sendImmediate(response: resp, data: Data([payload[0]]))
                return
            }
            // 每条流精确 1250 B / 50ms = 25 KB/s（6 条聚合 ≈ 150 KB/s >= 48 KB/s）
            emit.sendPaced(response: resp, data: Data(payload[start...end]), pieceSize: 1250, initialDelayMs: 5, pieceDelayMs: 50)
        }

        let diagBox = DiagnosticsBox()
        var config = LaneShuntConfig(
            maxConnections: 6,
            chunkSize: 32 * 1024,
            minSegmentedSize: 128 * 1024,
            baseSessionConfiguration: Self.makeMockSessionConfig(),
            warmupGracePeriod: 0.12,
            speedSampleWindow: 0.30,
            scoutHighSpeedThresholdBytesPerSec: 64 * 1024,
            scoutSustainDuration: 0.20,
            scoutCooldown: 0.25,
            maxScoutRotations: 2,
            scoutSuccessMinRatio: 2.0,
            scoutSuccessMinSpeedBytesPerSec: 80 * 1024,
            narrowbandAggregateThresholdBytesPerSec: 48 * 1024,
            narrowbandReducedConnections: 2,
            watchdogInterval: 0.05
        )
        config.onDiagnostics = { diagBox.set($0) }

        let dest = tempDir.appendingPathComponent("scenario-b.dmg")
        let result = try await LaneShunt.download(from: url, to: dest, config: config)
        XCTAssertTrue(result.usedSegmented)
        XCTAssertEqual(try Data(contentsOf: dest), payload)

        let diag = try XCTUnwrap(diagBox.get())
        XCTAssertEqual(diag.totalScoutsUsed, 2, "低速场景应最多执行 2 次单槽侦察")
        XCTAssertTrue(diag.scoutingPermanentlyDisabled, "连续 2 次侦察无改善后必须永久停止侦察")
        XCTAssertEqual(diag.activeSlotLimit, 6, "全槽聚合吞吐 >= 48 KB/s 时必须保持并发数不收缩")
        XCTAssertEqual(diag.totalRotations, 2, "停止侦察后绝不应继续无意义轮换")
    }

    func testScenarioCNarrowbandHotspotShrinksConcurrencyAndStopsThrashing() async throws {
        // 场景 C：全部 6 条连接共享 15 KB/s 窄带热点（聚合 < 48 KB/s），2 次侦察后永久停侦察并收缩并发至 2
        let payload = Self.deterministicPayload(size: 36 * 1024, seed: 0xC3)
        let url = URL(string: "https://mock.laneshunt.local/scenario-c.dmg")!

        // 6 条连接共享 15 KB/s，平均每条约 2.5 KB/s（250 B / 100ms）
        ConcurrentMockURLProtocol.handler = { request, emit in
            let (start, end) = Self.parseRangeHeader(request.value(forHTTPHeaderField: "Range"), total: payload.count)!
            let resp = HTTPURLResponse(url: request.url!, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: [
                "Content-Range": "bytes \(start)-\(end)/\(payload.count)",
                "ETag": "\"scenario-c\""
            ])!
            if start == 0 && end == 0 {
                emit.sendImmediate(response: resp, data: Data([payload[0]]))
                return
            }
            // 每条流 250 B / 100ms = 2.5 KB/s，6 条总聚合 = 15 KB/s < 48 KB/s
            emit.sendPaced(response: resp, data: Data(payload[start...end]), pieceSize: 250, initialDelayMs: 5, pieceDelayMs: 100)
        }

        let diagBox = DiagnosticsBox()
        var config = LaneShuntConfig(
            maxConnections: 6,
            chunkSize: 4 * 1024,
            minSegmentedSize: 16 * 1024,
            baseSessionConfiguration: Self.makeMockSessionConfig(),
            warmupGracePeriod: 0.12,
            speedSampleWindow: 0.30,
            scoutHighSpeedThresholdBytesPerSec: 64 * 1024,
            scoutSustainDuration: 0.20,
            scoutCooldown: 0.25,
            maxScoutRotations: 2,
            scoutSuccessMinRatio: 2.0,
            scoutSuccessMinSpeedBytesPerSec: 80 * 1024,
            narrowbandAggregateThresholdBytesPerSec: 48 * 1024,
            narrowbandReducedConnections: 2,
            watchdogInterval: 0.05
        )
        config.onDiagnostics = { diagBox.set($0) }

        let dest = tempDir.appendingPathComponent("scenario-c.dmg")
        let result = try await LaneShunt.download(from: url, to: dest, config: config)
        XCTAssertTrue(result.usedSegmented)
        XCTAssertEqual(try Data(contentsOf: dest), payload)

        let diag = try XCTUnwrap(diagBox.get())
        XCTAssertEqual(diag.totalScoutsUsed, 2, "窄带热点应执行 2 次有限侦察")
        XCTAssertTrue(diag.scoutingPermanentlyDisabled, "2 次无改善后必须锁定零抖动停用侦察")
        XCTAssertEqual(diag.activeSlotLimit, 2, "总聚合 < 48 KB/s 真窄带必须收缩并发至 2")
        XCTAssertEqual(diag.totalRotations, 2, "真窄带下不得出现无限抖动重连")
    }

    func testZeroByteStallWatchdogRecoversStalledChunk() async throws {
        let payload = Self.deterministicPayload(size: 1_024 * 1024, seed: 0x57)
        let url = URL(string: "https://mock.laneshunt.local/stall.dmg")!
        let chunk0Attempts = AtomicCounter()

        ConcurrentMockURLProtocol.handler = { request, emit in
            let (start, end) = Self.parseRangeHeader(request.value(forHTTPHeaderField: "Range"), total: payload.count)!
            let resp = HTTPURLResponse(url: request.url!, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: [
                "Content-Range": "bytes \(start)-\(end)/\(payload.count)",
                "ETag": "\"stall-v1\""
            ])!
            if start == 0 && end == 0 {
                emit.sendImmediate(response: resp, data: Data([payload[0]]))
                return
            }
            if start == 0 && chunk0Attempts.increment() == 1 {
                // 首次拉取 chunk 0 只发响应头、永远不发字节，触发零字节停滞看门狗
                emit.hangAfterResponse(resp)
                return
            }
            emit.sendImmediate(response: resp, data: Data(payload[start...end]))
        }

        let dest = tempDir.appendingPathComponent("stall-recovered.dmg")
        let result = try await LaneShunt.download(
            from: url,
            to: dest,
            config: LaneShuntConfig(
                maxConnections: 2,
                chunkSize: 256 * 1024,
                minSegmentedSize: 1024 * 1024,
                chunkStallTimeout: 0.25,
                baseSessionConfiguration: Self.makeMockSessionConfig(),
                watchdogInterval: 0.05,
                maxConcurrentHedges: 0 // 关闭对冲以纯粹验证零字节停滞看门狗独立恢复能力
            )
        )
        XCTAssertTrue(result.usedSegmented)
        XCTAssertGreaterThanOrEqual(chunk0Attempts.value, 2)
        XCTAssertEqual(try Data(contentsOf: dest), payload)
    }

    // MARK: - 10. 队列排空后有上限尾块对冲（First-Writer-Wins 与落败良性取消）

    func testTailHedgingFirstWriterWinsAndProgressNeverExceeds100Percent() async throws {
        let payload = Self.deterministicPayload(size: 1_024 * 1024, seed: 0x77)
        let url = URL(string: "https://mock.laneshunt.local/hedge.dmg")!
        let chunk0Calls = AtomicCounter()
        let primaryCancelled = AtomicFlag()

        ConcurrentMockURLProtocol.handler = { request, emit in
            let (start, end) = Self.parseRangeHeader(request.value(forHTTPHeaderField: "Range"), total: payload.count)!
            let resp = HTTPURLResponse(url: request.url!, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: [
                "Content-Range": "bytes \(start)-\(end)/\(payload.count)",
                "ETag": "\"hedge-v1\""
            ])!
            if start == 0 && end == 0 {
                emit.sendImmediate(response: resp, data: Data([payload[0]]))
                return
            }
            if start < 256 * 1024 {
                let call = chunk0Calls.increment()
                if call == 1 {
                    // 主流只发 16 KiB 就挂起，等待队列清空后空闲快槽从 16 KiB 发起尾块对冲
                    emit.sendPartialThenHang(
                        response: resp,
                        initialData: Data(payload[start..<(start + 16 * 1024)]),
                        onStopped: { primaryCancelled.set() }
                    )
                    return
                }
                // 对冲流立刻高速返回剩余字节
                emit.sendImmediate(response: resp, data: Data(payload[start...end]))
                return
            }
            emit.sendImmediate(response: resp, data: Data(payload[start...end]))
        }

        let diagBox = DiagnosticsBox()
        let recorder = ProgressRecorder()
        var config = LaneShuntConfig(
            maxConnections: 3,
            chunkSize: 256 * 1024,
            minSegmentedSize: 1024 * 1024,
            chunkStallTimeout: 10.0, // 远大于测试耗时，确保是由尾块对冲而非停滞看门狗接管
            baseSessionConfiguration: Self.makeMockSessionConfig(),
            warmupGracePeriod: 0.1,
            watchdogInterval: 0.05,
            maxConcurrentHedges: 2,
            progressMinInterval: 0.0
        )
        config.onDiagnostics = { diagBox.set($0) }

        let dest = tempDir.appendingPathComponent("hedge.dmg")
        let result = try await LaneShunt.download(
            from: url,
            to: dest,
            config: config,
            onProgress: { recorder.record($0) }
        )

        XCTAssertTrue(result.usedSegmented)
        XCTAssertEqual(try Data(contentsOf: dest), payload)
        XCTAssertEqual(chunk0Calls.value, 2, "chunk 0 应由空闲快槽发起 1 次尾块对冲")
        XCTAssertTrue(primaryCancelled.value, "先到者提交后落败主流应被良性取消")

        let diag = try XCTUnwrap(diagBox.get())
        XCTAssertGreaterThanOrEqual(diag.totalHedgesLaunched, 1)
        XCTAssertLessThanOrEqual(diag.peakConcurrentHedges, 2)

        let snap = recorder.snapshot()
        for event in snap.events {
            XCTAssertLessThanOrEqual(event.bytesReceived, Int64(payload.count), "对冲绝不能造成唯一字节重复计数超过 100%")
        }
        XCTAssertEqual(snap.events.last?.bytesReceived, Int64(payload.count))
    }

    // MARK: - 11. 限流全局退避（整数秒与 HTTP-date）及取消立即唤醒

    func testRateLimitBackoffIntegerAndHTTPDateAndInstantCancellationWakeup() async throws {
        let payload = Self.deterministicPayload(size: 1_024 * 1024, seed: 0x42)

        for useHTTPDate in [false, true] {
            let rateLimitCount = AtomicCounter()
            ConcurrentMockURLProtocol.handler = { request, emit in
                let (start, end) = Self.parseRangeHeader(request.value(forHTTPHeaderField: "Range"), total: payload.count)!
                if start == 0 && end == 0 {
                    let resp = HTTPURLResponse(url: request.url!, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: [
                        "Content-Range": "bytes 0-0/\(payload.count)",
                        "ETag": "\"rl-v1\""
                    ])!
                    emit.sendImmediate(response: resp, data: Data([payload[0]]))
                    return
                }
                if rateLimitCount.increment() == 1 {
                    let retryHeader: String
                    if useHTTPDate {
                        let df = DateFormatter()
                        df.locale = Locale(identifier: "en_US_POSIX")
                        df.timeZone = TimeZone(secondsFromGMT: 0)
                        df.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
                        retryHeader = df.string(from: Date().addingTimeInterval(1.0))
                    } else {
                        retryHeader = "1"
                    }
                    let resp = HTTPURLResponse(url: request.url!, statusCode: 429, httpVersion: "HTTP/1.1", headerFields: [
                        "Retry-After": retryHeader
                    ])!
                    emit.sendImmediate(response: resp, data: Data())
                    return
                }
                let resp = HTTPURLResponse(url: request.url!, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: [
                    "Content-Range": "bytes \(start)-\(end)/\(payload.count)",
                    "ETag": "\"rl-v1\""
                ])!
                emit.sendImmediate(response: resp, data: Data(payload[start...end]))
            }

            let diagBox = DiagnosticsBox()
            var config = LaneShuntConfig(
                maxConnections: 4,
                chunkSize: 256 * 1024,
                minSegmentedSize: 1024 * 1024,
                baseSessionConfiguration: Self.makeMockSessionConfig(),
                watchdogInterval: 0.05
            )
            config.onDiagnostics = { diagBox.set($0) }

            let dest = tempDir.appendingPathComponent("rl-\(useHTTPDate ? "date" : "int").dmg")
            let result = try await LaneShunt.download(
                from: URL(string: "https://mock.laneshunt.local/rl.dmg")!,
                to: dest,
                config: config
            )
            XCTAssertTrue(result.usedSegmented)
            XCTAssertEqual(try Data(contentsOf: dest), payload)
            let diag = try XCTUnwrap(diagBox.get())
            XCTAssertGreaterThanOrEqual(diag.backoffWaveCount, 1)
            XCTAssertLessThan(diag.activeSlotLimit, 4, "收到 429 后必须将并发上限减半")
        }

        // 11B. 30 秒 Retry-After 退避期间取消 Task 必须立即唤醒并原样抛出 CancellationError
        let enteredBackoff = expectation(description: "entered 429 backoff")
        let signalledBackoff = AtomicFlag()
        ConcurrentMockURLProtocol.handler = { request, emit in
            let (start, end) = Self.parseRangeHeader(request.value(forHTTPHeaderField: "Range"), total: payload.count)!
            if start == 0 && end == 0 {
                let resp = HTTPURLResponse(url: request.url!, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: [
                    "Content-Range": "bytes 0-0/\(payload.count)",
                    "ETag": "\"rl-cancel\""
                ])!
                emit.sendImmediate(response: resp, data: Data([payload[0]]))
                return
            }
            if !signalledBackoff.value {
                signalledBackoff.set()
                enteredBackoff.fulfill()
            }
            let resp = HTTPURLResponse(url: request.url!, statusCode: 429, httpVersion: "HTTP/1.1", headerFields: [
                "Retry-After": "30"
            ])!
            emit.sendImmediate(response: resp, data: Data())
        }

        let cancelDest = tempDir.appendingPathComponent("rl-cancel.dmg")
        let startTs = ProcessInfo.processInfo.systemUptime
        let task = Task {
            try await LaneShunt.download(
                from: URL(string: "https://mock.laneshunt.local/rl-cancel.dmg")!,
                to: cancelDest,
                config: LaneShuntConfig(
                    maxConnections: 2,
                    chunkSize: 256 * 1024,
                    minSegmentedSize: 1024 * 1024,
                    baseSessionConfiguration: Self.makeMockSessionConfig(),
                    watchdogInterval: 0.05
                )
            )
        }

        await fulfillment(of: [enteredBackoff], timeout: 3.0)
        try await Task.sleep(nanoseconds: 80_000_000)
        task.cancel()

        do {
            _ = try await task.value
            XCTFail("取消退避任务应抛出 CancellationError")
        } catch is CancellationError {
            let elapsed = ProcessInfo.processInfo.systemUptime - startTs
            XCTAssertLessThan(elapsed, 2.0, "取消必须立即唤醒 30s 退避等待")
            XCTAssertFalse(FileManager.default.fileExists(atPath: cancelDest.path))
            XCTAssertTrue(Self.tempPartFiles(in: tempDir).isEmpty)
        } catch {
            XCTFail("预期原生 CancellationError，实际抛出: \(error)")
        }
    }

    // MARK: - 12. 下载中途取消与临时文件彻底清理

    func testMidDownloadCancellationUnwrapsCancellationErrorAndCleansTempFiles() async throws {
        let payload = Self.deterministicPayload(size: 1_536 * 1024, seed: 0xCC)
        let startedStreaming = expectation(description: "chunk streaming started")
        let fulfilled = AtomicFlag()

        ConcurrentMockURLProtocol.handler = { request, emit in
            let (start, end) = Self.parseRangeHeader(request.value(forHTTPHeaderField: "Range"), total: payload.count)!
            let resp = HTTPURLResponse(url: request.url!, statusCode: 206, httpVersion: "HTTP/1.1", headerFields: [
                "Content-Range": "bytes \(start)-\(end)/\(payload.count)",
                "ETag": "\"cancel-v1\""
            ])!
            if start == 0 && end == 0 {
                emit.sendImmediate(response: resp, data: Data([payload[0]]))
                return
            }
            if !fulfilled.value {
                fulfilled.set()
                startedStreaming.fulfill()
            }
            emit.sendPaced(response: resp, data: Data(payload[start...end]), pieceSize: 4096, initialDelayMs: 10, pieceDelayMs: 80)
        }

        let dest = tempDir.appendingPathComponent("cancelled.dmg")
        let task = Task {
            try await LaneShunt.download(
                from: URL(string: "https://mock.laneshunt.local/cancel.dmg")!,
                to: dest,
                config: LaneShuntConfig(
                    maxConnections: 4,
                    chunkSize: 256 * 1024,
                    minSegmentedSize: 1024 * 1024,
                    baseSessionConfiguration: Self.makeMockSessionConfig(),
                    watchdogInterval: 0.05
                )
            )
        }

        await fulfillment(of: [startedStreaming], timeout: 3.0)
        try await Task.sleep(nanoseconds: 80_000_000)
        let cancelStart = ProcessInfo.processInfo.systemUptime
        task.cancel()

        do {
            _ = try await task.value
            XCTFail("取消中的下载应抛出 CancellationError")
        } catch is CancellationError {
            let stopDuration = ProcessInfo.processInfo.systemUptime - cancelStart
            XCTAssertLessThan(stopDuration, 1.5, "取消任务应在短时间内完成全部 Worker 退出与清理")
            XCTAssertFalse(FileManager.default.fileExists(atPath: dest.path))
            XCTAssertTrue(Self.tempPartFiles(in: tempDir).isEmpty, "取消后不得残留 .part 临时文件")
        } catch {
            XCTFail("必须原样抛出 CancellationError，不得二次包装: \(error)")
        }
    }

    // MARK: - 13. 账本终态竞态、206 溢出防护、会话隔离取消、分片退避、永久 TLS 失败、总超时与合成时钟侦察

    func testChunkLedgerStallTriggerBeforeFinalCommitDoesNotFailDownload() throws {
        let dest = tempDir.appendingPathComponent("stall-race.bin")
        let writer = try PosixOffsetFileWriter(near: dest)
        defer { writer.closeAndCleanup() }
        try writer.preallocate(totalSize: 1024, maxBytes: 4096)

        // maxChunkRetries = 0：若停滞标记误计入瞬态失败，会立刻把账本置为 retriesExhausted 中止
        let config = LaneShuntConfig(
            maxConnections: 1,
            chunkSize: 1024,
            minSegmentedSize: 1024,
            retryDelay: 0.05,
            chunkStallTimeout: 0.2,
            maxChunkRetries: 0
        )
        let ledger = ChunkLedger(totalBytes: 1024, config: config, startedAt: 100.0)
        ledger.markSlotSessionCreated(slotID: 0, now: 100.0)

        guard case .work(let work) = ledger.claimWork(slotID: 0, now: 100.0) else {
            return XCTFail("应当成功领取唯一分片")
        }
        let cancelCalled = AtomicFlag()
        XCTAssertTrue(
            ledger.attachCancelHandler(chunkIndex: work.chunkIndex, attemptSeq: work.attemptSeq) {
                cancelCalled.set()
            }
        )

        // 看门狗在最后数据包落盘前的瞬间记录了停滞触发
        let actions = ledger.evaluateWatchdog(now: 100.3)
        XCTAssertEqual(actions.count, 1)

        // 末包先一步完成落盘提交，使分片进入 isComplete
        let commit = try ledger.commitData(
            chunkIndex: work.chunkIndex,
            attemptSeq: work.attemptSeq,
            streamOffset: 0,
            data: Data(repeating: 0xAB, count: 1024),
            writer: writer,
            now: 100.31
        )
        XCTAssertTrue(commit.chunkCompleted)

        // 随后滞后取消进入 finishAttempt：不应消耗重试配额或中止已完成下载
        let siblingCancels = ledger.finishAttempt(
            chunkIndex: work.chunkIndex,
            slotID: 0,
            attemptSeq: work.attemptSeq,
            madeProgress: true,
            outcome: .transientFailure(
                description: "cancelled",
                retryAfter: nil,
                isRateLimit: false,
                rotateSession: true,
                isTimeout: false
            ),
            now: 100.32
        )
        XCTAssertTrue(siblingCancels.isEmpty)
        XCTAssertTrue(ledger.isCompleted(), "已完成分片绝不能因滞后停滞标记而被判失败")
        XCTAssertNil(ledger.currentAbortReason())
        XCTAssertTrue(ledger.consumeNeedsSessionRotation(slotID: 0))
        XCTAssertFalse(cancelCalled.value)
    }

    func testChunkLedgerSlowOrScoutTriggerDoesNotSwallowTerminalOutcomes() throws {
        let terminalCases: [(name: String, outcome: ChunkAttemptOutcome, verify: (LedgerAbortReason?) -> Void)] = [
            (
                "fatal-404",
                .fatalError(.httpStatus(404)),
                { reason in
                    guard case .fatalError(.httpStatus(404)) = reason else {
                        XCTFail("预期保留 fatalError(httpStatus(404))，实际为 \(String(describing: reason))")
                        return
                    }
                }
            ),
            (
                "drift-reset",
                .driftReset(reason: "etag-changed"),
                { reason in
                    guard case .driftReset(let detail) = reason else {
                        XCTFail("预期保留 driftReset，实际为 \(String(describing: reason))")
                        return
                    }
                    XCTAssertEqual(detail, "etag-changed")
                }
            ),
            (
                "task-cancelled",
                .taskCancelled,
                { reason in
                    guard case .cancelled = reason else {
                        XCTFail("预期保留 cancelled，实际为 \(String(describing: reason))")
                        return
                    }
                }
            )
        ]

        for testCase in terminalCases {
            let dest = tempDir.appendingPathComponent("terminal-\(testCase.name).bin")
            let writer = try PosixOffsetFileWriter(near: dest)
            defer { writer.closeAndCleanup() }
            let chunkSize: Int64 = 64 * 1024
            try writer.preallocate(totalSize: chunkSize * 2, maxBytes: chunkSize * 4)

            let config = LaneShuntConfig(
                maxConnections: 2,
                chunkSize: chunkSize,
                minSegmentedSize: chunkSize,
                chunkStallTimeout: 10.0,
                warmupGracePeriod: 0.1,
                speedSampleWindow: 0.5,
                slowRelativeRatio: 0.25,
                slowSustainDuration: 0.1,
                slotRotationCooldown: 0.1,
                globalRotationCooldown: 0.1,
                scoutHighSpeedThresholdBytesPerSec: 64 * 1024
            )
            let ledger = ChunkLedger(totalBytes: chunkSize * 2, config: config, startedAt: 200.0)
            ledger.markSlotSessionCreated(slotID: 0, now: 200.0)
            ledger.markSlotSessionCreated(slotID: 1, now: 200.0)

            guard case .work(let work0) = ledger.claimWork(slotID: 0, now: 200.0),
                  case .work(let work1) = ledger.claimWork(slotID: 1, now: 200.0)
            else {
                return XCTFail("两个槽位均应领到分片")
            }
            ledger.attachCancelHandler(chunkIndex: work0.chunkIndex, attemptSeq: work0.attemptSeq) {}
            ledger.attachCancelHandler(chunkIndex: work1.chunkIndex, attemptSeq: work1.attemptSeq) {}

            // 槽位 1 写入 64 KiB 确立高速基准，槽位 0 仅写入 1 KiB 触发相对慢槽轮换标记（.slowOrScout）
            _ = try ledger.commitData(
                chunkIndex: work1.chunkIndex,
                attemptSeq: work1.attemptSeq,
                streamOffset: work1.startOffset,
                data: Data(repeating: 0x11, count: Int(chunkSize)),
                writer: writer,
                now: 200.15
            )
            _ = try ledger.commitData(
                chunkIndex: work0.chunkIndex,
                attemptSeq: work0.attemptSeq,
                streamOffset: work0.startOffset,
                data: Data(repeating: 0x22, count: 1024),
                writer: writer,
                now: 200.15
            )

            XCTAssertTrue(ledger.evaluateWatchdog(now: 200.16).isEmpty)
            let slowActions = ledger.evaluateWatchdog(now: 200.30)
            XCTAssertEqual(slowActions.count, 1, "\(testCase.name): 慢槽应命中 .slowOrScout 轮换")

            _ = ledger.finishAttempt(
                chunkIndex: work0.chunkIndex,
                slotID: 0,
                attemptSeq: work0.attemptSeq,
                madeProgress: true,
                outcome: testCase.outcome,
                now: 200.31
            )
            testCase.verify(ledger.currentAbortReason())
            XCTAssertTrue(ledger.consumeNeedsSessionRotation(slotID: 0))
            if case .aborted = ledger.claimWork(slotID: 0, now: 200.32) {
                // 预期账本已终止，不再重新派发分片
            } else {
                XCTFail("\(testCase.name): 终态中止后 claimWork 必须返回 .aborted")
            }
        }
    }

    func testSingleStream206ResumeInt64MaxRangeEndFailsFastWithoutOverflow() async throws {
        let maxLimit: Int64 = 1024 * 1024
        let initialChunk = Data(repeating: 0x55, count: 4096)

        let cases: [(label: String, rangeEnd: Int64, expectedActual: Int64)] = [
            ("int64-max", Int64.max, Int64.max),
            ("oversized-finite", 2_000_000, 2_000_001)
        ]

        for testCase in cases {
            let attemptCounter = AtomicCounter()
            ConcurrentMockURLProtocol.handler = { request, emit in
                let attempt = attemptCounter.increment()
                if attempt == 1 {
                    let resp = HTTPURLResponse(
                        url: request.url!,
                        statusCode: 200,
                        httpVersion: "HTTP/1.1",
                        headerFields: ["ETag": "\"resume-overflow-\(testCase.label)\""]
                    )!
                    emit.sendPartialThenFail(
                        response: resp,
                        initialData: initialChunk,
                        error: URLError(.networkConnectionLost)
                    )
                    return
                }
                XCTAssertEqual(request.value(forHTTPHeaderField: "Range"), "bytes=\(initialChunk.count)-")
                let resp = HTTPURLResponse(
                    url: request.url!,
                    statusCode: 206,
                    httpVersion: "HTTP/1.1",
                    headerFields: [
                        "Content-Range": "bytes \(initialChunk.count)-\(testCase.rangeEnd)/*",
                        "ETag": "\"resume-overflow-\(testCase.label)\""
                    ]
                )!
                emit.sendImmediate(response: resp, data: Data(repeating: 0x66, count: 64))
            }

            let dest = tempDir.appendingPathComponent("overflow-\(testCase.label).bin")
            do {
                _ = try await LaneShunt.download(
                    from: URL(string: "https://mock.laneshunt.local/overflow-\(testCase.label).bin")!,
                    to: dest,
                    config: LaneShuntConfig(
                        expectedSizeHint: 64 * 1024,
                        maxBytes: maxLimit,
                        maxConnections: 1,
                        maxAttempts: 3,
                        retryDelay: 0.01,
                        baseSessionConfiguration: Self.makeMockSessionConfig()
                    )
                )
                XCTFail("\(testCase.label): 超过 maxBytes 的 206 Content-Range 应当立即抛出 sizeLimitExceeded")
            } catch let err as LaneShuntError {
                XCTAssertEqual(err, .sizeLimitExceeded(limit: maxLimit, actual: testCase.expectedActual))
                XCTAssertEqual(attemptCounter.value, 2)
                XCTAssertFalse(FileManager.default.fileExists(atPath: dest.path))
                XCTAssertTrue(Self.tempPartFiles(in: tempDir).isEmpty)
            }
        }
    }

    func testStaleCancelClosureDoesNotCancelReusedSessionNextTask() async throws {
        final class ClosureBox: @unchecked Sendable {
            private let lock = NSLock()
            private var closure: (@Sendable () -> Void)?
            func set(_ value: @escaping @Sendable () -> Void) {
                lock.lock()
                closure = value
                lock.unlock()
            }
            func invoke() {
                lock.lock()
                let fn = closure
                lock.unlock()
                fn?()
            }
        }
        final class DataBox: @unchecked Sendable {
            private let lock = NSLock()
            private var buffer = Data()
            func append(_ data: Data) {
                lock.lock()
                buffer.append(data)
                lock.unlock()
            }
            func snapshot() -> Data {
                lock.lock()
                defer { lock.unlock() }
                return buffer
            }
        }

        let secondPayload = Data("second-task-must-survive-stale-cancel".utf8)
        ConcurrentMockURLProtocol.handler = { request, emit in
            let resp = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
            if request.url?.path == "/first" {
                emit.sendImmediate(response: resp, data: Data("first".utf8))
            } else {
                emit.sendPaced(response: resp, data: secondPayload, pieceSize: 8, initialDelayMs: 5, pieceDelayMs: 15)
            }
        }

        let config = LaneShuntConfig(
            baseSessionConfiguration: Self.makeMockSessionConfig()
        )
        let driver = LaneShunt.IsolatedSessionDriver(
            label: "stale-cancel-test",
            config: config,
            requestTimeout: 5.0,
            resourceTimeout: 10.0
        )
        defer { driver.invalidateAndCancel() }

        let staleCancelBox = ClosureBox()
        let deadline = ProcessInfo.processInfo.systemUptime + 10.0

        // 任务 1 正常结束后保留其取消闭包
        try await driver.runTask(
            request: URLRequest(url: URL(string: "https://mock.laneshunt.local/first")!),
            idleTimeout: 5.0,
            overallDeadline: deadline,
            onTaskCreated: { cancel in
                staleCancelBox.set(cancel)
            },
            onResponse: { _, _ in .allow },
            onData: { _ in }
        )

        // 任务 2 复用同一个会话驱动；在其数据流进行中调用任务 1 遗留的取消闭包，任务 2 必须毫发无损完成
        let receivedSecond = DataBox()
        let firedStaleCancel = AtomicFlag()
        try await driver.runTask(
            request: URLRequest(url: URL(string: "https://mock.laneshunt.local/second")!),
            idleTimeout: 5.0,
            overallDeadline: deadline,
            onResponse: { _, _ in .allow },
            onData: { chunk in
                receivedSecond.append(chunk)
                if !firedStaleCancel.value {
                    firedStaleCancel.set()
                    staleCancelBox.invoke()
                }
            }
        )

        XCTAssertTrue(firedStaleCancel.value)
        XCTAssertEqual(receivedSecond.snapshot(), secondPayload)
    }

    func testChunkLedgerTransientFailureAppliesPerChunkBackoffBeforeReclaim() throws {
        let dest = tempDir.appendingPathComponent("chunk-backoff.bin")
        let writer = try PosixOffsetFileWriter(near: dest)
        defer { writer.closeAndCleanup() }
        try writer.preallocate(totalSize: 2048, maxBytes: 4096)

        let config = LaneShuntConfig(
            maxConnections: 1,
            chunkSize: 1024,
            minSegmentedSize: 1024,
            retryDelay: 0.2,
            watchdogInterval: 1.0,
            maxRetryAfterDelay: 10.0,
            maxChunkRetries: 3
        )
        let t0: TimeInterval = 300.0
        let ledger = ChunkLedger(totalBytes: 2048, config: config, startedAt: t0)
        ledger.markSlotSessionCreated(slotID: 0, now: t0)

        // 1. 领取 chunk 0 并上报非限流瞬态失败
        guard case .work(let work0) = ledger.claimWork(slotID: 0, now: t0) else {
            return XCTFail("应当领取 chunk 0")
        }
        XCTAssertEqual(work0.chunkIndex, 0)
        _ = ledger.finishAttempt(
            chunkIndex: work0.chunkIndex,
            slotID: 0,
            attemptSeq: work0.attemptSeq,
            madeProgress: false,
            outcome: .transientFailure(
                description: "connection lost",
                retryAfter: nil,
                isRateLimit: false,
                rotateSession: true,
                isTimeout: false
            ),
            now: t0
        )

        // 2. chunk 0 处于退避窗口期间，立即可就绪的 chunk 1 不应被阻塞
        guard case .work(let work1) = ledger.claimWork(slotID: 0, now: t0 + 0.01) else {
            return XCTFail("就绪新分片 chunk 1 应立即被派发")
        }
        XCTAssertEqual(work1.chunkIndex, 1)
        _ = try ledger.commitData(
            chunkIndex: work1.chunkIndex,
            attemptSeq: work1.attemptSeq,
            streamOffset: work1.startOffset,
            data: Data(repeating: 0x33, count: 1024),
            writer: writer,
            now: t0 + 0.02
        )
        _ = ledger.finishAttempt(
            chunkIndex: work1.chunkIndex,
            slotID: 0,
            attemptSeq: work1.attemptSeq,
            madeProgress: true,
            outcome: .completedCleanly,
            now: t0 + 0.02
        )

        // 3. 仅剩退避中的 chunk 0 时，claimWork 应返回指向退避截止时间的 .wait
        guard case .wait(let firstReadyAt, _) = ledger.claimWork(slotID: 0, now: t0 + 0.02) else {
            return XCTFail("chunk 0 仍在退避窗口内，应返回 .wait")
        }
        let firstBackoff = firstReadyAt - t0
        XCTAssertGreaterThanOrEqual(firstBackoff, 0.16)
        XCTAssertLessThanOrEqual(firstBackoff, 0.24)

        if case .wait = ledger.claimWork(slotID: 0, now: firstReadyAt - 0.001) {
            // 尚未到达就绪时刻
        } else {
            XCTFail("未到退避截止时间不应提前重领 chunk 0")
        }

        // 4. 到达 firstReadyAt 后可重新领取 chunk 0；再次瞬态失败后退避呈指数增长
        guard case .work(let retryWork0) = ledger.claimWork(slotID: 0, now: firstReadyAt) else {
            return XCTFail("到达退避截止时间后应重新领取 chunk 0")
        }
        XCTAssertEqual(retryWork0.chunkIndex, 0)
        _ = ledger.finishAttempt(
            chunkIndex: retryWork0.chunkIndex,
            slotID: 0,
            attemptSeq: retryWork0.attemptSeq,
            madeProgress: false,
            outcome: .transientFailure(
                description: "connection lost again",
                retryAfter: nil,
                isRateLimit: false,
                rotateSession: true,
                isTimeout: false
            ),
            now: firstReadyAt
        )

        guard case .wait(let secondReadyAt, _) = ledger.claimWork(slotID: 0, now: firstReadyAt + 0.01) else {
            return XCTFail("二次失败后应进入更长的退避等待")
        }
        let secondBackoff = secondReadyAt - firstReadyAt
        XCTAssertGreaterThanOrEqual(secondBackoff, 0.33)
        XCTAssertLessThanOrEqual(secondBackoff, 0.47)
    }

    func testSegmentedDownloadFailsFastOnPermanentTLSError() async throws {
        let totalSize = 1024 * 1024
        let chunkRequests = AtomicCounter()

        ConcurrentMockURLProtocol.handler = { request, emit in
            let rangeHeader = request.value(forHTTPHeaderField: "Range")
            if rangeHeader == "bytes=0-0" {
                let resp = HTTPURLResponse(
                    url: request.url!,
                    statusCode: 206,
                    httpVersion: "HTTP/1.1",
                    headerFields: [
                        "Content-Range": "bytes 0-0/\(totalSize)",
                        "ETag": "\"tls-fast-fail\""
                    ]
                )!
                emit.sendImmediate(response: resp, data: Data([0x01]))
                return
            }
            _ = chunkRequests.increment()
            emit.fail(URLError(.serverCertificateUntrusted))
        }

        let dest = tempDir.appendingPathComponent("tls-fail-fast.dmg")
        do {
            _ = try await LaneShunt.download(
                from: URL(string: "https://mock.laneshunt.local/tls-fail-fast.dmg")!,
                to: dest,
                config: LaneShuntConfig(
                    maxConnections: 1,
                    chunkSize: 256 * 1024,
                    minSegmentedSize: 1024 * 1024,
                    retryDelay: 0.01,
                    baseSessionConfiguration: Self.makeMockSessionConfig(),
                    maxChunkRetries: 4
                )
            )
            XCTFail("证书不可信等永久 TLS 错误应当立即失败")
        } catch let err as LaneShuntError {
            if case .retriesExhausted(let attempts, _, let isTimeout) = err {
                XCTAssertEqual(attempts, 1)
                XCTAssertFalse(isTimeout)
            } else {
                XCTFail("预期 retriesExhausted(attempts: 1)，实际为 \(err)")
            }
            XCTAssertEqual(chunkRequests.value, 1, "永久 TLS 错误绝不能消耗全部分片重试配额")
            XCTAssertFalse(FileManager.default.fileExists(atPath: dest.path))
            XCTAssertTrue(Self.tempPartFiles(in: tempDir).isEmpty)
        }
    }

    func testSegmentedDownloadTotalTimeoutThrowsTimeoutAndCleansTempFiles() async throws {
        let payload = Self.deterministicPayload(size: 1024 * 1024, seed: 0x91)

        ConcurrentMockURLProtocol.handler = { request, emit in
            let (start, end) = Self.parseRangeHeader(request.value(forHTTPHeaderField: "Range"), total: payload.count)!
            let resp = HTTPURLResponse(
                url: request.url!,
                statusCode: 206,
                httpVersion: "HTTP/1.1",
                headerFields: [
                    "Content-Range": "bytes \(start)-\(end)/\(payload.count)",
                    "ETag": "\"total-timeout-v1\""
                ]
            )!
            if start == 0 && end == 0 {
                emit.sendImmediate(response: resp, data: Data([payload[0]]))
                return
            }
            // 持续小包滴水（每 60ms 发 1 KiB），不触发零字节停滞，仅触发 totalTimeout
            emit.sendPaced(
                response: resp,
                data: Data(payload[start...end]),
                pieceSize: 1024,
                initialDelayMs: 10,
                pieceDelayMs: 60
            )
        }

        let dest = tempDir.appendingPathComponent("total-timeout.dmg")
        do {
            _ = try await LaneShunt.download(
                from: URL(string: "https://mock.laneshunt.local/total-timeout.dmg")!,
                to: dest,
                config: LaneShuntConfig(
                    maxConnections: 2,
                    chunkSize: 256 * 1024,
                    minSegmentedSize: 1024 * 1024,
                    singleStreamIdleTimeout: 5.0,
                    chunkStallTimeout: 5.0,
                    totalTimeout: 0.35,
                    baseSessionConfiguration: Self.makeMockSessionConfig(),
                    watchdogInterval: 0.04
                )
            )
            XCTFail("超过 totalTimeout 应当抛出 LaneShuntError.timeout")
        } catch is CancellationError {
            XCTFail("总超时绝不应被错误映射为 CancellationError")
        } catch let err as LaneShuntError {
            if case .timeout = err {
                // 预期命中
            } else {
                XCTFail("预期 LaneShuntError.timeout，实际为 \(err)")
            }
            XCTAssertFalse(FileManager.default.fileExists(atPath: dest.path))
            XCTAssertTrue(Self.tempPartFiles(in: tempDir).isEmpty)
        }
    }

    func testSegmentedDownloadChunkRetriesExhaustedAbortsSiblingsAndCleansTempFiles() async throws {
        let payload = Self.deterministicPayload(size: 768 * 1024, seed: 0x92)
        let chunk0Attempts = AtomicCounter()
        let siblingStopped = AtomicCounter()

        ConcurrentMockURLProtocol.handler = { request, emit in
            let (start, end) = Self.parseRangeHeader(request.value(forHTTPHeaderField: "Range"), total: payload.count)!
            let resp = HTTPURLResponse(
                url: request.url!,
                statusCode: 206,
                httpVersion: "HTTP/1.1",
                headerFields: [
                    "Content-Range": "bytes \(start)-\(end)/\(payload.count)",
                    "ETag": "\"chunk-exhaust-v1\""
                ]
            )!
            if start == 0 && end == 0 {
                emit.sendImmediate(response: resp, data: Data([payload[0]]))
                return
            }
            if start == 0 {
                _ = chunk0Attempts.increment()
                emit.fail(URLError(.networkConnectionLost))
                return
            }
            emit.sendPartialThenHang(
                response: resp,
                initialData: Data(payload[start..<(start + 4096)]),
                onStopped: { _ = siblingStopped.increment() }
            )
        }

        let dest = tempDir.appendingPathComponent("chunk-exhausted.dmg")
        do {
            _ = try await LaneShunt.download(
                from: URL(string: "https://mock.laneshunt.local/chunk-exhausted.dmg")!,
                to: dest,
                config: LaneShuntConfig(
                    maxConnections: 3,
                    chunkSize: 256 * 1024,
                    minSegmentedSize: 512 * 1024,
                    retryDelay: 0.01,
                    chunkStallTimeout: 5.0,
                    baseSessionConfiguration: Self.makeMockSessionConfig(),
                    watchdogInterval: 0.04,
                    maxConcurrentHedges: 0,
                    maxChunkRetries: 2
                )
            )
            XCTFail("单分片连续瞬态失败超出 maxChunkRetries 应抛出 retriesExhausted")
        } catch let err as LaneShuntError {
            if case .retriesExhausted = err {
                // 预期命中
            } else {
                XCTFail("预期 retriesExhausted，实际为 \(err)")
            }
            XCTAssertEqual(chunk0Attempts.value, 3, "应精确执行 1 次首试 + 2 次重试后中止")
            XCTAssertGreaterThanOrEqual(siblingStopped.value, 1, "兄弟在途槽位必须收到中止取消")
            XCTAssertFalse(FileManager.default.fileExists(atPath: dest.path))
            XCTAssertTrue(Self.tempPartFiles(in: tempDir).isEmpty)
        }
    }

    func testChunkLedgerSyntheticClockBoundedScoutScenariosAndScoutSuccess() throws {
        // 使用纯合成时钟驱动 ChunkLedger 状态机，精确验证均匀低速保并发、真窄带缩并发与侦察提速成功三条路径
        func runSyntheticScoutSimulation(
            name: String,
            initialBytesPerStep: Int,
            scoutSlotUpgradedBytesPerStep: Int?,
            stepDuration: TimeInterval = 0.1,
            steps: Int = 45
        ) throws -> DownloaderDiagnosticsSnapshot {
            let chunkSize: Int64 = 512 * 1024
            let totalBytes: Int64 = chunkSize * 12
            let dest = tempDir.appendingPathComponent("synth-\(name).bin")
            let writer = try PosixOffsetFileWriter(near: dest)
            defer { writer.closeAndCleanup() }
            try writer.preallocate(totalSize: totalBytes, maxBytes: totalBytes)

            let config = LaneShuntConfig(
                maxConnections: 6,
                chunkSize: chunkSize,
                minSegmentedSize: chunkSize,
                chunkStallTimeout: 10.0,
                warmupGracePeriod: 0.2,
                speedSampleWindow: 0.5,
                scoutHighSpeedThresholdBytesPerSec: 64 * 1024,
                scoutSustainDuration: 0.3,
                scoutCooldown: 0.3,
                maxScoutRotations: 2,
                scoutSuccessMinRatio: 2.0,
                scoutSuccessMinSpeedBytesPerSec: 80 * 1024,
                narrowbandAggregateThresholdBytesPerSec: 48 * 1024,
                narrowbandReducedConnections: 2
            )

            var now: TimeInterval = 500.0
            let ledger = ChunkLedger(totalBytes: totalBytes, config: config, startedAt: now)
            var activeWork: [Int: (work: ClaimedChunkWork, cursor: Int64)] = [:]
            var upgradedSlots: Set<Int> = []

            for slotID in 0..<6 {
                ledger.markSlotSessionCreated(slotID: slotID, now: now)
                if case .work(let work) = ledger.claimWork(slotID: slotID, now: now) {
                    ledger.attachCancelHandler(chunkIndex: work.chunkIndex, attemptSeq: work.attemptSeq) {}
                    activeWork[slotID] = (work, work.startOffset)
                }
            }

            let normalData = Data(repeating: 0x41, count: initialBytesPerStep)
            let upgradedData = scoutSlotUpgradedBytesPerStep.map { Data(repeating: 0x42, count: $0) }

            for _ in 0..<steps {
                now += stepDuration

                for slotID in 0..<6 {
                    if let current = activeWork[slotID] {
                        let chunkData = (upgradedSlots.contains(slotID) ? upgradedData : nil) ?? normalData
                        let remaining = Int(current.work.endOffset - current.cursor + 1)
                        let sliceLen = min(chunkData.count, remaining)
                        if sliceLen > 0 {
                            let commit = try ledger.commitData(
                                chunkIndex: current.work.chunkIndex,
                                attemptSeq: current.work.attemptSeq,
                                streamOffset: current.cursor,
                                data: chunkData.prefix(sliceLen),
                                writer: writer,
                                now: now
                            )
                            let nextCursor = current.cursor + Int64(sliceLen)
                            if commit.chunkCompleted {
                                _ = ledger.finishAttempt(
                                    chunkIndex: current.work.chunkIndex,
                                    slotID: slotID,
                                    attemptSeq: current.work.attemptSeq,
                                    madeProgress: true,
                                    outcome: .completedCleanly,
                                    now: now
                                )
                                activeWork.removeValue(forKey: slotID)
                            } else {
                                activeWork[slotID] = (current.work, nextCursor)
                            }
                        }
                    }
                }

                _ = ledger.evaluateWatchdog(now: now)

                // 模拟被看门狗标记轮换的槽位结束旧尝试、重建独立会话并领取新分片
                for slotID in 0..<6 {
                    if ledger.consumeNeedsSessionRotation(slotID: slotID) {
                        if let rotated = activeWork.removeValue(forKey: slotID) {
                            _ = ledger.finishAttempt(
                                chunkIndex: rotated.work.chunkIndex,
                                slotID: slotID,
                                attemptSeq: rotated.work.attemptSeq,
                                madeProgress: true,
                                outcome: .transientFailure(
                                    description: "rotated",
                                    retryAfter: nil,
                                    isRateLimit: false,
                                    rotateSession: true,
                                    isTimeout: false
                                ),
                                now: now
                            )
                            _ = ledger.consumeNeedsSessionRotation(slotID: slotID)
                        }
                        ledger.markSlotSessionCreated(slotID: slotID, now: now)
                        if scoutSlotUpgradedBytesPerStep != nil {
                            upgradedSlots.insert(slotID)
                        }
                    }

                    if activeWork[slotID] == nil,
                       case .work(let nextWork) = ledger.claimWork(slotID: slotID, now: now)
                    {
                        ledger.attachCancelHandler(chunkIndex: nextWork.chunkIndex, attemptSeq: nextWork.attemptSeq) {}
                        activeWork[slotID] = (nextWork, nextWork.startOffset)
                    }
                }
            }

            return ledger.diagnosticsSnapshot()
        }

        // 1. 均匀低速但聚合吞吐充足（6 × 20 KB/s = 120 KB/s >= 48 KB/s）：2 次侦察后停侦察并保持 6 并发
        let uniformSlowDiag = try runSyntheticScoutSimulation(
            name: "uniform-slow",
            initialBytesPerStep: 2048,
            scoutSlotUpgradedBytesPerStep: nil
        )
        XCTAssertEqual(uniformSlowDiag.totalScoutsUsed, 2)
        XCTAssertTrue(uniformSlowDiag.scoutingPermanentlyDisabled)
        XCTAssertEqual(uniformSlowDiag.activeSlotLimit, 6)
        XCTAssertEqual(uniformSlowDiag.totalRotations, 2)

        // 2. 真窄带热点（6 × 3 KB/s = 18 KB/s < 48 KB/s）：2 次侦察后停侦察并将并发收缩至 2
        let narrowbandDiag = try runSyntheticScoutSimulation(
            name: "narrowband",
            initialBytesPerStep: 300,
            scoutSlotUpgradedBytesPerStep: nil
        )
        XCTAssertEqual(narrowbandDiag.totalScoutsUsed, 2)
        XCTAssertTrue(narrowbandDiag.scoutingPermanentlyDisabled)
        XCTAssertEqual(narrowbandDiag.activeSlotLimit, 2)
        XCTAssertEqual(narrowbandDiag.totalRotations, 2)

        // 3. 侦察成功（新连接达到 120 KiB/s >= 2x 基线且 >= 80 KiB/s）：重置失败计数、不停用侦察且不收缩并发
        // Top-2 衰减基准随提速槽位与次快槽位越过 64 KiB/s 高速阈值，后续不再消耗侦察配额
        let scoutSuccessDiag = try runSyntheticScoutSimulation(
            name: "scout-success",
            initialBytesPerStep: 2048,
            scoutSlotUpgradedBytesPerStep: 12 * 1024,
            steps: 25
        )
        XCTAssertEqual(scoutSuccessDiag.totalScoutsUsed, 1)
        XCTAssertFalse(scoutSuccessDiag.scoutingPermanentlyDisabled)
        XCTAssertEqual(scoutSuccessDiag.activeSlotLimit, 6)
        XCTAssertGreaterThanOrEqual(scoutSuccessDiag.lastReferenceHighSpeed, 64 * 1024)
    }

    // MARK: - 测试辅助工具

    private static func makeMockSessionConfig() -> URLSessionConfiguration {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [ConcurrentMockURLProtocol.self]
        return cfg
    }

    private static func deterministicPayload(size: Int, seed: UInt8) -> Data {
        var data = Data(count: size)
        data.withUnsafeMutableBytes { raw in
            guard let ptr = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
            for i in 0..<size {
                ptr[i] = UInt8((i &* 31 &+ Int(seed) &+ (i >> 8)) & 0xFF)
            }
        }
        return data
    }

    private static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func parseRangeHeader(_ header: String?, total: Int) -> (Int, Int)? {
        guard let header, header.hasPrefix("bytes=") else { return nil }
        let spec = header.dropFirst("bytes=".count)
        let parts = spec.split(separator: "-", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2, let start = Int(parts[0]) else { return nil }
        let end: Int
        if parts[1].isEmpty {
            end = total - 1
        } else if let parsedEnd = Int(parts[1]) {
            end = min(parsedEnd, total - 1)
        } else {
            return nil
        }
        guard start >= 0, start <= end, end < total else { return nil }
        return (start, end)
    }

    private static func tempPartFiles(in dir: URL) -> [String] {
        let items = (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []
        return items.filter { $0.contains(".part.") }
    }
}

// MARK: - 并发线程安全测试辅助容器

private final class AtomicCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var count: Int = 0

    var value: Int {
        lock.lock()
        defer { lock.unlock() }
        return count
    }

    @discardableResult
    func increment() -> Int {
        lock.lock()
        defer { lock.unlock() }
        count += 1
        return count
    }
}

private final class AtomicFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var flag: Bool = false

    var value: Bool {
        lock.lock()
        defer { lock.unlock() }
        return flag
    }

    func set() {
        lock.lock()
        flag = true
        lock.unlock()
    }
}

private final class AtomicRequestLog: @unchecked Sendable {
    private let lock = NSLock()
    private var requests: [URLRequest] = []

    func append(_ request: URLRequest) {
        lock.lock()
        requests.append(request)
        lock.unlock()
    }

    func all() -> [URLRequest] {
        lock.lock()
        defer { lock.unlock() }
        return requests
    }
}

private final class DiagnosticsBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: DownloaderDiagnosticsSnapshot?

    func set(_ snapshot: DownloaderDiagnosticsSnapshot) {
        lock.lock()
        value = snapshot
        lock.unlock()
    }

    func get() -> DownloaderDiagnosticsSnapshot? {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

private final class ProgressRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var events: [DownloadProgress] = []
    private var onMain: Bool = false

    func record(_ progress: DownloadProgress) {
        lock.lock()
        if Thread.isMainThread { onMain = true }
        events.append(progress)
        lock.unlock()
    }

    func snapshot() -> (events: [DownloadProgress], calledOnMainThread: Bool) {
        lock.lock()
        defer { lock.unlock() }
        return (events, onMain)
    }
}

private final class MetricsCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var localPorts: Set<Int> = []
    private var nonReusedCount: Int = 0
    private var protocols: [String] = []

    func record(_ tx: URLSessionTaskTransactionMetrics) {
        lock.lock()
        if let port = tx.localPort {
            localPorts.insert(port)
        }
        if !tx.isReusedConnection {
            nonReusedCount += 1
        }
        if let proto = tx.networkProtocolName {
            protocols.append(proto)
        }
        lock.unlock()
    }

    func summary() -> (distinctLocalPorts: Set<Int>, nonReusedConnectionCount: Int, protocols: [String]) {
        lock.lock()
        defer { lock.unlock() }
        return (localPorts, nonReusedCount, protocols)
    }
}

// MARK: - 支持并发、限速、挂起与重定向的测试用 URLProtocol

private final class ConcurrentMockURLProtocol: URLProtocol, @unchecked Sendable {
    final class Emitter: @unchecked Sendable {
        private weak var proto: ConcurrentMockURLProtocol?

        init(proto: ConcurrentMockURLProtocol) {
            self.proto = proto
        }

        func sendImmediate(response: HTTPURLResponse, data: Data) {
            proto?.deliverImmediate(response: response, data: data)
        }

        func sendPaced(
            response: HTTPURLResponse,
            data: Data,
            pieceSize: Int,
            initialDelayMs: Int,
            pieceDelayMs: Int
        ) {
            proto?.deliverPaced(
                response: response,
                data: data,
                pieceSize: pieceSize,
                initialDelayMs: initialDelayMs,
                pieceDelayMs: pieceDelayMs
            )
        }

        func hangAfterResponse(_ response: HTTPURLResponse, onStopped: (@Sendable () -> Void)? = nil) {
            proto?.deliverPartialThenHang(response: response, initialData: Data(), onStopped: onStopped)
        }

        func sendPartialThenHang(
            response: HTTPURLResponse,
            initialData: Data,
            onStopped: (@Sendable () -> Void)? = nil
        ) {
            proto?.deliverPartialThenHang(response: response, initialData: initialData, onStopped: onStopped)
        }

        func sendPartialThenFail(response: HTTPURLResponse, initialData: Data, error: Error) {
            proto?.deliverPartialThenFail(response: response, initialData: initialData, error: error)
        }

        func redirect(to targetURL: URL, response: HTTPURLResponse) {
            proto?.deliverRedirect(to: targetURL, response: response)
        }

        func fail(_ error: Error) {
            proto?.deliverFailure(error)
        }
    }

    private static let handlerLock = NSLock()
    private static var _handler: (@Sendable (URLRequest, Emitter) -> Void)?
    static var handler: (@Sendable (URLRequest, Emitter) -> Void)? {
        get {
            handlerLock.lock()
            defer { handlerLock.unlock() }
            return _handler
        }
        set {
            handlerLock.lock()
            defer { handlerLock.unlock() }
            _handler = newValue
        }
    }

    static func reset() {
        handler = nil
    }

    private static let workQueue = DispatchQueue(
        label: "com.laneshunt.test.mockprotocol",
        qos: .userInitiated,
        attributes: .concurrent
    )

    private let stateLock = NSLock()
    private var stopped = false
    private var onStopCallback: (@Sendable () -> Void)?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = Self.handler else {
            client?.urlProtocol(self, didFailWithError: URLError(.unknown))
            return
        }
        let req = request
        let emitter = Emitter(proto: self)
        Self.workQueue.async {
            handler(req, emitter)
        }
    }

    override func stopLoading() {
        stateLock.lock()
        stopped = true
        let cb = onStopCallback
        onStopCallback = nil
        stateLock.unlock()
        cb?()
    }

    private var isStopped: Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return stopped
    }

    fileprivate func deliverImmediate(response: HTTPURLResponse, data: Data) {
        guard !isStopped else { return }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        if !data.isEmpty && !isStopped {
            client?.urlProtocol(self, didLoad: data)
        }
        if !isStopped {
            client?.urlProtocolDidFinishLoading(self)
        }
    }

    fileprivate func deliverPaced(
        response: HTTPURLResponse,
        data: Data,
        pieceSize: Int,
        initialDelayMs: Int,
        pieceDelayMs: Int
    ) {
        if initialDelayMs > 0 {
            if sleepInterruptible(milliseconds: initialDelayMs) { return }
        }
        guard !isStopped else { return }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)

        var offset = 0
        let total = data.count
        let step = max(1, pieceSize)
        while offset < total {
            if isStopped { return }
            let end = min(total, offset + step)
            let piece = data[offset..<end]
            client?.urlProtocol(self, didLoad: Data(piece))
            offset = end
            if offset < total && pieceDelayMs > 0 {
                if sleepInterruptible(milliseconds: pieceDelayMs) { return }
            }
        }
        if !isStopped {
            client?.urlProtocolDidFinishLoading(self)
        }
    }

    fileprivate func deliverPartialThenHang(
        response: HTTPURLResponse,
        initialData: Data,
        onStopped: (@Sendable () -> Void)?
    ) {
        stateLock.lock()
        if stopped {
            stateLock.unlock()
            onStopped?()
            return
        }
        self.onStopCallback = onStopped
        stateLock.unlock()

        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        if !initialData.isEmpty && !isStopped {
            client?.urlProtocol(self, didLoad: initialData)
        }
        // 保持不调用 finishLoading，直至上层通过 stopLoading 取消
    }

    fileprivate func deliverPartialThenFail(response: HTTPURLResponse, initialData: Data, error: Error) {
        guard !isStopped else { return }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        if !initialData.isEmpty && !isStopped {
            client?.urlProtocol(self, didLoad: initialData)
        }
        // 等待 URLSession 串行 delegateQueue 完成 didReceive 与 didLoad 落盘后再注入断流
        if sleepInterruptible(milliseconds: 30) { return }
        if !isStopped {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    fileprivate func deliverRedirect(to targetURL: URL, response: HTTPURLResponse) {
        guard !isStopped else { return }
        var redirectedRequest = URLRequest(url: targetURL)
        redirectedRequest.httpMethod = "GET"
        client?.urlProtocol(self, wasRedirectedTo: redirectedRequest, redirectResponse: response)
    }

    fileprivate func deliverFailure(_ error: Error) {
        guard !isStopped else { return }
        client?.urlProtocol(self, didFailWithError: error)
    }

    private func sleepInterruptible(milliseconds: Int) -> Bool {
        let stepUs: useconds_t = 10_000 // 10ms 粒度，取消后迅速退出线程
        var remainingUs = milliseconds * 1000
        while remainingUs > 0 {
            if isStopped { return true }
            let nap = min(remainingUs, Int(stepUs))
            usleep(useconds_t(nap))
            remainingUs -= nap
        }
        return isStopped
    }
}

// MARK: - 零外部依赖 POSIX 本地回环 HTTP/1.1 TCP 测试服务

private final class LocalLoopbackHTTPServer: @unchecked Sendable {
    let port: UInt16
    var url: URL { URL(string: "http://127.0.0.1:\(port)/payload.bin")! }

    private let listenFD: Int32
    private let payload: Data
    private let etag: String
    private let perChunkDelayMs: Int

    private let lock = NSLock()
    private var running = true
    private var observedClientPorts: Set<UInt16> = []
    private let acceptQueue = DispatchQueue(label: "com.laneshunt.test.httpserver.accept", qos: .userInitiated)
    private let connQueue = DispatchQueue(
        label: "com.laneshunt.test.httpserver.conn",
        qos: .userInitiated,
        attributes: .concurrent
    )

    init(payload: Data, etag: String, perChunkDelayMs: Int = 20) throws {
        self.payload = payload
        self.etag = etag
        self.perChunkDelayMs = perChunkDelayMs

        let fd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }

        var reuse: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        let bindResult = withUnsafePointer(to: &addr) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.bind(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else {
            let err = errno
            Darwin.close(fd)
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(err))
        }

        guard Darwin.listen(fd, 64) == 0 else {
            let err = errno
            Darwin.close(fd)
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(err))
        }

        var boundAddr = sockaddr_in()
        var boundLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        let nameRes = withUnsafeMutablePointer(to: &boundAddr) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.getsockname(fd, sockPtr, &boundLen)
            }
        }
        guard nameRes == 0 else {
            let err = errno
            Darwin.close(fd)
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(err))
        }

        self.listenFD = fd
        self.port = UInt16(bigEndian: boundAddr.sin_port)

        acceptQueue.async { [weak self] in
            self?.acceptLoop()
        }
    }

    func distinctClientPorts() -> Set<UInt16> {
        lock.lock()
        defer { lock.unlock() }
        return observedClientPorts
    }

    func stop() {
        lock.lock()
        if !running {
            lock.unlock()
            return
        }
        running = false
        lock.unlock()
        Darwin.shutdown(listenFD, SHUT_RDWR)
        Darwin.close(listenFD)
    }

    private func isRunning() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return running
    }

    private func acceptLoop() {
        while isRunning() {
            var clientAddr = sockaddr_in()
            var clientLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let clientFD = withUnsafeMutablePointer(to: &clientAddr) { ptr -> Int32 in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    Darwin.accept(listenFD, sockPtr, &clientLen)
                }
            }
            if clientFD < 0 {
                if errno == EINTR { continue }
                break
            }

            // 禁用 SIGPIPE 防止客户端早关连接触发测试进程信号退出
            var noSigPipe: Int32 = 1
            setsockopt(clientFD, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))

            let clientPort = UInt16(bigEndian: clientAddr.sin_port)
            connQueue.async { [weak self] in
                self?.handleConnection(clientFD: clientFD, clientPort: clientPort)
            }
        }
    }

    private func handleConnection(clientFD: Int32, clientPort: UInt16) {
        defer { Darwin.close(clientFD) }

        while isRunning() {
            guard let requestText = readHTTPRequestHeaders(fd: clientFD) else {
                return
            }

            lock.lock()
            observedClientPorts.insert(clientPort)
            lock.unlock()

            let headers = parseHeaders(requestText)
            let rangeHeader = headers["range"]

            if let rangeHeader,
               rangeHeader.hasPrefix("bytes="),
               let (start, end) = parseRange(rangeHeader, total: payload.count)
            {
                if !(start == 0 && end == 0) && perChunkDelayMs > 0 {
                    usleep(useconds_t(perChunkDelayMs * 1000))
                }
                let slice = payload[start...end]
                let headerText =
                    "HTTP/1.1 206 Partial Content\r\n" +
                    "Content-Length: \(slice.count)\r\n" +
                    "Content-Range: bytes \(start)-\(end)/\(payload.count)\r\n" +
                    "Accept-Ranges: bytes\r\n" +
                    "ETag: \(etag)\r\n" +
                    "Connection: keep-alive\r\n\r\n"
                guard sendAll(fd: clientFD, data: Data(headerText.utf8)),
                      sendAll(fd: clientFD, data: Data(slice))
                else {
                    return
                }
            } else {
                let headerText =
                    "HTTP/1.1 200 OK\r\n" +
                    "Content-Length: \(payload.count)\r\n" +
                    "Accept-Ranges: bytes\r\n" +
                    "ETag: \(etag)\r\n" +
                    "Connection: keep-alive\r\n\r\n"
                guard sendAll(fd: clientFD, data: Data(headerText.utf8)),
                      sendAll(fd: clientFD, data: payload)
                else {
                    return
                }
            }

            if headers["connection"]?.lowercased() == "close" {
                return
            }
        }
    }

    private func readHTTPRequestHeaders(fd: Int32) -> String? {
        var buffer = Data()
        var tmp = [UInt8](repeating: 0, count: 1024)
        let delimiter = Data("\r\n\r\n".utf8)
        while buffer.count < 16_384 {
            let n = Darwin.recv(fd, &tmp, tmp.count, 0)
            if n < 0 {
                if errno == EINTR { continue }
                return nil
            }
            if n == 0 {
                return nil
            }
            buffer.append(tmp, count: n)
            if buffer.range(of: delimiter) != nil {
                return String(data: buffer, encoding: .utf8)
            }
        }
        return nil
    }

    private func parseHeaders(_ text: String) -> [String: String] {
        var result: [String: String] = [:]
        let lines = text.components(separatedBy: "\r\n")
        for line in lines.dropFirst() {
            if line.isEmpty { break }
            if let colon = line.firstIndex(of: ":") {
                let key = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
                let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
                result[key] = value
            }
        }
        return result
    }

    private func parseRange(_ header: String, total: Int) -> (Int, Int)? {
        let spec = header.dropFirst("bytes=".count)
        let parts = spec.split(separator: "-", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2, let start = Int(parts[0]) else { return nil }
        let end = parts[1].isEmpty ? (total - 1) : (Int(parts[1]) ?? -1)
        guard start >= 0, start <= end, end < total else { return nil }
        return (start, end)
    }

    private func sendAll(fd: Int32, data: Data) -> Bool {
        data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return true }
            var sent = 0
            while sent < raw.count {
                let n = Darwin.send(fd, base.advanced(by: sent), raw.count - sent, 0)
                if n < 0 {
                    if errno == EINTR { continue }
                    return false
                }
                if n == 0 { return false }
                sent += n
            }
            return true
        }
    }
}
