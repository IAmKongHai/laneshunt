#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif
import Foundation

/// 基于 POSIX `pwrite` 的无重叠流式偏移写盘器，严格管控临时文件独占创建、预分配与句柄退出顺序
final class PosixOffsetFileWriter: @unchecked Sendable {
    let tempFileURL: URL

    private let stateLock = NSLock()
    private var fd: Int32
    private var isFinalized: Bool = false
    private var inFlightWrites: Int = 0

    /// 在 `destinationURL` 同目录独占创建权限为 `0o600` 的临时文件（禁止符号链接追踪与 `O_APPEND`）
    init(near destinationURL: URL) throws {
        let parentDir = destinationURL.deletingLastPathComponent()
        let baseName = destinationURL.lastPathComponent.isEmpty ? "download" : destinationURL.lastPathComponent

        var openedFD: Int32 = -1
        var createdURL: URL?
        var lastErrno: Int32 = 0

        for _ in 0..<8 {
            let suffix = UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(12)
            let candidate = parentDir.appendingPathComponent(".laneshunt-\(baseName).part.\(suffix)")
            let flags = O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW
            let result = candidate.path.withCString { cPath in
                Self.posixOpen(cPath, flags, mode_t(0o600))
            }
            if result >= 0 {
                openedFD = result
                createdURL = candidate
                break
            }
            lastErrno = errno
            if lastErrno != EEXIST {
                break
            }
        }

        guard openedFD >= 0, let finalTempURL = createdURL else {
            throw LaneShuntError.fileIO(
                "Failed to create temp file near \(destinationURL.path): \(Self.errnoMessage(lastErrno))"
            )
        }

        self.fd = openedFD
        self.tempFileURL = finalTempURL
    }

    deinit {
        closeAndCleanup()
    }

    /// 预分配目标文件大小（调用 `ftruncate` 前严格校验体积在 `[0, maxBytes]` 范围内）
    func preallocate(totalSize: Int64, maxBytes: Int64) throws {
        guard totalSize >= 0, totalSize <= maxBytes else {
            throw LaneShuntError.sizeLimitExceeded(limit: maxBytes, actual: totalSize)
        }
        try truncateFile(to: totalSize, skipIfZero: true)
    }

    /// 将临时文件截断归零（供单流重试遇 200/416 重置偏移时复用）
    func truncateToZero() throws {
        try truncateFile(to: 0)
    }

    private func truncateFile(to size: Int64, skipIfZero: Bool = false) throws {
        let activeFD = try beginFileOperation()
        defer { endFileOperation() }

        if skipIfZero && size == 0 { return }
        while true {
            if ftruncate(activeFD, off_t(size)) == 0 {
                return
            }
            let err = errno
            if err == EINTR { continue }
            throw LaneShuntError.fileIO("ftruncate(\(size)) failed: \(Self.errnoMessage(err))")
        }
    }

    /// 按偏移量并发安全写入数据，零扁平拷贝遍历 `data.regions` 并处理短写与 `EINTR`
    func write(_ data: Data, atOffset offset: Int64) throws {
        guard offset >= 0 else {
            throw LaneShuntError.fileIO("Negative write offset: \(offset)")
        }
        if data.isEmpty { return }

        let activeFD = try beginFileOperation()
        defer { endFileOperation() }

        var currentOffset = offset
        for region in data.regions {
            if region.isEmpty { continue }
            try region.withUnsafeBytes { rawBuffer in
                guard let baseAddress = rawBuffer.baseAddress else { return }
                var writtenInRegion = 0
                let totalInRegion = rawBuffer.count
                while writtenInRegion < totalInRegion {
                    let remaining = totalInRegion - writtenInRegion
                    let ptr = baseAddress.advanced(by: writtenInRegion)
                    let written = pwrite(activeFD, ptr, remaining, off_t(currentOffset))
                    if written < 0 {
                        let err = errno
                        if err == EINTR { continue }
                        throw LaneShuntError.fileIO(
                            "pwrite at offset \(currentOffset) failed: \(Self.errnoMessage(err))"
                        )
                    }
                    if written == 0 {
                        throw LaneShuntError.fileIO("pwrite returned 0 bytes at offset \(currentOffset)")
                    }
                    writtenInRegion += written
                    currentOffset += Int64(written)
                }
            }
        }
    }

    /// 全部工作任务退出后调用：校验最终文件尺寸、落盘同步、关闭句柄并原子重命名至 `destinationURL`
    @discardableResult
    func finalize(expectedSize: Int64?, destinationURL: URL) throws -> Int64 {
        stateLock.lock()
        guard fd >= 0 else {
            stateLock.unlock()
            throw LaneShuntError.fileIO("Cannot finalize an already closed file writer")
        }
        guard inFlightWrites == 0 else {
            stateLock.unlock()
            throw LaneShuntError.fileIO("Cannot finalize while \(inFlightWrites) writes are still active")
        }
        let closingFD = fd
        fd = -1
        stateLock.unlock()

        var st = stat()
        if fstat(closingFD, &st) != 0 {
            let err = errno
            _ = Self.posixClose(closingFD)
            unlinkTempFile()
            throw LaneShuntError.fileIO("fstat failed: \(Self.errnoMessage(err))")
        }
        let actualSize = Int64(st.st_size)
        if let expectedSize, actualSize != expectedSize {
            _ = Self.posixClose(closingFD)
            unlinkTempFile()
            throw LaneShuntError.fileIO(
                "Final file size mismatch: expected \(expectedSize), actual \(actualSize)"
            )
        }

        while fsync(closingFD) != 0 {
            let err = errno
            if err == EINTR { continue }
            if err == EINVAL || err == ENOTSUP || err == ENOTTY {
                break
            }
            _ = Self.posixClose(closingFD)
            unlinkTempFile()
            throw LaneShuntError.fileIO("fsync failed: \(Self.errnoMessage(err))")
        }

        if Self.posixClose(closingFD) != 0 {
            let err = errno
            if err != EINTR {
                unlinkTempFile()
                throw LaneShuntError.fileIO("close failed: \(Self.errnoMessage(err))")
            }
        }

        let renameResult = tempFileURL.path.withCString { srcPath in
            destinationURL.path.withCString { dstPath in
                rename(srcPath, dstPath)
            }
        }
        if renameResult != 0 {
            let err = errno
            unlinkTempFile()
            throw LaneShuntError.fileIO(
                "Atomic rename to \(destinationURL.path) failed: \(Self.errnoMessage(err))"
            )
        }

        stateLock.lock()
        isFinalized = true
        stateLock.unlock()
        return actualSize
    }

    /// 幂等关闭句柄并删除未落位的临时文件
    func closeAndCleanup() {
        stateLock.lock()
        let closingFD = fd
        let shouldUnlink = !isFinalized
        fd = -1
        isFinalized = true
        stateLock.unlock()

        if closingFD >= 0 {
            _ = Self.posixClose(closingFD)
        }
        if shouldUnlink {
            unlinkTempFile()
        }
    }

    private func beginFileOperation() throws -> Int32 {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard fd >= 0 else {
            throw LaneShuntError.fileIO("File writer is already closed")
        }
        inFlightWrites += 1
        return fd
    }

    private func endFileOperation() {
        stateLock.lock()
        inFlightWrites -= 1
        stateLock.unlock()
    }

    private func unlinkTempFile() {
        _ = tempFileURL.path.withCString { cPath in
            unlink(cPath)
        }
    }

    private static func posixOpen(_ path: UnsafePointer<CChar>, _ flags: Int32, _ mode: mode_t) -> Int32 {
        #if canImport(Darwin)
        Darwin.open(path, flags, mode)
        #elseif canImport(Glibc)
        Glibc.open(path, flags, mode)
        #elseif canImport(Musl)
        Musl.open(path, flags, mode)
        #endif
    }

    private static func posixClose(_ fd: Int32) -> Int32 {
        #if canImport(Darwin)
        Darwin.close(fd)
        #elseif canImport(Glibc)
        Glibc.close(fd)
        #elseif canImport(Musl)
        Musl.close(fd)
        #endif
    }

    private static func errnoMessage(_ code: Int32) -> String {
        if let cStr = strerror(code) {
            return "\(String(cString: cStr)) (errno=\(code))"
        }
        return "errno=\(code)"
    }
}
