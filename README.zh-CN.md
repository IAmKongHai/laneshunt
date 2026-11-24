# LaneShunt

[![CI](https://github.com/IAmKongHai/laneshunt/actions/workflows/ci.yml/badge.svg)](https://github.com/IAmKongHai/laneshunt/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[English README](README.md)

**零外部依赖的 Swift / Go 原生多连接动态分片下载引擎，内置慢流换路与增量尾部对冲。**

LaneShunt 专为高丢包弱网环境（例如晚高峰 30%+ 丢包的跨境直连链路）设计。在这类网络下，普通单连接 TCP 或多路复用的 HTTP/2 很容易落入拥塞窗口坍塌状态，以几 KB/s 的速度“滴水式”爬行数分钟，却又不会触发无数据空闲超时。

---

## 核心特性

- **真正独立的底层 TCP 连接槽**：
  - Swift 侧每槽独立 `.ephemeral` `URLSession`（`httpMaximumConnectionsPerHost = 1`），规避跨分片队头阻塞。
  - Go 侧每槽深拷贝独立 `http.Transport`，关闭 `ForceAttemptHTTP2` 并显式覆写 `TLSClientConfig.NextProtos = ["http/1.1"]`，确保建立多条独立 TCP 套接字。
- **零浪费能力探测与平滑回退**：先发 `GET Range: bytes=0-0` 探测；小文件、服务端不支持 `Range`、返回非 `identity` 编码或缺失强校验器时，自动无感降级为单流续传。
- **256 KiB 不可变微块账本 + 偏移直写**：各 Worker 通过 POSIX `pwrite` / `os.File.WriteAt` 按偏移直接流式写入单个预分配临时文件，内存占用恒定极低。
- **衰减高速基准 + 有限侦察慢流换路**：实时监测单槽吞吐，主动淘汰慢连接并重建新 TCP 套接字；面对整体窄带网络（如 15 KB/s 热点），经有限次单槽侦察后自动收缩并发，避免无限重连抖动。
- **有上限增量尾部对冲**：微块队列排空后，空闲快槽从滞后尾块的已提交偏移继续对冲拉取，胜者落盘即取消败者流，大幅消除长尾延迟。
- **生产级协议安全**：默认强制 HTTPS 并硬拦截 `https -> http` 明文降级重定向；跨主机跳转自动剥离 `If-Range`；全过程强校验 `ETag`/`Last-Modified` 与总长度，中途远端换包自动全量重置防字节拼接；尊重 `Retry-After` 并在 `429/502/503/504` 时并发减半；永久 TLS 证书错误快速失败。

### 真实跨境弱网生产实测

本引擎从 [CraftPaste](https://github.com/IAmKongHai/CraftPaste) 自动更新模块经生产发版验证后抽离，在约 31% 丢包的跨境直连链路下实测表现：

| 指标 | 普通单连接 HTTP/2 | LaneShunt（6 并发独立槽） |
| --- | --- | --- |
| 测试安装包体积 | 6.28 MiB（`6,587,560` 字节） | 6.28 MiB（`6,587,560` 字节） |
| 实际下载耗时 | 3–10 分钟（常卡顿或总超时失败） | **3.5–4.0 秒**（峰值约 3.25 MiB/s） |
| 服务端 4xx / 5xx / 416 错误 | — | **0** |
| 尾部对冲额外流量放大 | — | **约 10.9%**（~705 KiB） |

---

## 快速开始

### Swift (SwiftPM)

需要 Swift 6.0+（支持 `macOS 13+`、`iOS 16+`、`tvOS 16+`、`watchOS 9+`），仅依赖 `Foundation` 与 `Darwin`/`Glibc`。

```swift
dependencies: [
    .package(url: "https://github.com/IAmKongHai/laneshunt.git", from: "0.1.0")
]
```

```swift
import Foundation
import LaneShunt

let result = try await LaneShunt.download(
    from: URL(string: "https://example.com/release.dmg")!,
    to: URL(fileURLWithPath: "/tmp/release.dmg"),
    config: LaneShuntConfig(maxConnections: 6)
) { progress in
    if let fraction = progress.fractionCompleted {
        print(String(format: "%.1f%%", fraction * 100))
    }
}
```

### Go (Go Module)

需要 Go 1.22+，纯标准库实现，跨平台支持 macOS / Linux / Windows。

```bash
go get github.com/IAmKongHai/laneshunt/go@v0.1.0
```

```go
cfg := laneshunt.DefaultConfig()
cfg.MaxConnections = 6
res, err := laneshunt.Download(ctx, "https://example.com/setup.exe", "/tmp/setup.exe", cfg)
```

### 命令行工具与本地慢流对比压测

```bash
cd go
# 一键运行本地模拟慢流对比测试（4 条慢连接 + 2 条快连接，对比标准单连接 vs LaneShunt）
go run ./cmd/laneshunt -bench

# 直接使用命令行下载文件
go run ./cmd/laneshunt https://example.com/archive.tar.gz ./archive.tar.gz
```

详细算法原理与双语言行为对齐规范请参阅 [docs/architecture.md](docs/architecture.md)。

## 开源协议

[MIT](LICENSE)
