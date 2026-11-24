package laneshunt

import (
	"errors"
	"fmt"
	"net/http"
	"time"
)

const (
	// DefaultMaxBytes 为默认允许落盘的最大字节数（256 MiB）。
	DefaultMaxBytes int64 = 256 << 20
	// DefaultMaxRedirects 为默认允许的最大重定向跳数。
	DefaultMaxRedirects = 10
	// DefaultMaxConnections 为分段模式默认并发独立 TCP 连接数。
	DefaultMaxConnections = 6
	// DefaultChunkSize 为默认不可变微切片尺寸（256 KiB）。
	DefaultChunkSize int64 = 256 << 10
	// DefaultMinSegmentedSize 为启用分段下载的默认最小文件尺寸（1 MiB）。
	DefaultMinSegmentedSize int64 = 1 << 20
	// DefaultMaxAttempts 为外层下载最大尝试次数（含首次）。
	DefaultMaxAttempts = 3
	// DefaultMaxFullResets 为中途远端资源变更时允许的最大全量重置次数。
	DefaultMaxFullResets = 2
	// DefaultRetryDelay 为默认重试等待间隔。
	DefaultRetryDelay = 2 * time.Second
	// DefaultSingleStreamIdleTimeout 为单流模式默认无数据空闲中断阈值。
	DefaultSingleStreamIdleTimeout = 60 * time.Second
	// DefaultChunkStallTimeout 为分段模式默认单片零字节假死中断阈值。
	DefaultChunkStallTimeout = 15 * time.Second
	// DefaultTotalTimeout 为整次下载的默认硬总时限。
	DefaultTotalTimeout = 10 * time.Minute

	// 以下为内部启发式调优默认参数（不对外暴露为公共 API）。
	defaultWarmupGrace             = 2 * time.Second
	defaultRateWindow              = 3 * time.Second
	defaultRefHighSpeedWindow      = 18 * time.Second
	defaultRelativeSlowDuration    = 3 * time.Second
	defaultSlotRotateCooldown      = 8 * time.Second
	defaultGlobalRotateCooldown    = 3 * time.Second
	defaultScoutTriggerDuration    = 8 * time.Second
	defaultScoutCooldown           = 10 * time.Second
	defaultMaxScouts               = 2
	defaultWatchdogInterval        = 500 * time.Millisecond
	defaultMaxRetryAfter           = 60 * time.Second
	defaultMaxConcurrentHedges     = 2
	defaultMaxRotationsPerDownload = 12
	defaultProgressMinInterval     = 50 * time.Millisecond
)

var (
	// ErrInsecureURL 表示目标地址不是合法 HTTPS 地址或包含凭据信息。
	ErrInsecureURL = errors.New("insecure download url")
	// ErrInsecureRedirect 表示重定向降级到非 HTTPS 协议或包含非法目标地址。
	ErrInsecureRedirect = errors.New("insecure redirect")
	// ErrTooManyRedirects 表示重定向跳数超过允许上限。
	ErrTooManyRedirects = errors.New("too many redirects")
	// ErrTimeout 表示下载因空闲超时、分片停滞或总时限超时中断。
	ErrTimeout = errors.New("download timed out")
	// ErrSizeLimitExceeded 表示远端声明或实际发送的数据超出安全体积上限。
	ErrSizeLimitExceeded = errors.New("download size limit exceeded")
	// ErrFileIO 表示本地临时文件或落盘操作失败。
	ErrFileIO = errors.New("download file i/o error")
)

// HTTPStatusError 表示服务端返回非预期 HTTP 状态码。
type HTTPStatusError struct {
	StatusCode int
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("HTTP %d", e.StatusCode)
}

// TimeoutError 表示下载超时错误，可通过 errors.Is(err, ErrTimeout) 匹配。
type TimeoutError struct {
	Cause error
}

func (e *TimeoutError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("download timed out: %v", e.Cause)
	}
	return ErrTimeout.Error()
}

func (e *TimeoutError) Unwrap() error { return e.Cause }

func (e *TimeoutError) Is(target error) bool { return target == ErrTimeout }

// SizeLimitExceededError 表示下载大小超过允许上限。
type SizeLimitExceededError struct {
	Limit  int64
	Actual int64
}

func (e *SizeLimitExceededError) Error() string {
	return fmt.Sprintf("download size %d exceeds limit %d", e.Actual, e.Limit)
}

func (e *SizeLimitExceededError) Is(target error) bool { return target == ErrSizeLimitExceeded }

// RetriesExhaustedError 表示瞬态失败或资源重置已耗尽重试预算。
type RetriesExhaustedError struct {
	Attempts int
	Cause    error
}

func (e *RetriesExhaustedError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("download failed after %d attempts: %v", e.Attempts, e.Cause)
	}
	return fmt.Sprintf("download failed after %d attempts", e.Attempts)
}

func (e *RetriesExhaustedError) Unwrap() error { return e.Cause }

// FileIOError 表示本地文件读写、截断、同步或重命名错误。
type FileIOError struct {
	Op    string
	Cause error
}

func (e *FileIOError) Error() string {
	if e.Op != "" && e.Cause != nil {
		return fmt.Sprintf("file %s failed: %v", e.Op, e.Cause)
	}
	if e.Cause != nil {
		return fmt.Sprintf("file i/o failed: %v", e.Cause)
	}
	return ErrFileIO.Error()
}

func (e *FileIOError) Unwrap() error { return e.Cause }

func (e *FileIOError) Is(target error) bool { return target == ErrFileIO }

// Progress 描述单次进度回调的结构化状态。
type Progress struct {
	BytesReceived int64
	TotalBytes    int64
	IsReset       bool
}

// Result 描述下载成功后的结果摘要。
type Result struct {
	FinalURL      string
	BytesWritten  int64
	TotalBytes    int64
	AttemptsUsed  int
	UsedSegmented bool
}

// Config 定义弹性下载器的核心可配置项；零值默认强制 HTTPS 并套用生产默认参数。
type Config struct {
	ExpectedSizeHint        int64
	MaxBytes                int64
	AllowInsecureHTTP       bool
	MaxRedirects            int
	MaxConnections          int
	ChunkSize               int64
	MinSegmentedSize        int64
	MaxAttempts             int
	MaxFullResets           int
	RetryDelay              time.Duration
	SingleStreamIdleTimeout time.Duration
	ChunkStallTimeout       time.Duration
	TotalTimeout            time.Duration
	UserAgent               string
	BaseClient              *http.Client
	OnProgress              func(Progress)

	// 内部启发式调优参数，仅在包内测试或默认归一化时使用。
	warmupGrace             time.Duration
	rateWindow              time.Duration
	refHighSpeedWindow      time.Duration
	relativeSlowDuration    time.Duration
	slotRotateCooldown      time.Duration
	globalRotateCooldown    time.Duration
	scoutTriggerDuration    time.Duration
	scoutCooldown           time.Duration
	maxScouts               int
	watchdogInterval        time.Duration
	maxRetryAfter           time.Duration
	maxConcurrentHedges     int
	maxRotationsPerDownload int
	progressMinInterval     time.Duration
}

// DefaultConfig 返回带生产默认值的安全配置（默认强制 HTTPS）。
func DefaultConfig() Config {
	return (Config{}).normalized()
}

// RequireHTTPS 返回当前配置是否强制要求 HTTPS。
func (c Config) RequireHTTPS() bool {
	return !c.AllowInsecureHTTP
}

func (c Config) normalized() Config {
	if c.MaxBytes <= 0 {
		c.MaxBytes = DefaultMaxBytes
	}
	if c.MaxRedirects <= 0 {
		c.MaxRedirects = DefaultMaxRedirects
	}
	if c.MaxConnections <= 0 {
		c.MaxConnections = DefaultMaxConnections
	}
	if c.ChunkSize <= 0 {
		c.ChunkSize = DefaultChunkSize
	}
	if c.MinSegmentedSize <= 0 {
		c.MinSegmentedSize = DefaultMinSegmentedSize
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = DefaultMaxAttempts
	}
	if c.MaxFullResets <= 0 {
		c.MaxFullResets = DefaultMaxFullResets
	}
	if c.RetryDelay <= 0 {
		c.RetryDelay = DefaultRetryDelay
	}
	if c.SingleStreamIdleTimeout <= 0 {
		c.SingleStreamIdleTimeout = DefaultSingleStreamIdleTimeout
	}
	if c.ChunkStallTimeout <= 0 {
		c.ChunkStallTimeout = DefaultChunkStallTimeout
	}
	if c.TotalTimeout <= 0 {
		c.TotalTimeout = DefaultTotalTimeout
	}
	if c.warmupGrace <= 0 {
		c.warmupGrace = defaultWarmupGrace
	}
	if c.rateWindow <= 0 {
		c.rateWindow = defaultRateWindow
	}
	if c.refHighSpeedWindow <= 0 {
		c.refHighSpeedWindow = defaultRefHighSpeedWindow
	}
	if c.relativeSlowDuration <= 0 {
		c.relativeSlowDuration = defaultRelativeSlowDuration
	}
	if c.slotRotateCooldown <= 0 {
		c.slotRotateCooldown = defaultSlotRotateCooldown
	}
	if c.globalRotateCooldown <= 0 {
		c.globalRotateCooldown = defaultGlobalRotateCooldown
	}
	if c.scoutTriggerDuration <= 0 {
		c.scoutTriggerDuration = defaultScoutTriggerDuration
	}
	if c.scoutCooldown <= 0 {
		c.scoutCooldown = defaultScoutCooldown
	}
	if c.maxScouts <= 0 {
		c.maxScouts = defaultMaxScouts
	}
	if c.watchdogInterval <= 0 {
		c.watchdogInterval = defaultWatchdogInterval
	}
	if c.maxRetryAfter <= 0 {
		c.maxRetryAfter = defaultMaxRetryAfter
	}
	if c.maxConcurrentHedges <= 0 {
		c.maxConcurrentHedges = defaultMaxConcurrentHedges
	}
	if c.maxRotationsPerDownload <= 0 {
		c.maxRotationsPerDownload = defaultMaxRotationsPerDownload
	}
	if c.progressMinInterval == 0 {
		c.progressMinInterval = defaultProgressMinInterval
	}
	return c
}

func (c Config) effectiveChunkStallTimeout() time.Duration {
	return min(c.SingleStreamIdleTimeout, c.ChunkStallTimeout)
}
