package laneshunt

import (
	"context"
	"errors"
	"io"
	"slices"
	"sync"
	"time"
)

type chunkState int

const (
	chunkQueued chunkState = iota
	chunkInFlight
	chunkCommitted
)

type claimKind int

const (
	claimDone claimKind = iota
	claimWork
	claimWait
	claimWaitBackoff
)

type attemptOutcome int

const (
	outcomeCompleted attemptOutcome = iota
	outcomeTruncated
	outcomeRotated
	outcomeBenignCancel
	outcomeRateLimited
	outcomeTransientError
)

type chunkAttempt struct {
	id        uint64
	slotID    int
	hedge     bool
	startedAt time.Time
	cancel    context.CancelFunc
}

type chunkRecord struct {
	index           int
	end             int64
	committedOffset int64
	state           chunkState
	retries         int
	notBefore       time.Time
	attempts        []*chunkAttempt
	// commitMu 串行化同一分块在对冲并发下的 WriteAt 与 committedOffset 推进，保证先到者胜出且无重叠写盘。
	commitMu sync.Mutex
}

type claimResult struct {
	kind       claimKind
	chunkIndex int
	reqStart   int64
	reqEnd     int64
	attemptID  uint64
	isHedge    bool
	waitCh     <-chan struct{}
	waitUntil  time.Time
}

type commitResult struct {
	bytesAdded    int64
	progressBytes int64
	chunkDone     bool
	lostRace      bool
	loserCancels  []context.CancelFunc
}

const defaultMaxChunkRetries = 4

// chunkLedger 集中管理不可变微切片的领取、尾块对冲、唯一字节提交、重试预算与限流退避状态。
// 锁序不变量：严禁在持有 ledger.mu 时申请 chunk.commitMu；commitBytes 仅按 commitMu -> ledger.mu 顺序加锁。
type chunkLedger struct {
	mu                        sync.Mutex
	chunks                    []*chunkRecord
	nextChunk                 int
	requeued                  []int
	inFlight                  map[int]struct{}
	totalSize                 int64
	committedBytes            int64
	completedChunks           int
	targetConcurrency         int
	activeWorkers             int
	maxConcurrentHedges       int
	activeHedges              int
	nextAttemptID             uint64
	benignCancels             map[uint64]struct{}
	retryNotBefore            time.Time
	lastBackoffEpochEnd       time.Time
	retryDelay                time.Duration
	maxRetryAfter             time.Duration
	totalTransientFailures    int
	maxChunkRetries           int
	maxTotalTransientFailures int
	aborted                   bool
	abortErr                  error
	notifyCh                  chan struct{}
}

func newChunkLedger(totalSize, chunkSize int64, maxConnections, maxConcurrentHedges int, retryDelay, maxRetryAfter time.Duration) *chunkLedger {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	if maxConnections <= 0 {
		maxConnections = DefaultMaxConnections
	}
	if maxConcurrentHedges <= 0 {
		maxConcurrentHedges = defaultMaxConcurrentHedges
	}

	var chunks []*chunkRecord
	if totalSize > 0 {
		count := int((totalSize + chunkSize - 1) / chunkSize)
		chunks = make([]*chunkRecord, 0, count)
		for idx := 0; idx < count; idx++ {
			start := int64(idx) * chunkSize
			end := min(start+chunkSize-1, totalSize-1)
			chunks = append(chunks, &chunkRecord{
				index:           idx,
				end:             end,
				committedOffset: start,
				state:           chunkQueued,
			})
		}
	}

	maxTotalFailures := max(len(chunks)*2, 12)

	return &chunkLedger{
		chunks:                    chunks,
		inFlight:                  make(map[int]struct{}, maxConnections),
		totalSize:                 totalSize,
		targetConcurrency:         maxConnections,
		maxConcurrentHedges:       maxConcurrentHedges,
		benignCancels:             make(map[uint64]struct{}),
		retryDelay:                retryDelay,
		maxRetryAfter:             maxRetryAfter,
		maxChunkRetries:           defaultMaxChunkRetries,
		maxTotalTransientFailures: maxTotalFailures,
		notifyCh:                  make(chan struct{}),
	}
}

func (l *chunkLedger) chunkCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.chunks)
}

func (l *chunkLedger) targetConcurrencyValue() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.targetConcurrency
}

func (l *chunkLedger) isComplete() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return !l.aborted && l.completedChunks == len(l.chunks) && l.committedBytes == l.totalSize
}

func (l *chunkLedger) err() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.abortErr
}

func (l *chunkLedger) broadcastLocked() {
	close(l.notifyCh)
	l.notifyCh = make(chan struct{})
}

func (l *chunkLedger) nextIDLocked() uint64 {
	l.nextAttemptID++
	return l.nextAttemptID
}

// claim 为空闲槽位分配下一个待下载微切片，队列排空后在配额内为落后块分配尾块对冲任务。
func (l *chunkLedger) claim(slotID int, canHedge func() bool, now time.Time, rateOfSlot func(int) float64) claimResult {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.aborted || l.completedChunks == len(l.chunks) {
		return claimResult{kind: claimDone}
	}
	if now.Before(l.retryNotBefore) {
		return claimResult{
			kind:      claimWaitBackoff,
			waitUntil: l.retryNotBefore,
			waitCh:    l.notifyCh,
		}
	}
	if l.activeWorkers >= l.targetConcurrency {
		return claimResult{
			kind:   claimWait,
			waitCh: l.notifyCh,
		}
	}

	var earliestNotBefore time.Time

	// 优先领取已到期的重入队分块，未到期的延迟分块保留在队列中且不阻塞其他待领分块
	for i := len(l.requeued) - 1; i >= 0; i-- {
		idx := l.requeued[i]
		ch := l.chunks[idx]
		if ch.state != chunkQueued || ch.committedOffset > ch.end {
			l.requeued = slices.Delete(l.requeued, i, i+1)
			continue
		}
		if !ch.notBefore.IsZero() && now.Before(ch.notBefore) {
			if earliestNotBefore.IsZero() || ch.notBefore.Before(earliestNotBefore) {
				earliestNotBefore = ch.notBefore
			}
			continue
		}
		l.requeued = slices.Delete(l.requeued, i, i+1)
		ch.notBefore = time.Time{}
		attemptID := l.nextIDLocked()
		ch.state = chunkInFlight
		l.inFlight[idx] = struct{}{}
		ch.attempts = append(ch.attempts, &chunkAttempt{
			id:        attemptID,
			slotID:    slotID,
			hedge:     false,
			startedAt: now,
		})
		l.activeWorkers++
		return claimResult{
			kind:       claimWork,
			chunkIndex: idx,
			reqStart:   ch.committedOffset,
			reqEnd:     ch.end,
			attemptID:  attemptID,
			isHedge:    false,
		}
	}

	for l.nextChunk < len(l.chunks) {
		idx := l.nextChunk
		l.nextChunk++
		ch := l.chunks[idx]
		if ch.state != chunkQueued || ch.committedOffset > ch.end {
			continue
		}
		attemptID := l.nextIDLocked()
		ch.state = chunkInFlight
		l.inFlight[idx] = struct{}{}
		ch.attempts = append(ch.attempts, &chunkAttempt{
			id:        attemptID,
			slotID:    slotID,
			hedge:     false,
			startedAt: now,
		})
		l.activeWorkers++
		return claimResult{
			kind:       claimWork,
			chunkIndex: idx,
			reqStart:   ch.committedOffset,
			reqEnd:     ch.end,
			attemptID:  attemptID,
			isHedge:    false,
		}
	}

	if l.activeHedges < l.maxConcurrentHedges && len(l.inFlight) > 0 && canHedge != nil && canHedge() {
		var best *chunkRecord
		var bestRate float64
		var bestRemaining int64
		var bestStarted time.Time

		for idx := range l.inFlight {
			ch := l.chunks[idx]
			if ch.state != chunkInFlight || len(ch.attempts) != 1 || ch.committedOffset > ch.end {
				continue
			}
			primary := ch.attempts[0]
			if primary.slotID == slotID {
				continue
			}
			rem := ch.end - ch.committedOffset + 1
			var rate float64
			if rateOfSlot != nil {
				rate = rateOfSlot(primary.slotID)
			}
			if best == nil ||
				rate < bestRate ||
				(rate == bestRate && rem > bestRemaining) ||
				(rate == bestRate && rem == bestRemaining && primary.startedAt.Before(bestStarted)) ||
				(rate == bestRate && rem == bestRemaining && primary.startedAt.Equal(bestStarted) && ch.index < best.index) {
				best = ch
				bestRate = rate
				bestRemaining = rem
				bestStarted = primary.startedAt
			}
		}

		if best != nil {
			attemptID := l.nextIDLocked()
			best.attempts = append(best.attempts, &chunkAttempt{
				id:        attemptID,
				slotID:    slotID,
				hedge:     true,
				startedAt: now,
			})
			l.activeHedges++
			l.activeWorkers++
			return claimResult{
				kind:       claimWork,
				chunkIndex: best.index,
				reqStart:   best.committedOffset,
				reqEnd:     best.end,
				attemptID:  attemptID,
				isHedge:    true,
			}
		}
	}

	if !earliestNotBefore.IsZero() {
		return claimResult{
			kind:      claimWaitBackoff,
			waitUntil: earliestNotBefore,
			waitCh:    l.notifyCh,
		}
	}

	return claimResult{
		kind:   claimWait,
		waitCh: l.notifyCh,
	}
}

// registerAttemptCancel 绑定某次分片尝试的取消函数，便于对冲胜出者良性取消落败流。
func (l *chunkLedger) registerAttemptCancel(chunkIndex int, attemptID uint64, cancel context.CancelFunc) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if chunkIndex < 0 || chunkIndex >= len(l.chunks) {
		return
	}
	ch := l.chunks[chunkIndex]
	for _, a := range ch.attempts {
		if a.id == attemptID {
			a.cancel = cancel
			if _, alreadyBenign := l.benignCancels[attemptID]; alreadyBenign && cancel != nil {
				go cancel()
			}
			return
		}
	}
}

func (l *chunkLedger) isBenignCancel(attemptID uint64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.benignCancels[attemptID]
	return ok
}

// commitBytes 以分块级串行门控写入严格超出 committedOffset 的唯一新增字节，并更新全局进度。
func (l *chunkLedger) commitBytes(chunkIndex int, attemptID uint64, writer io.WriterAt, writeStart int64, data []byte) (commitResult, error) {
	if len(data) == 0 {
		return commitResult{}, nil
	}
	ch := l.chunks[chunkIndex]
	ch.commitMu.Lock()
	defer ch.commitMu.Unlock()

	l.mu.Lock()
	if l.aborted || ch.state == chunkCommitted {
		l.mu.Unlock()
		return commitResult{lostRace: true}, nil
	}
	cur := ch.committedOffset
	endExclusive := ch.end + 1
	l.mu.Unlock()

	if writeStart > cur {
		return commitResult{}, &FileIOError{
			Op:    "write",
			Cause: errors.New("non-contiguous chunk write offset"),
		}
	}
	dataEnd := writeStart + int64(len(data))
	if dataEnd <= cur {
		return commitResult{}, nil
	}
	sliceStart := cur - writeStart
	sliceEnd := min(int64(len(data)), endExclusive-writeStart)
	toWrite := data[sliceStart:sliceEnd]
	if len(toWrite) == 0 {
		return commitResult{}, nil
	}

	n, err := writer.WriteAt(toWrite, cur)
	if err != nil || n != len(toWrite) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return commitResult{}, &FileIOError{Op: "write", Cause: err}
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.aborted {
		return commitResult{lostRace: true}, nil
	}
	ch.committedOffset = cur + int64(n)
	l.committedBytes += int64(n)
	res := commitResult{
		bytesAdded:    int64(n),
		progressBytes: l.committedBytes,
	}
	if ch.committedOffset > ch.end && ch.state != chunkCommitted {
		ch.state = chunkCommitted
		delete(l.inFlight, chunkIndex)
		l.completedChunks++
		res.chunkDone = true
		for _, a := range ch.attempts {
			if a.id == attemptID {
				continue
			}
			l.benignCancels[a.id] = struct{}{}
			if a.cancel != nil {
				res.loserCancels = append(res.loserCancels, a.cancel)
			}
		}
		if l.completedChunks == len(l.chunks) {
			l.broadcastLocked()
		}
	}
	return res, nil
}

// transientBackoffDelayLocked 为非限流瞬态失败的分块计算带确定性有界抖动的指数退避时长。
func (l *chunkLedger) transientBackoffDelayLocked(chunkIndex, retries int) time.Duration {
	if l.retryDelay <= 0 || retries <= 0 {
		return 0
	}
	base := min(l.retryDelay, 500*time.Millisecond)
	shift := min(retries-1, 4)
	delay := base << shift
	capDelay := 4 * time.Second
	if l.maxRetryAfter > 0 && l.maxRetryAfter < capDelay {
		capDelay = l.maxRetryAfter
	}
	if delay > capDelay {
		delay = capDelay
	}
	jitterPct := int64(85 + ((chunkIndex*17 + retries*13) % 31))
	jittered := (delay * time.Duration(jitterPct)) / 100
	if jittered > capDelay {
		jittered = capDelay
	}
	return jittered
}

// releaseAttempt 归还槽位占用并在分块未完成时按结果决定重新入队或终止下载。
func (l *chunkLedger) releaseAttempt(chunkIndex int, attemptID uint64, outcome attemptOutcome, cause error, bytesAdvanced int64, now time.Time) (abortedNow bool, allDone bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	ch := l.chunks[chunkIndex]
	for i, a := range ch.attempts {
		if a.id == attemptID {
			if a.hedge {
				l.activeHedges--
			}
			l.activeWorkers--
			ch.attempts = slices.Delete(ch.attempts, i, i+1)
			break
		}
	}

	_, wasBenign := l.benignCancels[attemptID]
	delete(l.benignCancels, attemptID)

	if l.aborted {
		l.broadcastLocked()
		return true, false
	}

	if ch.state == chunkCommitted || ch.committedOffset > ch.end {
		if ch.state != chunkCommitted {
			ch.state = chunkCommitted
			l.completedChunks++
		}
		delete(l.inFlight, chunkIndex)
		l.broadcastLocked()
		return false, l.completedChunks == len(l.chunks)
	}

	isTransientFailure := false
	switch {
	case wasBenign || outcome == outcomeBenignCancel || outcome == outcomeRotated:
	case outcome == outcomeTruncated && bytesAdvanced > 0:
		// 合法截短的 206 已推进有效偏移，不消耗瞬态失败预算
	default:
		isTransientFailure = true
		ch.retries++
		l.totalTransientFailures++
		if ch.retries > l.maxChunkRetries || l.totalTransientFailures > l.maxTotalTransientFailures {
			l.aborted = true
			l.abortErr = &RetriesExhaustedError{
				Attempts: ch.retries,
				Cause:    cause,
			}
			l.broadcastLocked()
			return true, false
		}
	}

	if len(ch.attempts) == 0 {
		delete(l.inFlight, chunkIndex)
		ch.state = chunkQueued
		if isTransientFailure && outcome != outcomeRateLimited {
			if delay := l.transientBackoffDelayLocked(chunkIndex, ch.retries); delay > 0 {
				ch.notBefore = now.Add(delay)
			} else {
				ch.notBefore = time.Time{}
			}
		} else {
			ch.notBefore = time.Time{}
		}
		l.requeued = append(l.requeued, chunkIndex)
	}

	l.broadcastLocked()
	return false, false
}

// applyRateLimitBackoff 响应 429/502/503/504：设置全局退避截止时间并将目标并发减半（每轮退避窗口仅减半一次）。
func (l *chunkLedger) applyRateLimitBackoff(now, until time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if until.After(l.retryNotBefore) {
		l.retryNotBefore = until
	}
	if !now.Before(l.lastBackoffEpochEnd) {
		l.targetConcurrency = max(l.targetConcurrency/2, 1)
		l.lastBackoffEpochEnd = l.retryNotBefore
	}
	l.broadcastLocked()
}

// shrinkConcurrency 将并发目标上限收缩至 target（仅减不增）。
func (l *chunkLedger) shrinkConcurrency(target int) {
	target = max(target, 1)
	l.mu.Lock()
	defer l.mu.Unlock()
	if target < l.targetConcurrency {
		l.targetConcurrency = target
		l.broadcastLocked()
	}
}

// abort 标记账本因不可恢复错误、资源漂移或外部取消而中止，并唤醒所有等待中的工作协程。
func (l *chunkLedger) abort(err error) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.aborted {
		return false
	}
	l.aborted = true
	l.abortErr = err
	l.broadcastLocked()
	return true
}
