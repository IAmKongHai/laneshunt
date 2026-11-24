package laneshunt

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

const (
	cancelReasonNone   int32 = 0
	cancelReasonRotate int32 = 1
	cancelReasonStall  int32 = 2
)

const (
	// 相对慢流轮换与有限侦察吞吐阈值（字节/秒）
	relativeRotationMinRefSpeed  = 64 * 1024
	relativeRotationMaxSlowSpeed = 512 * 1024
	scoutSuccessMinSpeed         = 80 * 1024
	narrowbandAggregateThreshold = 48 * 1024
	narrowbandShrunkConcurrency  = 2
)

type timedBytes struct {
	at    time.Time
	bytes int64
}

// slidingByteWindow 以均摊 O(1) 维护滑动时间窗内的字节累加和，避免高频读盘时反复搬移切片。
type slidingByteWindow struct {
	items    []timedBytes
	head     int
	sumBytes int64
}

func (w *slidingByteWindow) add(at time.Time, n int64) {
	w.items = append(w.items, timedBytes{at: at, bytes: n})
	w.sumBytes += n
}

func (w *slidingByteWindow) reset() {
	w.items = nil
	w.head = 0
	w.sumBytes = 0
}

func (w *slidingByteWindow) sumSince(cutoff time.Time) int64 {
	for w.head < len(w.items) && w.items[w.head].at.Before(cutoff) {
		w.sumBytes -= w.items[w.head].bytes
		w.head++
	}
	if w.head >= 64 && w.head*2 >= len(w.items) {
		w.items = slices.Delete(w.items, 0, w.head)
		w.head = 0
	}
	return w.sumBytes
}

func (w *slidingByteWindow) rate(now, origin time.Time, window time.Duration) float64 {
	sum := w.sumSince(now.Add(-window))
	dur := max(min(now.Sub(origin), window), 50*time.Millisecond)
	return float64(sum) / dur.Seconds()
}

type completedChunkSample struct {
	completedAt time.Time
	rate        float64
}

type slotMetrics struct {
	connCreatedAt     time.Time
	lastRotatedAt     time.Time
	inFlight          bool
	attemptID         uint64
	attemptStart      time.Time
	lastDataAt        time.Time
	attemptBytes      int64
	cancelFn          context.CancelFunc
	cancelReason      *atomic.Int32
	rotatePending     bool
	bytesWindow       slidingByteWindow
	slowSince         time.Time
	completedCount    int
	lastCompletedRate float64
}

// speedTracker 跟踪各槽位实时滑动速率、近期已完成分片的衰减高速参考基准、慢流轮换与聚合感知有限侦察状态。
type speedTracker struct {
	mu                    sync.Mutex
	cfg                   Config
	effectiveStall        time.Duration
	startedAt             time.Time
	slots                 []*slotMetrics
	tickRates             []float64
	globalWindow          slidingByteWindow
	completedChunks       []completedChunkSample
	lastGlobalRotateAt    time.Time
	totalRotations        int
	lowRefSince           time.Time
	scoutsUsed            int
	scoutingStopped       bool
	lastScoutAt           time.Time
	pendingScoutSlot      int
	pendingScoutBaseline  float64
	pendingScoutStartedAt time.Time
	pendingScoutPrevDone  int
}

func newSpeedTracker(cfg Config, numSlots int, now time.Time) *speedTracker {
	slots := make([]*slotMetrics, numSlots)
	for i := range slots {
		slots[i] = &slotMetrics{
			connCreatedAt: now,
		}
	}
	return &speedTracker{
		cfg:              cfg,
		effectiveStall:   cfg.effectiveChunkStallTimeout(),
		startedAt:        now,
		slots:            slots,
		tickRates:        make([]float64, numSlots),
		pendingScoutSlot: -1,
	}
}

func (t *speedTracker) startAttempt(slotID int, attemptID uint64, cancelFn context.CancelFunc, cancelReason *atomic.Int32, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.slots[slotID]
	s.inFlight = true
	s.attemptID = attemptID
	s.attemptStart = now
	s.lastDataAt = now
	s.attemptBytes = 0
	s.cancelFn = cancelFn
	s.cancelReason = cancelReason
}

func (t *speedTracker) endAttempt(slotID int, attemptID uint64, completed bool, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.slots[slotID]
	if s.attemptID != attemptID {
		return
	}
	if completed && s.attemptBytes > 0 {
		dur := max(now.Sub(s.attemptStart), time.Millisecond)
		rate := float64(s.attemptBytes) / dur.Seconds()
		s.completedCount++
		s.lastCompletedRate = rate
		t.completedChunks = append(t.completedChunks, completedChunkSample{
			completedAt: now,
			rate:        rate,
		})
	}
	s.inFlight = false
	s.cancelFn = nil
	s.cancelReason = nil
}

func (t *speedTracker) recordBytes(slotID int, n int64, now time.Time) {
	if n <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.slots[slotID]
	s.lastDataAt = now
	s.attemptBytes += n
	s.bytesWindow.add(now, n)
	t.globalWindow.add(now, n)
}

func (t *speedTracker) markConnectionRebuilt(slotID int, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.slots[slotID]
	s.connCreatedAt = now
	s.bytesWindow.reset()
	s.slowSince = time.Time{}
	s.rotatePending = false
}

func (t *speedTracker) consumeRotatePending(slotID int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.slots[slotID]
	if s.rotatePending {
		s.rotatePending = false
		return true
	}
	return false
}

func (t *speedTracker) slotRate(slotID int, now time.Time) float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.slotRateLocked(t.slots[slotID], now)
}

func (t *speedTracker) canSlotHedge(slotID int, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.slots[slotID]
	if s.completedCount == 0 {
		return false
	}
	ref := t.refHighSpeedLocked(now, nil)
	return s.lastCompletedRate >= relativeRotationMinRefSpeed && (ref <= 0 || s.lastCompletedRate >= ref*0.5)
}

func (t *speedTracker) slotRateLocked(s *slotMetrics, now time.Time) float64 {
	return s.bytesWindow.rate(now, s.connCreatedAt, t.cfg.rateWindow)
}

func (t *speedTracker) aggregateRateLocked(now time.Time) float64 {
	return t.globalWindow.rate(now, t.startedAt, t.cfg.rateWindow)
}

func (t *speedTracker) refHighSpeedLocked(now time.Time, cachedSlotRates []float64) float64 {
	cutoff := now.Add(-t.cfg.refHighSpeedWindow)
	t.completedChunks = slices.DeleteFunc(t.completedChunks, func(c completedChunkSample) bool {
		return c.completedAt.Before(cutoff)
	})

	winSec := t.cfg.refHighSpeedWindow.Seconds()
	if winSec <= 0 {
		winSec = defaultRefHighSpeedWindow.Seconds()
	}

	var top1, top2 float64
	count := 0
	consider := func(v float64) {
		count++
		if count == 1 || v > top1 {
			top2 = top1
			top1 = v
		} else if count == 2 || v > top2 {
			top2 = v
		}
	}

	for _, c := range t.completedChunks {
		age := max(now.Sub(c.completedAt).Seconds(), 0)
		decay := max(1.0-0.5*(age/winSec), 0.5)
		consider(c.rate * decay)
	}
	for i, s := range t.slots {
		if s.inFlight && now.Sub(s.connCreatedAt) >= t.cfg.warmupGrace {
			if cachedSlotRates != nil {
				consider(cachedSlotRates[i])
			} else {
				consider(t.slotRateLocked(s, now))
			}
		}
	}
	if count == 0 {
		return 0
	}
	if count < 4 {
		return top1
	}
	return (top1 + top2) / 2.0
}

type watchdogActions struct {
	cancels  []context.CancelFunc
	shrinkTo int
}

// evaluateTick 执行一次慢流看门狗巡检：检测零字节假死、相对慢流单槽轮换与聚合感知有限侦察。
func (t *speedTracker) evaluateTick(now time.Time) watchdogActions {
	t.mu.Lock()
	defer t.mu.Unlock()

	var actions watchdogActions
	t.scanStallsLocked(now, &actions)

	anyPastWarmup := false
	for i, s := range t.slots {
		if s.inFlight || i == t.pendingScoutSlot {
			t.tickRates[i] = t.slotRateLocked(s, now)
		} else {
			t.tickRates[i] = 0
		}
		if s.inFlight && now.Sub(s.connCreatedAt) >= t.cfg.warmupGrace {
			anyPastWarmup = true
		}
	}

	refHighSpeed := t.refHighSpeedLocked(now, t.tickRates)
	aggRate := t.aggregateRateLocked(now)

	if refHighSpeed >= relativeRotationMinRefSpeed {
		t.evaluateRelativeRotationLocked(now, refHighSpeed, &actions)
		return actions
	}
	if !anyPastWarmup {
		return actions
	}
	t.evaluateScoutLocked(now, aggRate, &actions)
	return actions
}

func (t *speedTracker) scanStallsLocked(now time.Time, actions *watchdogActions) {
	for _, s := range t.slots {
		if !s.inFlight || now.Sub(s.lastDataAt) < t.effectiveStall {
			continue
		}
		if s.cancelReason != nil && s.cancelReason.CompareAndSwap(cancelReasonNone, cancelReasonStall) {
			s.rotatePending = true
			if s.cancelFn != nil {
				actions.cancels = append(actions.cancels, s.cancelFn)
			}
		}
	}
}

func (t *speedTracker) isScoutSucceededLocked() bool {
	if t.pendingScoutSlot < 0 {
		return false
	}
	ps := t.slots[t.pendingScoutSlot]
	scoutRate := t.tickRates[t.pendingScoutSlot]
	if ps.completedCount > t.pendingScoutPrevDone && ps.lastCompletedRate > scoutRate {
		scoutRate = ps.lastCompletedRate
	}
	return scoutRate >= t.pendingScoutBaseline*2.0 && scoutRate >= scoutSuccessMinSpeed
}

func (t *speedTracker) stopScoutingAndMaybeShrinkLocked(aggRate float64, actions *watchdogActions) {
	t.scoutingStopped = true
	if aggRate < narrowbandAggregateThreshold {
		actions.shrinkTo = narrowbandShrunkConcurrency
	}
}

func (t *speedTracker) evaluateRelativeRotationLocked(now time.Time, refHighSpeed float64, actions *watchdogActions) {
	t.lowRefSince = time.Time{}
	if t.isScoutSucceededLocked() {
		t.pendingScoutSlot = -1
	}

	globalCooldownOK := t.lastGlobalRotateAt.IsZero() || now.Sub(t.lastGlobalRotateAt) >= t.cfg.globalRotateCooldown
	slowestIdx := -1
	var slowestRate float64
	for i, s := range t.slots {
		if !s.inFlight || now.Sub(s.connCreatedAt) < t.cfg.warmupGrace {
			continue
		}
		rate := t.tickRates[i]
		if rate >= refHighSpeed*0.25 || rate >= relativeRotationMaxSlowSpeed {
			s.slowSince = time.Time{}
			continue
		}
		if s.slowSince.IsZero() {
			s.slowSince = now
		}
		slotCooldownOK := s.lastRotatedAt.IsZero() || now.Sub(s.lastRotatedAt) >= t.cfg.slotRotateCooldown
		if globalCooldownOK && slotCooldownOK &&
			t.totalRotations < t.cfg.maxRotationsPerDownload &&
			now.Sub(s.slowSince) >= t.cfg.relativeSlowDuration {
			if slowestIdx < 0 || rate < slowestRate {
				slowestIdx = i
				slowestRate = rate
			}
		}
	}
	if slowestIdx < 0 {
		return
	}
	target := t.slots[slowestIdx]
	if target.cancelReason != nil && target.cancelReason.CompareAndSwap(cancelReasonNone, cancelReasonRotate) {
		target.rotatePending = true
		target.lastRotatedAt = now
		target.slowSince = time.Time{}
		t.lastGlobalRotateAt = now
		t.totalRotations++
		if target.cancelFn != nil {
			actions.cancels = append(actions.cancels, target.cancelFn)
		}
	}
}

func (t *speedTracker) evaluateScoutLocked(now time.Time, aggRate float64, actions *watchdogActions) {
	if t.pendingScoutSlot >= 0 {
		elapsed := now.Sub(t.pendingScoutStartedAt)
		evalMin := t.cfg.warmupGrace + t.cfg.rateWindow/2
		evalMax := t.cfg.warmupGrace + t.cfg.rateWindow
		if elapsed >= evalMin && t.isScoutSucceededLocked() {
			t.pendingScoutSlot = -1
			t.lowRefSince = time.Time{}
			return
		}
		if elapsed >= evalMax {
			t.pendingScoutSlot = -1
			if t.scoutsUsed >= t.cfg.maxScouts {
				t.stopScoutingAndMaybeShrinkLocked(aggRate, actions)
			}
		}
		return
	}

	if t.scoutingStopped {
		return
	}
	if t.lowRefSince.IsZero() {
		t.lowRefSince = now
		return
	}
	if now.Sub(t.lowRefSince) < t.cfg.scoutTriggerDuration {
		return
	}
	if t.scoutsUsed >= t.cfg.maxScouts || t.totalRotations >= t.cfg.maxRotationsPerDownload {
		t.stopScoutingAndMaybeShrinkLocked(aggRate, actions)
		return
	}
	if !t.lastScoutAt.IsZero() && now.Sub(t.lastScoutAt) < t.cfg.scoutCooldown {
		return
	}

	slowestIdx := -1
	var slowestRate float64
	for i, s := range t.slots {
		if !s.inFlight || now.Sub(s.connCreatedAt) < t.cfg.warmupGrace {
			continue
		}
		rate := t.tickRates[i]
		if slowestIdx < 0 || rate < slowestRate {
			slowestIdx = i
			slowestRate = rate
		}
	}
	if slowestIdx < 0 {
		return
	}
	target := t.slots[slowestIdx]
	if target.cancelReason != nil && target.cancelReason.CompareAndSwap(cancelReasonNone, cancelReasonRotate) {
		t.pendingScoutSlot = slowestIdx
		t.pendingScoutBaseline = max(slowestRate, 1)
		t.pendingScoutStartedAt = now
		t.pendingScoutPrevDone = target.completedCount
		t.lastScoutAt = now
		t.scoutsUsed++
		t.totalRotations++
		target.rotatePending = true
		target.lastRotatedAt = now
		target.slowSince = time.Time{}
		if target.cancelFn != nil {
			actions.cancels = append(actions.cancels, target.cancelFn)
		}
	}
}
