package laneshunt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type workerSlot struct {
	id         int
	httpClient *slotHTTPClient
}

// segmentedRun 封装单次分段下载的不可变共享上下文，供各 Worker 槽位协程方法直接访问。
type segmentedRun struct {
	d              *Downloader
	parentCtx      context.Context
	totalCtx       context.Context
	segCtx         context.Context
	segCancel      context.CancelFunc
	lockedURL      string
	lockedTotal    int64
	lockedVal      lockedValidator
	file           *os.File
	ledger         *chunkLedger
	tracker        *speedTracker
	emitter        *progressEmitter
	effectiveStall time.Duration
}

// downloadSegmented 执行多连接并发分段下载，严守「先全部取消并等待退出 → 验尺寸/Sync → 关句柄 → 重命名或删临时文件 → 关连接池」退出顺序。
func (d *Downloader) downloadSegmented(
	parentCtx, totalCtx context.Context,
	lockedURL string,
	lockedTotal int64,
	lockedVal lockedValidator,
	cleanDest, parentDir string,
	emitter *progressEmitter,
) error {
	if lockedTotal <= 0 || lockedTotal > d.cfg.MaxBytes {
		return &SizeLimitExceededError{Limit: d.cfg.MaxBytes, Actual: lockedTotal}
	}

	f, err := createTempFile(parentDir)
	if err != nil {
		return err
	}
	tempPath := f.Name()

	if truncErr := f.Truncate(lockedTotal); truncErr != nil {
		cleanupTempFile(&f, tempPath)
		return &FileIOError{Op: "truncate", Cause: truncErr}
	}

	numSlots := d.cfg.MaxConnections
	ledger := newChunkLedger(lockedTotal, d.cfg.ChunkSize, numSlots, d.cfg.maxConcurrentHedges, d.cfg.RetryDelay, d.cfg.maxRetryAfter)
	if ledger.chunkCount() < numSlots && ledger.chunkCount() > 0 {
		numSlots = ledger.chunkCount()
	}
	tracker := newSpeedTracker(d.cfg, numSlots, time.Now())
	effectiveStall := d.cfg.effectiveChunkStallTimeout()

	slots := make([]*workerSlot, numSlots)
	for i := 0; i < numSlots; i++ {
		slots[i] = &workerSlot{
			id: i,
			httpClient: newIsolatedHTTP1Client(
				d.cfg.BaseClient,
				d.cfg.RequireHTTPS(),
				d.cfg.MaxRedirects,
				effectiveStall,
				nil,
			),
		}
	}

	segCtx, segCancel := context.WithCancel(totalCtx)
	closeAllSlots := func() {
		for _, s := range slots {
			if s != nil && s.httpClient != nil {
				s.httpClient.closeIdle()
			}
		}
	}

	var watchWg sync.WaitGroup
	watchWg.Add(1)
	go func() {
		defer watchWg.Done()
		interval := max(min(d.cfg.watchdogInterval, effectiveStall/4), 20*time.Millisecond)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-segCtx.Done():
				return
			case tickNow := <-ticker.C:
				actions := tracker.evaluateTick(tickNow)
				for _, cancelFn := range actions.cancels {
					cancelFn()
				}
				if actions.shrinkTo > 0 {
					ledger.shrinkConcurrency(actions.shrinkTo)
				}
			}
		}
	}()

	run := &segmentedRun{
		d:              d,
		parentCtx:      parentCtx,
		totalCtx:       totalCtx,
		segCtx:         segCtx,
		segCancel:      segCancel,
		lockedURL:      lockedURL,
		lockedTotal:    lockedTotal,
		lockedVal:      lockedVal,
		file:           f,
		ledger:         ledger,
		tracker:        tracker,
		emitter:        emitter,
		effectiveStall: effectiveStall,
	}

	var workerWg sync.WaitGroup
	for _, slot := range slots {
		workerWg.Add(1)
		go func(ws *workerSlot) {
			defer workerWg.Done()
			run.runWorkerSlot(ws)
		}(slot)
	}

	workerWg.Wait()
	segCancel()
	watchWg.Wait()

	if ledger.isComplete() && parentCtx.Err() == nil {
		finErr := finalizeTempFile(f, tempPath, cleanDest, lockedTotal)
		closeAllSlots()
		if finErr != nil {
			return finErr
		}
		emitter.report(lockedTotal, lockedTotal)
		return nil
	}

	cleanupTempFile(&f, tempPath)
	closeAllSlots()

	if parentCtx.Err() != nil {
		return classifyParentOrTotalErr(parentCtx, totalCtx, parentCtx.Err())
	}
	if err := ledger.err(); err != nil {
		return err
	}
	if totalCtx.Err() != nil {
		return &TimeoutError{Cause: totalCtx.Err()}
	}
	return &RetriesExhaustedError{Attempts: 1, Cause: errors.New("segmented download did not complete")}
}

func (r *segmentedRun) rebuildSlotTransport(ws *workerSlot) {
	ws.httpClient.closeIdle()
	ws.httpClient = newIsolatedHTTP1Client(
		r.d.cfg.BaseClient,
		r.d.cfg.RequireHTTPS(),
		r.d.cfg.MaxRedirects,
		r.effectiveStall,
		nil,
	)
	r.tracker.markConnectionRebuilt(ws.id, time.Now())
}

func (r *segmentedRun) abortAttempt(
	ws *workerSlot,
	claim claimResult,
	reqCancel context.CancelFunc,
	resp *http.Response,
	abortErr error,
	bytesAdvanced int64,
) {
	reqCancel()
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	now := time.Now()
	r.tracker.endAttempt(ws.id, claim.attemptID, false, now)
	r.ledger.abort(abortErr)
	r.segCancel()
	_, _ = r.ledger.releaseAttempt(claim.chunkIndex, claim.attemptID, outcomeBenignCancel, abortErr, bytesAdvanced, now)
}

func (r *segmentedRun) handleAttemptError(
	ws *workerSlot,
	claim claimResult,
	reqCancel context.CancelFunc,
	resp *http.Response,
	cancelReason *atomic.Int32,
	lostRace bool,
	cause error,
	bytesAdvanced int64,
) bool {
	// 严格轮换序：先 reqCancel -> Body.Close -> CloseIdleConnections（在 rebuildSlotTransport 中）-> 换新 Transport
	reqCancel()
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	reason := cancelReason.Load()
	now := time.Now()
	r.tracker.endAttempt(ws.id, claim.attemptID, false, now)

	if r.parentCtx.Err() != nil {
		r.ledger.abort(classifyParentOrTotalErr(r.parentCtx, r.totalCtx, cause))
		r.segCancel()
		_, _ = r.ledger.releaseAttempt(claim.chunkIndex, claim.attemptID, outcomeBenignCancel, cause, bytesAdvanced, now)
		return true
	}
	if redirErr := extractRedirectError(cause); redirErr != nil {
		r.ledger.abort(redirErr)
		r.segCancel()
		_, _ = r.ledger.releaseAttempt(claim.chunkIndex, claim.attemptID, outcomeBenignCancel, redirErr, bytesAdvanced, now)
		return true
	}
	if isPermanentTLSError(cause) {
		r.ledger.abort(cause)
		r.segCancel()
		_, _ = r.ledger.releaseAttempt(claim.chunkIndex, claim.attemptID, outcomeBenignCancel, cause, bytesAdvanced, now)
		return true
	}
	if lostRace || r.ledger.isBenignCancel(claim.attemptID) {
		r.rebuildSlotTransport(ws)
		_, allDone := r.ledger.releaseAttempt(claim.chunkIndex, claim.attemptID, outcomeBenignCancel, nil, bytesAdvanced, now)
		if allDone {
			r.segCancel()
			return true
		}
		return false
	}
	if r.totalCtx.Err() != nil {
		r.ledger.abort(&TimeoutError{Cause: r.totalCtx.Err()})
		r.segCancel()
		_, _ = r.ledger.releaseAttempt(claim.chunkIndex, claim.attemptID, outcomeBenignCancel, r.totalCtx.Err(), bytesAdvanced, now)
		return true
	}
	if reason == cancelReasonStall {
		r.rebuildSlotTransport(ws)
		causeErr := cause
		if causeErr == nil {
			causeErr = ErrTimeout
		}
		var te *TimeoutError
		if !errors.As(causeErr, &te) {
			causeErr = &TimeoutError{Cause: causeErr}
		}
		aborted, _ := r.ledger.releaseAttempt(claim.chunkIndex, claim.attemptID, outcomeTransientError, causeErr, bytesAdvanced, now)
		if aborted {
			r.segCancel()
			return true
		}
		return false
	}
	if reason == cancelReasonRotate {
		r.rebuildSlotTransport(ws)
		_, _ = r.ledger.releaseAttempt(claim.chunkIndex, claim.attemptID, outcomeRotated, nil, bytesAdvanced, now)
		return false
	}

	causeErr := cause
	if causeErr == nil {
		causeErr = io.ErrUnexpectedEOF
	} else {
		causeErr = wrapIfTimeout(causeErr)
	}
	r.rebuildSlotTransport(ws)
	aborted, _ := r.ledger.releaseAttempt(claim.chunkIndex, claim.attemptID, outcomeTransientError, causeErr, bytesAdvanced, now)
	if aborted {
		r.segCancel()
		return true
	}
	return false
}

func (r *segmentedRun) runWorkerSlot(ws *workerSlot) {
	buf := make([]byte, ioBufferSize)

	for {
		if r.segCtx.Err() != nil {
			return
		}

		now := time.Now()
		claim := r.ledger.claim(
			ws.id,
			func() bool { return r.tracker.canSlotHedge(ws.id, now) },
			now,
			func(otherSlot int) float64 { return r.tracker.slotRate(otherSlot, now) },
		)

		switch claim.kind {
		case claimDone:
			r.segCancel()
			return
		case claimWaitBackoff:
			delay := time.Until(claim.waitUntil)
			if delay <= 0 {
				continue
			}
			timer := time.NewTimer(delay)
			select {
			case <-r.segCtx.Done():
				timer.Stop()
				return
			case <-claim.waitCh:
				timer.Stop()
			case <-timer.C:
			}
			continue
		case claimWait:
			select {
			case <-r.segCtx.Done():
				return
			case <-claim.waitCh:
			}
			continue
		case claimWork:
		}

		if r.tracker.consumeRotatePending(ws.id) {
			r.rebuildSlotTransport(ws)
		}

		reqCtx, reqCancel := context.WithCancel(r.segCtx)
		var cancelReason atomic.Int32
		r.ledger.registerAttemptCancel(claim.chunkIndex, claim.attemptID, reqCancel)
		r.tracker.startAttempt(ws.id, claim.attemptID, reqCancel, &cancelReason, time.Now())

		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, r.lockedURL, nil)
		if err != nil {
			r.abortAttempt(ws, claim, reqCancel, nil, err, 0)
			return
		}
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", claim.reqStart, claim.reqEnd))
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("If-Range", r.lockedVal.value)
		if r.d.cfg.UserAgent != "" {
			req.Header.Set("User-Agent", r.d.cfg.UserAgent)
		}

		resp, doErr := ws.httpClient.client.Do(req)
		if doErr != nil {
			if r.handleAttemptError(ws, claim, reqCancel, nil, &cancelReason, false, doErr, 0) {
				return
			}
			continue
		}

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusRequestedRangeNotSatisfiable {
			r.abortAttempt(ws, claim, reqCancel, resp, &driftResetError{cause: &HTTPStatusError{StatusCode: resp.StatusCode}}, 0)
			return
		}

		if isRateLimitOrGatewayStatus(resp.StatusCode) {
			code := resp.StatusCode
			waitDelay := retryDelayForStatus(resp, r.d.cfg)
			reqCancel()
			_ = resp.Body.Close()
			nowBackoff := time.Now()
			r.tracker.endAttempt(ws.id, claim.attemptID, false, nowBackoff)
			r.ledger.applyRateLimitBackoff(nowBackoff, nowBackoff.Add(waitDelay))
			aborted, _ := r.ledger.releaseAttempt(claim.chunkIndex, claim.attemptID, outcomeRateLimited, &HTTPStatusError{StatusCode: code}, 0, nowBackoff)
			if aborted {
				r.segCancel()
				return
			}
			continue
		}

		if isRetryableServerStatus(resp.StatusCode) {
			code := resp.StatusCode
			reqCancel()
			_ = resp.Body.Close()
			nowRetry := time.Now()
			r.tracker.endAttempt(ws.id, claim.attemptID, false, nowRetry)
			r.rebuildSlotTransport(ws)
			aborted, _ := r.ledger.releaseAttempt(claim.chunkIndex, claim.attemptID, outcomeTransientError, &HTTPStatusError{StatusCode: code}, 0, nowRetry)
			if aborted {
				r.segCancel()
				return
			}
			continue
		}

		if resp.StatusCode != http.StatusPartialContent {
			r.abortAttempt(ws, claim, reqCancel, resp, &HTTPStatusError{StatusCode: resp.StatusCode}, 0)
			return
		}

		// 逐片 206 协议强校验：编码与类型、Content-Range 边界与总长、锁定强校验器一致
		cr, crOK := parseContentRange(resp.Header.Get("Content-Range"))
		if crOK && !cr.isUnsatisfied && cr.hasTotal && cr.total > r.d.cfg.MaxBytes {
			r.abortAttempt(ws, claim, reqCancel, resp, &SizeLimitExceededError{Limit: r.d.cfg.MaxBytes, Actual: cr.total}, 0)
			return
		}
		if !isIdentityContentEncoding(resp.Header) {
			r.abortAttempt(ws, claim, reqCancel, resp, &driftResetError{cause: errors.New("unexpected non-identity Content-Encoding on 206 chunk")}, 0)
			return
		}
		if isMultipartByteranges(resp.Header) {
			r.abortAttempt(ws, claim, reqCancel, resp, &driftResetError{cause: errors.New("multipart/byteranges not supported on 206 chunk")}, 0)
			return
		}
		if !crOK || cr.isUnsatisfied || !cr.hasTotal || cr.total != r.lockedTotal || cr.start != claim.reqStart || cr.end < cr.start || cr.end > claim.reqEnd {
			r.abortAttempt(ws, claim, reqCancel, resp, &driftResetError{
				cause: fmt.Errorf("mismatched Content-Range %q for request bytes=%d-%d/%d", resp.Header.Get("Content-Range"), claim.reqStart, claim.reqEnd, r.lockedTotal),
			}, 0)
			return
		}
		if !r.lockedVal.matchesResponse(resp.Header) {
			r.abortAttempt(ws, claim, reqCancel, resp, &driftResetError{cause: errors.New("strong validator changed or missing on 206 chunk")}, 0)
			return
		}

		expectedSegmentLen := cr.end - cr.start + 1
		limitedBody := io.LimitReader(resp.Body, expectedSegmentLen+1)

		var (
			streamOffset  int64
			bytesAdvanced int64
			readErr       error
			chunkFinished bool
			lostRace      bool
			fatalErr      error
		)

		for {
			n, rErr := limitedBody.Read(buf)
			if n > 0 {
				if streamOffset+int64(n) > expectedSegmentLen {
					fatalErr = &SizeLimitExceededError{
						Limit:  expectedSegmentLen,
						Actual: streamOffset + int64(n),
					}
					break
				}
				r.tracker.recordBytes(ws.id, int64(n), time.Now())

				writePos := claim.reqStart + streamOffset
				commitRes, cErr := r.ledger.commitBytes(claim.chunkIndex, claim.attemptID, r.file, writePos, buf[:n])
				if cErr != nil {
					fatalErr = cErr
					break
				}
				streamOffset += int64(n)
				bytesAdvanced += commitRes.bytesAdded
				if commitRes.bytesAdded > 0 {
					r.emitter.report(commitRes.progressBytes, r.lockedTotal)
				}
				for _, loserFn := range commitRes.loserCancels {
					loserFn()
				}
				if commitRes.chunkDone {
					chunkFinished = true
					// 正常完成时再探测 1 字节：既校验服务端未超发字节，又使底层 HTTP/1.1 响应体抵达 io.EOF 以便 Keep-Alive 复用
					var probeExtra [1]byte
					extraN, extraErr := limitedBody.Read(probeExtra[:])
					if extraN > 0 {
						fatalErr = &SizeLimitExceededError{
							Limit:  expectedSegmentLen,
							Actual: streamOffset + int64(extraN),
						}
					} else if extraErr != nil && extraErr != io.EOF {
						readErr = extraErr
					}
					break
				}
				if commitRes.lostRace {
					lostRace = true
					break
				}
			}
			if rErr == io.EOF {
				break
			}
			if rErr != nil {
				readErr = rErr
				break
			}
		}

		if fatalErr != nil {
			r.abortAttempt(ws, claim, reqCancel, resp, fatalErr, bytesAdvanced)
			return
		}

		if readErr == nil && !lostRace && (chunkFinished || streamOffset == expectedSegmentLen) {
			// 注意：只有在没有轮换请求时才先关闭响应体再取消 ctx，以保留健康 HTTP/1.1 Keep-Alive 连接复用
			needRotate := r.tracker.consumeRotatePending(ws.id) || cancelReason.Load() != cancelReasonNone
			if needRotate {
				reqCancel()
			}
			_ = resp.Body.Close()
			if !needRotate {
				reqCancel()
			}
			r.tracker.endAttempt(ws.id, claim.attemptID, true, time.Now())
			if needRotate {
				r.rebuildSlotTransport(ws)
			}

			outcome := outcomeCompleted
			if !chunkFinished && cr.end < claim.reqEnd {
				outcome = outcomeTruncated
			}
			_, allDone := r.ledger.releaseAttempt(claim.chunkIndex, claim.attemptID, outcome, nil, bytesAdvanced, time.Now())
			if allDone {
				r.segCancel()
				return
			}
			continue
		}

		if r.handleAttemptError(ws, claim, reqCancel, resp, &cancelReason, lostRace, readErr, bytesAdvanced) {
			return
		}
	}
}
