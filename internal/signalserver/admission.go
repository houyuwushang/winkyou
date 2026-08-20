package signalserver

import (
	"container/list"
	"net/netip"
	"time"
)

type admissionResult uint8

const (
	admissionAllowed admissionResult = iota
	admissionInvalidSource
	admissionGlobalRate
	admissionSourceRate
	admissionSourceTableFull
)

type tokenBucket struct {
	rate     float64
	capacity float64
	tokens   float64
	last     time.Time
}

func newTokenBucket(rate int, now time.Time) tokenBucket {
	capacity := float64(rate)
	return tokenBucket{rate: capacity, capacity: capacity, tokens: capacity, last: now}
}

func (bucket *tokenBucket) take(now time.Time) bool {
	if !now.Before(bucket.last) {
		elapsed := now.Sub(bucket.last).Seconds()
		bucket.tokens += elapsed * bucket.rate
		if bucket.tokens > bucket.capacity {
			bucket.tokens = bucket.capacity
		}
		bucket.last = now
	}
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

type sourceBucket struct {
	address  netip.Addr
	bucket   tokenBucket
	lastSeen time.Time
	element  *list.Element
}

type admissionController struct {
	global          tokenBucket
	perSourceRate   int
	maxSources      int
	sourceIdleLimit time.Duration
	sources         map[netip.Addr]*sourceBucket
	order           *list.List
}

func newAdmissionController(globalRate, perSourceRate, maxSources int, sourceIdleLimit time.Duration, now time.Time) *admissionController {
	return &admissionController{
		global:          newTokenBucket(globalRate, now),
		perSourceRate:   perSourceRate,
		maxSources:      maxSources,
		sourceIdleLimit: sourceIdleLimit,
		sources:         make(map[netip.Addr]*sourceBucket, maxSources),
		order:           list.New(),
	}
}

func (controller *admissionController) allow(address netip.Addr, now time.Time) admissionResult {
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
		return admissionInvalidSource
	}
	address = address.Unmap()
	if current := controller.sources[address]; current != nil {
		current.lastSeen = now
		controller.order.MoveToBack(current.element)
		if !current.bucket.take(now) {
			return admissionSourceRate
		}
		if !controller.global.take(now) {
			return admissionGlobalRate
		}
		return admissionAllowed
	}

	if !controller.global.take(now) {
		return admissionGlobalRate
	}
	controller.removeExpired(now)
	if len(controller.sources) >= controller.maxSources {
		return admissionSourceTableFull
	}
	current := &sourceBucket{
		address:  address,
		bucket:   newTokenBucket(controller.perSourceRate, now),
		lastSeen: now,
	}
	current.bucket.take(now)
	current.element = controller.order.PushBack(current)
	controller.sources[address] = current
	return admissionAllowed
}

func (controller *admissionController) removeExpired(now time.Time) {
	for {
		front := controller.order.Front()
		if front == nil {
			return
		}
		current := front.Value.(*sourceBucket)
		if now.Sub(current.lastSeen) < controller.sourceIdleLimit {
			return
		}
		delete(controller.sources, current.address)
		controller.order.Remove(front)
	}
}
