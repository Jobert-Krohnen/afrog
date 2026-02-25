package runner

import (
	"context"
	"sync"
	"time"

	"github.com/zan8in/oobadapter/pkg/oobadapter"
)

type OOBManager struct {
	adapter       *oobadapter.OOBAdapter
	pollInterval  time.Duration
	hitRetention  time.Duration
	mu            sync.Mutex
	waiters       map[string]*oobWaitEntry
	hits          map[string]oobHit
	lastPolledAt  map[string]time.Time
	lastPollError map[string]time.Time
}

type OOBHitSnapshot struct {
	Filter     string
	FilterType string
	FirstAt    time.Time
	LastAt     time.Time
	Count      uint64
	Snippet    string
}

type oobHit struct {
	firstAt time.Time
	lastAt  time.Time
	count   uint64
	snippet string
}

type oobWaitEntry struct {
	filter     string
	filterType string
	done       chan struct{}
	refs       int
}

func NewOOBManager(ctx context.Context, adapter *oobadapter.OOBAdapter, pollInterval time.Duration, hitRetention time.Duration) *OOBManager {
	if pollInterval <= 0 {
		pollInterval = time.Second
	}
	if hitRetention <= 0 {
		hitRetention = 10 * time.Minute
	}
	m := &OOBManager{
		adapter:       adapter,
		pollInterval:  pollInterval,
		hitRetention:  hitRetention,
		waiters:       make(map[string]*oobWaitEntry),
		hits:          make(map[string]oobHit),
		lastPolledAt:  make(map[string]time.Time),
		lastPollError: make(map[string]time.Time),
	}
	go m.loop(ctx)
	return m
}

func (m *OOBManager) Wait(filter string, filterType string, timeout time.Duration) bool {
	if m == nil || m.adapter == nil || filter == "" || timeout <= 0 {
		return false
	}
	if filterType == "" {
		filterType = oobadapter.OOBDNS
	}

	key := filterType + "|" + filter

	m.mu.Lock()
	if hit, ok := m.hits[key]; ok && time.Since(hit.lastAt) <= m.hitRetention {
		m.mu.Unlock()
		return true
	}
	if e, ok := m.waiters[key]; ok {
		e.refs++
		ch := e.done
		m.mu.Unlock()
		return waitClosed(ch, timeout)
	}

	e := &oobWaitEntry{
		filter:     filter,
		filterType: filterType,
		done:       make(chan struct{}),
		refs:       1,
	}
	m.waiters[key] = e
	ch := e.done
	m.mu.Unlock()

	ok := waitClosed(ch, timeout)

	m.mu.Lock()
	if cur, exists := m.waiters[key]; exists {
		cur.refs--
		if cur.refs <= 0 {
			delete(m.waiters, key)
		}
	}
	m.mu.Unlock()

	return ok
}

func (m *OOBManager) HitSnapshot(filter string, filterType string) (OOBHitSnapshot, bool) {
	if m == nil || filter == "" {
		return OOBHitSnapshot{}, false
	}
	if filterType == "" {
		filterType = oobadapter.OOBDNS
	}
	key := filterType + "|" + filter
	m.mu.Lock()
	h, ok := m.hits[key]
	retention := m.hitRetention
	m.mu.Unlock()
	if !ok {
		return OOBHitSnapshot{}, false
	}
	if retention > 0 && time.Since(h.lastAt) > retention {
		return OOBHitSnapshot{}, false
	}
	return OOBHitSnapshot{
		Filter:     filter,
		FilterType: filterType,
		FirstAt:    h.firstAt,
		LastAt:     h.lastAt,
		Count:      h.count,
		Snippet:    h.snippet,
	}, true
}

func waitClosed(ch <-chan struct{}, timeout time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ch:
		return true
	case <-timer.C:
		return false
	}
}

func (m *OOBManager) loop(ctx context.Context) {
	ticker := time.NewTicker(m.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		typeGroup := m.snapshotWaiters()
		if len(typeGroup) == 0 {
			m.cleanupHits()
			continue
		}

		now := time.Now()
		for filterType, keys := range typeGroup {
			m.mu.Lock()
			lastAt := m.lastPolledAt[filterType]
			m.mu.Unlock()
			if !lastAt.IsZero() && now.Sub(lastAt) < m.pollInterval {
				continue
			}

			body, err := m.adapter.Poll(filterType)
			m.mu.Lock()
			m.lastPolledAt[filterType] = now
			if err != nil {
				m.lastPollError[filterType] = now
			}
			m.mu.Unlock()
			if err != nil || len(body) == 0 {
				continue
			}

			for _, key := range keys {
				m.mu.Lock()
				e, ok := m.waiters[key]
				m.mu.Unlock()
				if !ok {
					continue
				}
				if m.adapter.Match(body, e.filterType, e.filter) {
					now2 := time.Now()
					snippet := oobSnippet(body, 512)
					m.mu.Lock()
					if _, ok := m.waiters[key]; ok {
						delete(m.waiters, key)
						if h, ok := m.hits[key]; ok {
							h.lastAt = now2
							h.count++
							if h.snippet == "" {
								h.snippet = snippet
							}
							m.hits[key] = h
						} else {
							m.hits[key] = oobHit{firstAt: now2, lastAt: now2, count: 1, snippet: snippet}
						}
						close(e.done)
					}
					m.mu.Unlock()
				}
			}
		}

		m.cleanupHits()
	}
}

func (m *OOBManager) snapshotWaiters() map[string][]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.waiters) == 0 {
		return nil
	}
	group := make(map[string][]string)
	for k, e := range m.waiters {
		group[e.filterType] = append(group[e.filterType], k)
	}
	return group
}

func (m *OOBManager) cleanupHits() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.hits) == 0 {
		return
	}
	now := time.Now()
	for k, h := range m.hits {
		if now.Sub(h.lastAt) > m.hitRetention {
			delete(m.hits, k)
		}
	}
}

func oobSnippet(body []byte, max int) string {
	if len(body) == 0 || max <= 0 {
		return ""
	}
	if len(body) > max {
		body = body[:max]
	}
	return string(body)
}
