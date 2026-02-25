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
	hits          map[string]time.Time
	lastPolledAt  map[string]time.Time
	lastPollError map[string]time.Time
}

type oobWaitEntry struct {
	filter     string
	filterType string
	done       chan struct{}
	refs       int
}

func NewOOBManager(ctx context.Context, adapter *oobadapter.OOBAdapter) *OOBManager {
	m := &OOBManager{
		adapter:       adapter,
		pollInterval:  time.Second,
		hitRetention:  10 * time.Minute,
		waiters:       make(map[string]*oobWaitEntry),
		hits:          make(map[string]time.Time),
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
	if t, ok := m.hits[key]; ok && time.Since(t) <= m.hitRetention {
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
					m.mu.Lock()
					if _, ok := m.waiters[key]; ok {
						delete(m.waiters, key)
						m.hits[key] = time.Now()
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
	for k, t := range m.hits {
		if now.Sub(t) > m.hitRetention {
			delete(m.hits, k)
		}
	}
}
