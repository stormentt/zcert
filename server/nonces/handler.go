package nonces

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type nonceRecord struct {
	Nonce string
	When  time.Time
}

type NonceManager struct {
	seen     []nonceRecord
	lastCull time.Time

	mtx sync.RWMutex
}

func (h *NonceManager) Cull() {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	var filtered []nonceRecord

	for _, nr := range h.seen {
		if time.Since(nr.When) < time.Hour*1 {
			filtered = append(filtered, nr)
		} else {
			log.WithFields(log.Fields{
				"nonce": nr.Nonce,
				"when":  nr.When,
			}).Trace("culling nonce")
		}
	}

	h.seen = filtered
}

func (h *NonceManager) Cullable() bool {
	return time.Since(h.lastCull) > time.Minute*5
}

func (h *NonceManager) Seen(nonce string) bool {
	h.mtx.RLock()
	defer h.mtx.RUnlock()

	for _, nr := range h.seen {
		if nr.Nonce == nonce {
			return true
		}
	}

	return false
}

func (h *NonceManager) Record(nonce string) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	when := time.Now()

	log.WithFields(log.Fields{
		"nonce": nonce,
		"when":  when,
	}).Trace("recording nonce")

	h.seen = append(h.seen, nonceRecord{nonce, when})
}
