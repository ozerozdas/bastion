// Package events fans scan lifecycle events out to the SSE endpoint
// (PROJECT_SPEC.md §6, BST-023).
//
// A Broker implements jobs.Publisher. Publish never blocks: each subscriber
// has a small buffered channel, and a subscriber that cannot keep up is
// dropped (its channel is closed) instead of stalling a scan worker. There is
// no replay, so a client that disconnects or is dropped reconnects and
// continues with the next event.
package events

import (
	"sync"

	"github.com/ozerozdas/bastion/internal/jobs"
)

// subscriberBuffer is how many events a subscriber may fall behind by. The UI
// only needs the newest lifecycle state, so dropping a slow client is cheaper
// than holding a scan worker.
const subscriberBuffer = 16

// Broker fans scan events out to every current subscriber. Create it with
// NewBroker; the zero value has no subscriber map. It is safe for concurrent
// use.
type Broker struct {
	mu   sync.Mutex
	subs map[*subscriber]struct{}
}

type subscriber struct {
	ch chan jobs.Event
}

// NewBroker returns a broker with no subscribers.
func NewBroker() *Broker {
	return &Broker{subs: make(map[*subscriber]struct{})}
}

// Publish delivers ev to every subscriber without blocking. A subscriber whose
// buffer is full is dropped: its channel is closed and it receives no further
// events. Publish runs on scan workers, so it must stay cheap.
func (b *Broker) Publish(ev jobs.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for sub := range b.subs {
		select {
		case sub.ch <- ev:
		default:
			delete(b.subs, sub)
			close(sub.ch)
		}
	}
}

// Subscribe registers a subscriber and returns its events plus the function
// that removes it again. The channel is closed when the subscriber is
// unsubscribed or dropped for being too slow. Unsubscribe is idempotent.
func (b *Broker) Subscribe() (<-chan jobs.Event, func()) {
	sub := &subscriber{ch: make(chan jobs.Event, subscriberBuffer)}

	b.mu.Lock()
	b.subs[sub] = struct{}{}
	b.mu.Unlock()

	return sub.ch, func() { b.unsubscribe(sub) }
}

// unsubscribe removes sub and closes its channel, once.
func (b *Broker) unsubscribe(sub *subscriber) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.subs[sub]; !ok {
		return
	}
	delete(b.subs, sub)
	close(sub.ch)
}

// Subscribers reports how many subscribers are connected. Tests use it to
// assert that a client disconnect frees its subscriber.
func (b *Broker) Subscribers() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs)
}
