package events

import (
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/jobs"
)

func TestPublishReachesSubscribers(t *testing.T) {
	broker := NewBroker()
	first, unsubscribeFirst := broker.Subscribe()
	defer unsubscribeFirst()
	second, unsubscribeSecond := broker.Subscribe()
	defer unsubscribeSecond()

	ev := jobs.Event{Type: jobs.EventQueued, ScanID: 7, AssetID: 3, Status: "queued"}
	broker.Publish(ev)

	for i, ch := range []<-chan jobs.Event{first, second} {
		select {
		case got := <-ch:
			if got != ev {
				t.Errorf("subscriber %d: got %+v, want %+v", i, got, ev)
			}
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d: no event delivered", i)
		}
	}
	if got := broker.Subscribers(); got != 2 {
		t.Errorf("Subscribers() = %d, want 2", got)
	}
}

func TestUnsubscribeFreesSubscriber(t *testing.T) {
	broker := NewBroker()
	ch, unsubscribe := broker.Subscribe()

	unsubscribe()
	unsubscribe() // idempotent
	if got := broker.Subscribers(); got != 0 {
		t.Fatalf("Subscribers() = %d, want 0", got)
	}
	if _, open := <-ch; open {
		t.Error("channel is still open after unsubscribe")
	}

	// Publishing with no subscribers is a no-op.
	broker.Publish(jobs.Event{Type: jobs.EventFinished})
}

func TestSlowSubscriberIsDroppedWithoutBlockingPublish(t *testing.T) {
	broker := NewBroker()
	ch, unsubscribe := broker.Subscribe()
	defer unsubscribe()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// One more than the buffer, with nobody reading: the broker must
		// drop the subscriber instead of waiting for it.
		for i := range subscriberBuffer + 4 {
			broker.Publish(jobs.Event{Type: jobs.EventProgress, ScanID: int64(i)})
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a slow subscriber")
	}

	if got := broker.Subscribers(); got != 0 {
		t.Errorf("Subscribers() = %d, want 0 (slow subscriber dropped)", got)
	}

	// The dropped channel is closed; draining it ends instead of hanging.
	for range ch {
	}
}
