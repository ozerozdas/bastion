package httpapi

import (
	"bufio"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/jobs"
)

func TestEventsRequiresSessionCookie(t *testing.T) {
	ts := newTestServer(t)

	resp := ts.do(t, http.MethodGet, "/api/events", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	if problem := readProblem(t, resp); problem.Status != http.StatusUnauthorized {
		t.Errorf("problem.status = %d, want %d", problem.Status, http.StatusUnauthorized)
	}
}

func TestEventsStreamsPublishedEvents(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	resp := openEvents(t, ts, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got, want := resp.Header.Get("Content-Type"), "text/event-stream"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}
	if got, want := resp.Header.Get("Cache-Control"), "no-cache"; got != want {
		t.Errorf("Cache-Control = %q, want %q", got, want)
	}

	reader := bufio.NewReader(resp.Body)
	want := []struct {
		event string
		ev    jobs.Event
	}{
		{
			event: string(jobs.EventQueued),
			ev:    jobs.Event{Type: jobs.EventQueued, ScanID: 7, AssetID: 3, Status: "queued"},
		},
		{
			event: string(jobs.EventProgress),
			ev: jobs.Event{
				Type:    jobs.EventProgress,
				ScanID:  7,
				AssetID: 3,
				Status:  "running",
				Stage:   jobs.StageScan,
				Scanner: "trivy",
			},
		},
		{
			event: string(jobs.EventFinished),
			ev: jobs.Event{
				Type:    jobs.EventFinished,
				ScanID:  7,
				AssetID: 3,
				Status:  "failed",
				Error:   "trivy exited 1",
			},
		},
	}

	for _, w := range want {
		ts.events.Publish(w.ev)

		event, data := readSSEFrame(t, reader)
		if event != w.event {
			t.Fatalf("event = %q, want %q", event, w.event)
		}
		var got scanEvent
		if err := json.Unmarshal([]byte(data), &got); err != nil {
			t.Fatalf("decode data %q: %v", data, err)
		}
		if want := (scanEvent{
			Type:    string(w.ev.Type),
			ScanID:  w.ev.ScanID,
			AssetID: w.ev.AssetID,
			Status:  w.ev.Status,
			Stage:   w.ev.Stage,
			Scanner: w.ev.Scanner,
			Error:   w.ev.Error,
		}); got != want {
			t.Errorf("data = %+v, want %+v", got, want)
		}
	}
}

func TestEventsDisconnectFreesSubscriber(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	resp := openEvents(t, ts, cookie)
	waitForCondition(t, "subscriber to connect", func() bool {
		return ts.events.Subscribers() == 1
	})

	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close stream: %v", err)
	}
	waitForCondition(t, "subscriber to be freed", func() bool {
		return ts.events.Subscribers() == 0
	})
}

// openEvents starts an SSE request and closes it when the test ends.
func openEvents(t *testing.T, ts *testServer, cookie *http.Cookie) *http.Response {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.url+"/api/events", http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := ts.client.Do(req)
	if err != nil {
		t.Fatalf("GET /api/events: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// readSSEFrame reads one event/data frame, skipping comments and blank lines
// before it.
func readSSEFrame(t *testing.T, r *bufio.Reader) (event, data string) {
	t.Helper()

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read event stream: %v", err)
		}
		line = strings.TrimSuffix(line, "\n")

		switch {
		case line == "":
			if event != "" || data != "" {
				return event, data
			}
		case strings.HasPrefix(line, "event: "):
			event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			data = strings.TrimPrefix(line, "data: ")
		}
	}
}

// waitForCondition polls until cond is true or the test times out.
func waitForCondition(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
