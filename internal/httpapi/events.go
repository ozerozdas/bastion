package httpapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ozerozdas/bastion/internal/jobs"
)

// eventsPingInterval is how often an idle stream sends a comment, so a dead
// peer is noticed and the connection stays open.
const eventsPingInterval = 15 * time.Second

// scanEvent is the SSE data payload (§6). It mirrors jobs.Event with
// snake_case names; optional fields are omitted rather than sent empty.
type scanEvent struct {
	Type    string `json:"type"`
	ScanID  int64  `json:"scan_id"`
	AssetID int64  `json:"asset_id"`
	Status  string `json:"status"`
	Stage   string `json:"stage,omitempty"`
	Scanner string `json:"scanner,omitempty"`
	Error   string `json:"error,omitempty"`
}

// handleEvents streams scan lifecycle events as Server-Sent Events.
//
// The session middleware already authenticated the request like every other
// /api/* route. Each subscriber has a small buffer, so a client that cannot
// keep up is dropped by the broker and its stream simply ends instead of
// blocking a scan worker. There is no replay: the client refetches state after
// reconnecting.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	ch, unsubscribe := s.events.Subscribe()
	defer unsubscribe()

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeProblem(w, http.StatusInternalServerError, "Internal Server Error",
			"this server cannot stream responses")
		return
	}

	header := w.Header()
	header.Set("Content-Type", "text/event-stream")
	header.Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ping := time.NewTicker(eventsPingInterval)
	defer ping.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			if _, err := io.WriteString(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case ev, open := <-ch:
			if !open {
				return
			}
			if err := writeScanEvent(w, ev); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// writeScanEvent writes one SSE frame. The payload stays on one line:
// json.Marshal escapes newlines, so an error message cannot break the frame.
func writeScanEvent(w io.Writer, ev jobs.Event) error {
	data, err := json.Marshal(scanEvent{
		Type:    string(ev.Type),
		ScanID:  ev.ScanID,
		AssetID: ev.AssetID,
		Status:  ev.Status,
		Stage:   ev.Stage,
		Scanner: ev.Scanner,
		Error:   ev.Error,
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, data)
	return err
}
