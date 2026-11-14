package main

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/ozerozdas/bastion/internal/jobs"
	"github.com/ozerozdas/bastion/internal/scanners"
)

// scanProgress writes one plain line per scan stage and scanner to its writer
// (stderr in the CLI). Every line ends up beside the selected output format,
// never inside it, so stdout stays byte-identical. A line identical to the
// previous one is dropped, so a repeated event is not printed twice.
//
// A nil *scanProgress is a valid no-op, which is what tests and --quiet use.
type scanProgress struct {
	mu   sync.Mutex
	out  io.Writer
	last string
}

func newScanProgress(out io.Writer) *scanProgress {
	if out == nil {
		return nil
	}
	return &scanProgress{out: out}
}

// line prints msg unless it repeats the previous line.
func (p *scanProgress) line(msg string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if msg == p.last {
		return
	}
	p.last = msg
	_, _ = fmt.Fprintln(p.out, msg)
}

// stage prints the line for one pipeline stage. It is the single mapping used
// by the stored pipeline (through Publish) and by the direct one.
func (p *scanProgress) stage(stage, scanner string) {
	switch stage {
	case jobs.StageResolve:
		p.line("resolving target…")
	case jobs.StageFetch:
		p.line("fetching target…")
	case jobs.StageScan:
		if scanner != "" {
			p.line(scanner + ": running…")
		}
	case scanners.PhaseWaitingDB:
		if scanner != "" {
			p.line(scanner + ": waiting for vulnerability database…")
		}
	default:
		// Normalizing takes no measurable time and would only add noise.
	}
}

// Publish implements jobs.Publisher for the stored pipeline. Progress is all
// it reports; the scan's own outcome is summarized from its scanner runs.
func (p *scanProgress) Publish(ev jobs.Event) {
	if ev.Type != jobs.EventProgress {
		return
	}
	p.stage(ev.Stage, ev.Scanner)
}

// runs prints one line per finished scanner: "trivy: succeeded (4s)" or
// "osv: failed: <message>". Errors are collapsed onto one line because this
// output is a stream of plain lines.
func (p *scanProgress) runs(list []scannerRun) {
	for _, run := range list {
		switch run.Status {
		case "succeeded":
			p.line(fmt.Sprintf("%s: succeeded (%s)", run.Scanner, progressDuration(run.DurationMS)))
		case "failed":
			p.line(fmt.Sprintf("%s: failed: %s", run.Scanner, strings.Join(strings.Fields(run.Error), " ")))
		default:
			p.line(fmt.Sprintf("%s: %s", run.Scanner, run.Status))
		}
	}
}

// progressDuration formats a scanner's duration at a resolution that keeps the
// line stable: whole tenths of a second once it takes a second or more.
func progressDuration(ms int64) string {
	d := time.Duration(ms) * time.Millisecond
	switch {
	case d < 10*time.Millisecond:
		return "<10ms"
	case d < time.Second:
		return d.Round(time.Millisecond).String()
	default:
		return d.Round(100 * time.Millisecond).String()
	}
}
