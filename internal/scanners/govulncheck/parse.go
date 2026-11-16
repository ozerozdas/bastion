package govulncheck

import (
	"encoding/json"
	"fmt"
	"io"
)

// message is one object of govulncheck's JSON stream. Only the two kinds the
// reachability mapping needs are decoded; config, progress and SBOM objects are
// ignored.
type message struct {
	OSV     *osvEntry   `json:"osv,omitempty"`
	Finding *osvFinding `json:"finding,omitempty"`
}

// osvEntry is an advisory from the vulnerability database, with the ids that
// name the same issue elsewhere (CVE, GHSA).
type osvEntry struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases,omitempty"`
}

// osvFinding is one finding govulncheck emitted for an advisory. The same
// advisory can produce a module-level, a package-level and several symbol-level
// findings, so they are aggregated rather than replaced.
type osvFinding struct {
	OSV   string  `json:"osv,omitempty"`
	Trace []frame `json:"trace,omitempty"`
}

// frame is one entry of a finding's trace. Function is empty for package- and
// module-level findings.
type frame struct {
	Module   string `json:"module,omitempty"`
	Package  string `json:"package,omitempty"`
	Function string `json:"function,omitempty"`
}

// parse reads a govulncheck JSON stream and returns, per advisory id (and per
// alias), whether each module has a call trace for it.
func parse(r io.Reader) (map[string]map[string]bool, error) {
	dec := json.NewDecoder(r)

	type call struct {
		osv       string
		module    string
		reachable bool
	}
	aliases := make(map[string][]string)
	var calls []call

	for {
		var msg message
		if err := dec.Decode(&msg); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("govulncheck: decode output: %w", err)
		}
		if msg.OSV != nil {
			normalized := make([]string, 0, len(msg.OSV.Aliases))
			for _, alias := range msg.OSV.Aliases {
				normalized = append(normalized, normalizeID(alias))
			}
			aliases[normalizeID(msg.OSV.ID)] = normalized
		}
		if msg.Finding == nil || msg.Finding.OSV == "" {
			continue
		}
		calls = append(calls, call{
			osv:       normalizeID(msg.Finding.OSV),
			module:    traceModule(msg.Finding.Trace),
			reachable: isCalled(msg.Finding.Trace),
		})
	}

	states := make(map[string]map[string]bool)
	for _, c := range calls {
		ids := append([]string{c.osv}, aliases[c.osv]...)
		for _, id := range ids {
			if id == "" {
				continue
			}
			byModule := states[id]
			if byModule == nil {
				byModule = make(map[string]bool)
				states[id] = byModule
			}
			byModule[c.module] = byModule[c.module] || c.reachable
		}
	}
	return states, nil
}

// isCalled reports whether the trace reaches a function. Module- and
// package-level findings have no function frame.
func isCalled(trace []frame) bool {
	for _, f := range trace {
		if f.Function != "" {
			return true
		}
	}
	return false
}

// traceModule is the module a finding's trace starts in; empty when the trace
// has no frame.
func traceModule(trace []frame) string {
	if len(trace) == 0 {
		return ""
	}
	return trace[0].Module
}
