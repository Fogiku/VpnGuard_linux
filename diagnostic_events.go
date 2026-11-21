package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

const diagnosticEventCapacity = 128

type diagnosticEvent struct {
	Sequence uint64 `json:"sequence"`
	Type     string `json:"type"`
	Module   string `json:"module,omitempty"`
}

type diagnosticEventPage struct {
	SchemaVersion int                   `json:"schemaVersion"`
	Cursor        string                `json:"cursor"`
	Reset         bool                  `json:"reset"`
	Events        []diagnosticEvent     `json:"events"`
	Snapshot      *diagnosticSnapshotV1 `json:"snapshot,omitempty"`
}

type diagnosticEventLog struct {
	mu    sync.Mutex
	epoch string
	last  uint64
	ring  [diagnosticEventCapacity]diagnosticEvent
}

var controllerEvents = diagnosticEventLog{epoch: newToken()}

func (l *diagnosticEventLog) record(kind, module string) {
	switch kind {
	case "exit.changed", "routes.changed":
		switch module {
		case "wg", "awg", "meduza", "zapret", "direct", "block":
		default:
			module = ""
		}
	case "inet.lost", "inet.restored":
		module = "inet"
	default:
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.last++
	l.ring[(l.last-1)%diagnosticEventCapacity] = diagnosticEvent{l.last, kind, module}
}

func (l *diagnosticEventLog) page(cursor string) diagnosticEventPage {
	epoch, number, ok := strings.Cut(cursor, ".")
	after, err := strconv.ParseUint(number, 10, 64)
	l.mu.Lock()
	defer l.mu.Unlock()
	p := diagnosticEventPage{SchemaVersion: 1, Events: []diagnosticEvent{}, Cursor: l.epoch + "." + strconv.FormatUint(l.last, 10)}
	if !ok || err != nil || epoch != l.epoch || after > l.last || l.last-after > diagnosticEventCapacity {
		p.Reset = true
		return p
	}
	for seq := after + 1; seq <= l.last; seq++ {
		p.Events = append(p.Events, l.ring[(seq-1)%diagnosticEventCapacity])
	}
	return p
}

func serveDiagnosticEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "требуется GET", http.StatusMethodNotAllowed)
		return
	}
	page := controllerEvents.page(r.URL.Query().Get("cursor"))
	if page.Reset {
		// Take the cursor first. Changes during snapshot collection remain available on the next poll.
		s := readDiagnosticSnapshotV1()
		page.Snapshot = &s
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(page)
}
