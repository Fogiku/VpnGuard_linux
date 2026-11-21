package main

type diagnosticModuleV1 struct {
	ID    string `json:"id"`
	Level int    `json:"level"`
	Up    bool   `json:"up"`
}

type diagnosticDecisionsV1 struct {
	Info    int `json:"info"`
	Warning int `json:"warning"`
	Error   int `json:"error"`
	Other   int `json:"other"`
}

type diagnosticSnapshotV1 struct {
	SchemaVersion int                   `json:"schemaVersion"`
	AgentVersion  string                `json:"agentVersion"`
	Simulation    bool                  `json:"simulation"`
	RoutingReady  bool                  `json:"routingReady"`
	Modules       []diagnosticModuleV1  `json:"modules"`
	Decisions     diagnosticDecisionsV1 `json:"decisions"`
}

func readDiagnosticSnapshotV1() diagnosticSnapshotV1 {
	s := diagnosticSnapshotV1{
		SchemaVersion: 1, AgentVersion: Version, Simulation: Sim,
		RoutingReady: !routesStarting.Load(), Modules: []diagnosticModuleV1{},
	}
	// IDs of user-configured exits and free-form status text can identify clients.
	for _, id := range []string{"inet", "wg", "meduza", "dns", "awg", "zapret", "direct", "block", "flows", "remote"} {
		if m := mod(id); m != nil {
			st := m.Status()
			s.Modules = append(s.Modules, diagnosticModuleV1{id, st.Level, st.Up})
		}
	}
	logMu.Lock()
	defer logMu.Unlock()
	for _, entry := range decRing {
		switch entry.Lvl {
		case "INFO":
			s.Decisions.Info++
		case "WARN":
			s.Decisions.Warning++
		case "ERROR":
			s.Decisions.Error++
		default:
			s.Decisions.Other++
		}
	}
	return s
}
