package main

const diagnosticWindowSeconds int64 = 300

type diagnosticTelemetryPage struct {
	SchemaVersion int             `json:"schemaVersion"`
	From          int64           `json:"from"`
	Through       int64           `json:"through"`
	StepSeconds   int64           `json:"stepSeconds"`
	Samples       []historySample `json:"samples"`
}

func (s *historyStore) diagnosticWindow(now int64) diagnosticTelemetryPage {
	end := now / historyStep * historyStep
	page := diagnosticTelemetryPage{
		SchemaVersion: 1, From: end - diagnosticWindowSeconds + historyStep,
		Through: end, StepSeconds: historyStep, Samples: []historySample{},
	}
	if s == nil {
		return page
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sample := range s.samples {
		if sample.At < page.From || sample.At > end {
			continue
		}
		values := make(map[string]float64)
		for _, key := range [...]string{"dns.queries", "dns.errors", "dns.refused", "dns.cache_entries", "dns.level", "meduza.level"} {
			if v, ok := sample.Values[key]; ok {
				values[key] = v
			}
		}
		if len(values) > 0 {
			page.Samples = append(page.Samples, historySample{At: sample.At, Values: values})
		}
	}
	return page
}
