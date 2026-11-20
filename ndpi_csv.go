package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Metadata must come from the controlled runner, never from the CSV itself.
// CSV 4.2 has no per-flow confidence. A label is an observation, not a policy input.
type dpiCapture struct {
	Source        string
	Version       string
	GuessDisabled bool
	Start, End    time.Time
}
type dpiObservation struct {
	Flow        flowRow
	First, Last time.Time
	Source      string
	Confidence  string
}

var dpiLabel = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,96}$`)
var dpiTimestamp = regexp.MustCompile(`^[0-9]{1,12}\.[0-9]{3}$`)

func parseDPITime(s string) (time.Time, error) {
	if !dpiTimestamp.MatchString(s) {
		return time.Time{}, fmt.Errorf("invalid DPI timestamp")
	}
	parts := strings.Split(s, ".")
	sec, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	ms, _ := strconv.ParseInt(parts[1], 10, 64)
	return time.Unix(sec, ms*1e6), nil
}

// Fail the whole batch on malformed/duplicate tuples: no partial classification.
func parseNDPI42CSV(input string, capture dpiCapture) ([]dpiObservation, error) {
	if capture.Source == "" || len(capture.Source) > 128 || capture.Version != "4.2.0" || !capture.GuessDisabled || capture.Start.IsZero() || capture.End.Before(capture.Start) || capture.End.Sub(capture.Start) > time.Minute {
		return nil, fmt.Errorf("unsupported DPI provenance or capture window")
	}
	if len(input) > 1<<20 {
		return nil, fmt.Errorf("DPI export exceeds 1 MiB")
	}
	r := csv.NewReader(strings.NewReader(input))
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("missing DPI CSV header")
	}
	columns := map[string]int{}
	for i, name := range header {
		if _, ok := columns[name]; ok {
			return nil, fmt.Errorf("duplicate DPI column")
		}
		columns[name] = i
	}
	for _, name := range []string{"#flow_id", "protocol", "first_seen", "last_seen", "src_ip", "src_port", "dst_ip", "dst_port", "ndpi_proto_num", "ndpi_proto"} {
		if _, ok := columns[name]; !ok {
			return nil, fmt.Errorf("missing DPI column %s", name)
		}
	}
	var result []dpiObservation
	seen := map[string]bool{}
	ids := map[string]bool{}
	for {
		row, e := r.Read()
		if e == io.EOF {
			break
		}
		if e != nil || len(result) >= 512 {
			return nil, fmt.Errorf("malformed or oversized DPI batch")
		}
		get := func(k string) string { return row[columns[k]] }
		id := get("#flow_id")
		if _, e := strconv.ParseUint(id, 10, 32); e != nil || ids[id] {
			return nil, fmt.Errorf("invalid or duplicate DPI flow ID")
		}
		ids[id] = true
		proto := get("protocol")
		if proto != "6" && proto != "17" {
			return nil, fmt.Errorf("unsupported DPI transport")
		}
		src, e1 := netip.ParseAddr(get("src_ip"))
		dst, e2 := netip.ParseAddr(get("dst_ip"))
		sp, e3 := strconv.ParseUint(get("src_port"), 10, 16)
		dp, e4 := strconv.ParseUint(get("dst_port"), 10, 16)
		first, e5 := parseDPITime(get("first_seen"))
		last, e6 := parseDPITime(get("last_seen"))
		if e1 != nil || e2 != nil || !src.Is4() || !dst.Is4() || src.IsUnspecified() || dst.IsUnspecified() || src.IsMulticast() || dst.IsMulticast() || e3 != nil || e4 != nil || sp == 0 || dp == 0 || e5 != nil || e6 != nil || first.Before(capture.Start) || last.After(capture.End) || last.Before(first) {
			return nil, fmt.Errorf("invalid DPI tuple or time range")
		}
		label := get("ndpi_proto")
		num, e := strconv.ParseUint(get("ndpi_proto_num"), 10, 32)
		if e != nil || !dpiLabel.MatchString(label) || (num == 0) != (label == "Unknown") {
			return nil, fmt.Errorf("invalid DPI protocol label")
		}
		key := fmt.Sprintf("%s/%s/%d/%s/%d", proto, src, sp, dst, dp)
		if seen[key] {
			return nil, fmt.Errorf("ambiguous reused DPI tuple")
		}
		seen[key] = true
		transport := "tcp"
		if proto == "17" {
			transport = "udp"
		}
		result = append(result, dpiObservation{Flow: flowRow{Protocol: transport, Source: src.String(), Destination: dst.String(), SourcePort: int(sp), DestinationPort: int(dp), Application: label}, First: first, Last: last, Source: capture.Source, Confidence: "unavailable"})
	}
	return result, nil
}

// Exact direction only. Capture/observation window must overlap; no IP-only,
// port-only, reverse-tuple or post-NAT matching. Caller must establish lifetime
// identity before applying a result to a live conntrack entry.
func (d dpiObservation) matches(row flowRow, first, last time.Time) bool {
	return !first.IsZero() && !last.Before(first) && !d.Last.Before(first) && !last.Before(d.First) &&
		d.Flow.Protocol == row.Protocol && d.Flow.Source == row.Source && d.Flow.Destination == row.Destination && d.Flow.SourcePort == row.SourcePort && d.Flow.DestinationPort == row.DestinationPort
}
