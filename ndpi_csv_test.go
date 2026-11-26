package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNDPIBatchLimitsAndAmbiguity(t *testing.T) {
	c := dpiTestCapture()
	duplicateTuple := dpiCSVHeader + dpiCSVRow + strings.Replace(dpiCSVRow, "0,6,", "1,6,", 1)
	duplicateHeader := strings.Replace(dpiCSVHeader, "src_ip", "src_port", 1) + dpiCSVRow
	for _, bad := range []string{duplicateTuple, duplicateHeader, dpiCSVHeader + strings.Replace(dpiCSVRow, "HTTP", "\"unterminated", 1)} {
		if _, err := parseNDPI42CSV(bad, c); err == nil {
			t.Fatal("ambiguous/malformed input accepted")
		}
	}
	var b strings.Builder
	b.WriteString(dpiCSVHeader)
	for i := 0; i < 512; i++ {
		fmt.Fprintf(&b, "%d,17,1700000000.000,1700000000.010,192.0.2.10,%d,198.51.100.20,443,0,Unknown\n", i, 10000+i)
	}
	if rows, err := parseNDPI42CSV(b.String(), c); err != nil || len(rows) != 512 {
		t.Fatal("valid boundary rejected", err)
	}
	b.WriteString("512,17,1700000000.000,1700000000.010,192.0.2.10,10512,198.51.100.20,443,0,Unknown\n")
	if _, err := parseNDPI42CSV(b.String(), c); err == nil {
		t.Fatal("row limit ignored")
	}
}

func TestNDPI42ActualOfflineExport(t *testing.T) {
	path := os.Getenv("VPNGUARD_NDPI_OFFLINE_CSV")
	if path == "" {
		t.Skip("requires synthetic ndpiReader 4.2 export")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := parseNDPI42CSV(string(data), dpiTestCapture())
	if err != nil || len(rows) != 4 {
		t.Fatal("incomplete fixture export", len(rows), err)
	}
	expected := map[int]string{41001: "HTTP", 41002: "DNS", 41003: "Unknown", 41004: "HTTP.YouTube"}
	for _, row := range rows {
		if expected[row.Flow.SourcePort] != row.Flow.Application {
			t.Fatal("unexpected fixture classification")
		}
		delete(expected, row.Flow.SourcePort)
	}
	if len(expected) != 0 {
		t.Fatal("fixture flows missing")
	}
}

const dpiCSVHeader = "#flow_id,protocol,first_seen,last_seen,src_ip,src_port,dst_ip,dst_port,ndpi_proto_num,ndpi_proto\n"
const dpiCSVRow = "0,6,1700000000.000,1700000000.010,192.0.2.10,41001,198.51.100.20,80,7,HTTP\n"

func dpiTestCapture() dpiCapture {
	return dpiCapture{Source: "offline-fixture", Version: "4.2.0", GuessDisabled: true, Start: time.Unix(1700000000, 0), End: time.Unix(1700000003, 0)}
}
func TestNDPI42CSVValidation(t *testing.T) {
	c := dpiTestCapture()
	rows, err := parseNDPI42CSV(dpiCSVHeader+dpiCSVRow, c)
	if err != nil || len(rows) != 1 || rows[0].Flow.Application != "HTTP" || rows[0].Confidence != "unavailable" {
		t.Fatal(rows, err)
	}
	for _, bad := range []string{
		"", dpiCSVHeader + "bad\n", dpiCSVHeader + dpiCSVRow + dpiCSVRow,
		dpiCSVHeader + strings.Replace(dpiCSVRow, "192.0.2.10", "::ffff:192.0.2.10", 1),
		dpiCSVHeader + strings.Replace(dpiCSVRow, "41001", "65536", 1),
		dpiCSVHeader + strings.Replace(dpiCSVRow, "1700000000.010", "1699999999.000", 1),
		dpiCSVHeader + strings.Replace(dpiCSVRow, "1700000000.010", "1700000004.000", 1),
		dpiCSVHeader + strings.Replace(dpiCSVRow, "7,HTTP", "0,HTTP", 1),
		dpiCSVHeader + strings.Replace(dpiCSVRow, "HTTP", "<script>", 1),
		strings.Repeat("x", (1<<20)+1),
	} {
		if _, err := parseNDPI42CSV(bad, c); err == nil {
			t.Fatal("invalid batch accepted")
		}
	}
	for _, change := range []func(*dpiCapture){func(c *dpiCapture) { c.GuessDisabled = false }, func(c *dpiCapture) { c.Version = "dev" }, func(c *dpiCapture) { c.Source = "" }, func(c *dpiCapture) { c.End = c.Start.Add(2 * time.Minute) }} {
		bad := c
		change(&bad)
		if _, err := parseNDPI42CSV(dpiCSVHeader+dpiCSVRow, bad); err == nil {
			t.Fatal("invalid provenance accepted")
		}
	}
}
func TestNDPIUnknownAndTupleWindow(t *testing.T) {
	c := dpiTestCapture()
	rows, err := parseNDPI42CSV(dpiCSVHeader+strings.Replace(dpiCSVRow, "7,HTTP", "0,Unknown", 1), c)
	if err != nil || rows[0].Flow.Application != "Unknown" {
		t.Fatal(rows, err)
	}
	d := rows[0]
	r := d.Flow
	if !d.matches(r, c.Start, c.End) {
		t.Fatal("matching observation rejected")
	}
	r.SourcePort++
	if d.matches(r, c.Start, c.End) || d.matches(d.Flow, c.End, c.End.Add(time.Second)) {
		t.Fatal("unrelated observation matched")
	}
	r = d.Flow
	r.Source, r.Destination = r.Destination, r.Source
	r.SourcePort, r.DestinationPort = r.DestinationPort, r.SourcePort
	if d.matches(r, c.Start, c.End) {
		t.Fatal("reverse/NAT tuple accepted")
	}
}

func TestNDPICompoundProtocol(t *testing.T) {
	const simple = ",7,HTTP"
	for _, test := range []struct {
		compound string
		valid    bool
	}{
		{",91.178,TLS.Service", true}, {",91.x,TLS.Service", false}, {",0.0,TLS.Service", false},
	} {
		rows, err := parseNDPI42CSV(dpiCSVHeader+strings.Replace(dpiCSVRow, simple, test.compound, 1), dpiTestCapture())
		if (err == nil) != test.valid || test.valid && rows[0].Flow.Application != "TLS.Service" {
			t.Fatal(test, err)
		}
	}
}
