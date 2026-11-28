package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed deploy/passive_dpi.py
var passiveDPIScript string

func sampleDPITable(iface string, events *flowEventSession, lan ...string) (Table, dpiSampleResult, map[string]dpiBinding) {
	result := dpiSampleResult{At: time.Now().Unix(), Status: "worker"}
	t := Table{Title: "Пассивное распознавание nDPI", Cols: []string{"Протокол", "Потоков в выборке"}, Rows: [][]string{}, Empty: "Ожидание выборки"}
	if Sim {
		result.Status = "simulation"
		t.Empty = "Захват доступен на шлюзе Linux."
		return t, result, nil
	}
	before, beforeErr := events.dpiBoundary()
	result.Source = "WG · " + iface
	args := append([]string{"-", iface}, lan...)
	if len(lan) > 0 {
		result.Source = "LAN"
	}
	out, code := S.Run(18*time.Second, passiveDPIScript, "python3", args...)
	var batch struct {
		Start, End            int64
		Packets               *int
		CSV, Error, Interface string
	}
	if code != 0 || json.Unmarshal([]byte(out), &batch) != nil {
		t.Empty = "Не удалось запустить сборщик nDPI."
		return t, result, nil
	}
	if batch.Error != "" {
		switch batch.Error {
		case "missing", "version", "permission", "interface", "drops", "format":
			result.Status = batch.Error
		default:
			result.Status = "reader"
		}
		t.Empty = map[string]string{"missing": "Нажмите «Установить libndpi-bin» на этой странице.", "version": "Поддерживается ndpiReader 4.2.0.", "permission": "Для чтения пакетов нужны права CAP_NET_RAW.", "interface": "Не удалось открыть интерфейс выборки или файл в памяти.", "drops": "Ядро сообщило о потере пакетов. Выборка пропущена."}[batch.Error]
		if t.Empty == "" {
			t.Empty = "Не удалось обработать выборку nDPI."
		}
		return t, result, nil
	}
	if batch.Packets == nil || batch.Start <= 0 || batch.End < batch.Start || batch.End-batch.Start > 60000 || *batch.Packets < 0 || *batch.Packets > 128 || (*batch.Packets == 0 && batch.CSV != "") {
		result.Status = "format"
		t.Empty = "Некорректные границы выборки."
		return t, result, nil
	}
	if len(lan) > 0 {
		if batch.Interface == "" {
			result.Status = "interface"
			return t, result, nil
		}
		iface = batch.Interface
		result.Source = "LAN · " + iface
	}
	result.Interface = iface
	c := dpiCapture{Source: iface, Version: "4.2.0", GuessDisabled: true, Start: time.UnixMilli(batch.Start), End: time.UnixMilli(batch.End)}
	t.Note = fmt.Sprintf("%s · %s · %d пакетов. CSV nDPI 4.2.0 не содержит оценки уверенности.", iface, c.End.Format(time.RFC3339), *batch.Packets)
	t.Empty = "За время выборки протоколы не наблюдались."
	if *batch.Packets == 0 {
		result.Status = "empty"
		result.Counts = &dpiSampleCounts{}
		return t, result, nil
	}
	observed, err := parseNDPI42CSV(batch.CSV, c)
	if err != nil || len(observed) > *batch.Packets {
		result.Status = "format"
		t.Empty = "Формат или границы выборки не прошли проверку."
		return t, result, nil
	}
	counts := map[string]int{}
	targets := 0
	for _, o := range observed {
		label := o.Flow.Application
		counts[label]++
		// nDPI 4.2 emits either a standalone label or master.service.
		_, service, compound := strings.Cut(label, ".")
		if !compound {
			service = label
		}
		switch strings.ToLower(service) {
		case "youtube", "youtubeupload", "discord", "telegram", "netflix", "steam":
			targets++
		}
	}
	result.Status = "sample"
	result.Counts = &dpiSampleCounts{Packets: *batch.Packets, TargetServices: targets, Unknown: counts["Unknown"], Recognized: len(observed) - counts["Unknown"]}
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		t.Rows = append(t.Rows, []string{name, strconv.Itoa(counts[name])})
	}
	if beforeErr != nil || len(observed) == 0 {
		return t, result, nil
	}
	deadline := time.Now().Add(1500 * time.Millisecond)
	for {
		after, err := events.dpiBoundary()
		if err != nil || after.Frame.Epoch != before.Frame.Epoch {
			return t, result, nil
		}
		if !after.At.Before(c.End) {
			bindings := map[string]dpiBinding{}
			for _, d := range observed {
				if b, err := bindDPIObservation(d, c, before, after); err == nil {
					bindings[b.Generation] = b
				}
			}
			result.Counts.Bound = len(bindings)
			return t, result, bindings
		}
		if time.Now().After(deadline) {
			return t, result, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
}
