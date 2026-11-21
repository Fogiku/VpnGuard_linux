package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"
)

//go:embed deploy/passive_dpi.py
var passiveDPIScript string

func sampleDPITable(iface string) Table {
	t := Table{Title: "Пассивное распознавание nDPI", Cols: []string{"Протокол", "Потоков в выборке"}, Rows: [][]string{}, Empty: "Ожидание выборки"}
	if Sim {
		t.Empty = "Захват доступен на шлюзе Linux."
		return t
	}
	out, code := S.Run(12*time.Second, passiveDPIScript, "python3", "-", iface)
	var batch struct {
		Start, End int64
		Packets    int
		CSV, Error string
	}
	if code != 0 || json.Unmarshal([]byte(out), &batch) != nil {
		t.Empty = "Не удалось запустить сборщик nDPI."
		return t
	}
	if batch.Error != "" {
		t.Empty = map[string]string{"missing": "Установите libndpi-bin версии nDPI 4.2.0.", "version": "Поддерживается ndpiReader 4.2.0.", "permission": "Для чтения пакетов нужны права CAP_NET_RAW.", "interface": "Не удалось открыть интерфейс WG-Server или файл в памяти.", "drops": "Ядро сообщило о потере пакетов. Выборка пропущена."}[batch.Error]
		if t.Empty == "" {
			t.Empty = "Не удалось обработать выборку nDPI."
		}
		return t
	}
	c := dpiCapture{Source: iface, Version: "4.2.0", GuessDisabled: true, Start: time.UnixMilli(batch.Start), End: time.UnixMilli(batch.End)}
	t.Note = fmt.Sprintf("%s · %s · %d пакетов. CSV nDPI 4.2.0 не содержит оценки уверенности.", iface, c.End.Format(time.RFC3339), batch.Packets)
	t.Empty = "За время выборки протоколы не наблюдались."
	if batch.Packets == 0 {
		return t
	}
	observed, err := parseNDPI42CSV(batch.CSV, c)
	if err != nil {
		t.Empty = "Формат или границы выборки не прошли проверку."
		return t
	}
	counts := map[string]int{}
	for _, o := range observed {
		counts[o.Flow.Application]++
	}
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		t.Rows = append(t.Rows, []string{name, strconv.Itoa(counts[name])})
	}
	return t
}
