package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var olcInvocationID = regexp.MustCompile(`^[a-f0-9]{32}$`)
var olcPeerCount = regexp.MustCompile(`(?:^| )Current peers count: ([0-9]+), Devices: \[`)

const olcJournalEvents = `Current peers count: [0-9]+, Devices: \[|Server link reported conference end:|server reconnect reason=provider`

func olcServiceStatus(unit string) (client, received, sent string) {
	client, received, sent = "Нет данных", "—", "—"
	out, code := S.Run(3*time.Second, "", "systemctl", "show",
		"--property=InvocationID,IPIngressBytes,IPEgressBytes", "--", unit)
	if code != 0 {
		return
	}
	props := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		key, val, ok := strings.Cut(line, "=")
		if ok {
			props[key] = val
		}
	}
	received, sent = olcBytes(props["IPIngressBytes"]), olcBytes(props["IPEgressBytes"])
	if invocation := props["InvocationID"]; olcInvocationID.MatchString(invocation) {
		journal, code := S.Run(3*time.Second, "", "journalctl", "--no-pager", "--output=cat",
			"--lines=1", "--grep="+olcJournalEvents, "_SYSTEMD_INVOCATION_ID="+invocation)
		if code == 0 {
			client = olcClientStatus(journal)
		}
	}
	return
}

func olcClientStatus(message string) string {
	if strings.Contains(message, "Server link reported conference end:") {
		return "Связь с комнатой прервана"
	}
	if strings.Contains(message, "server reconnect reason=provider") {
		return "Переподключение: клиент не подтверждён"
	}
	count := olcPeerCount.FindStringSubmatch(message)
	if len(count) == 0 {
		return "Нет данных"
	}
	if count[1] == "0" {
		return "Ожидает клиента"
	}
	return "Подключено клиентов: " + count[1]
}

func olcBytes(raw string) string {
	n, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
	if err != nil || n == ^uint64(0) {
		return "—"
	}
	if n < 1024 {
		return fmt.Sprintf("%d Б", n)
	}
	value := float64(n) / 1024
	for _, unit := range []string{"КиБ", "МиБ", "ГиБ"} {
		if value < 1024 || unit == "ГиБ" {
			return fmt.Sprintf("%.1f %s", value, unit)
		}
		value /= 1024
	}
	return "—"
}
