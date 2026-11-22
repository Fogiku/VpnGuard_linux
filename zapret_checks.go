package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const zapretDefaultTargets = "https://www.youtube.com,https://discord.com,https://i.ytimg.com,https://redirector.googlevideo.com,https://gateway.discord.gg,https://cdn.discordapp.com"
const zapretLegacyTargets = "https://www.youtube.com,https://discord.com,https://i.ytimg.com"

var zVideoMapping = regexp.MustCompile(`\b(sn-[a-z0-9-]{4,})`)
var zVideoHostname = regexp.MustCompile(`rr\d{1,2}---sn-[a-z0-9-]{4,}\.googlevideo\.com`)
var zPlayerJS = regexp.MustCompile(`/s/player/[A-Za-z0-9_./-]+/base\.js`)

type zProbeResult struct {
	Code                 string
	Bytes, Seconds, Mbit float64
	OK                   bool
	Detail               string
}

func parseZProbe(text string, exit int, speed bool) zProbeResult {
	var r zProbeResult
	f := strings.Fields(text)
	if len(f) > 0 {
		r.Code = f[0]
	}
	if len(f) > 1 {
		r.Bytes, _ = strconv.ParseFloat(f[1], 64)
	}
	if len(f) > 2 {
		r.Seconds, _ = strconv.ParseFloat(f[2], 64)
	}
	valid := len(r.Code) == 3 && r.Code[0] >= '1' && r.Code[0] <= '5' && r.Code[1] >= '0' && r.Code[1] <= '9' && r.Code[2] >= '0' && r.Code[2] <= '9'
	if !valid {
		r.Detail = "нет HTTP-ответа"
		switch exit {
		case 6:
			r.Detail = "Не найден адрес сервера (DNS)"
		case 7:
			r.Detail = "Не удалось установить соединение"
		case 28:
			r.Detail = "Тайм-аут"
			if len(f) >= 5 {
				tcp, tcpErr := strconv.ParseFloat(f[3], 64)
				tls, tlsErr := strconv.ParseFloat(f[4], 64)
				if tcpErr == nil && tlsErr == nil {
					switch {
					case tls > 0:
						r.Detail += " после TLS, до HTTP-ответа"
					case tcp > 0:
						r.Detail += " после установки TCP-соединения"
					case tcp == 0 && tls == 0:
						r.Detail += " до подтверждения TCP-соединения"
					}
				}
			}
		case 35:
			r.Detail = "Ошибка TLS-рукопожатия"
		case 60:
			r.Detail = "Ошибка проверки сертификата"
		}
		if exit != 0 {
			r.Detail += fmt.Sprintf(" · curl %d", exit)
		}
		return r
	}
	if speed {
		if r.Seconds > 0 {
			r.Mbit = r.Bytes * 8 / 1e6 / max(0.2, r.Seconds)
		}
		// A tiny error page or a reset must never pass as video speed.
		r.OK = (exit == 0 || exit == 28) && r.Code[0] == '2' && r.Bytes >= 65536 && r.Mbit >= 1.5
		r.Detail = fmt.Sprintf("HTTP %s · %.0f КБ · %.2f с · %.1f Мбит/с (нужно ≥ 1,5)", r.Code, r.Bytes/1024, r.Seconds, r.Mbit)
		if r.Bytes < 65536 {
			r.Detail += " · получено меньше 64 КБ"
		}
	} else {
		r.OK = exit == 0
		r.Detail = fmt.Sprintf("HTTP %s · %.0f мс", r.Code, r.Seconds*1000)
	}
	if exit != 0 && !(speed && r.OK) {
		r.Detail += fmt.Sprintf(" · curl %d", exit)
	}
	return r
}
func zCurlArgs(address string) []string {
	return []string{"-q", "-4", "--http1.1", "-s", "--local-port", "42000-42099", "--interface", address, "--connect-timeout", "5", "--max-time", "12"}
}
func (m *zapret2) discoverVideo(address string) {
	if time.Since(m.videoAt) < 6*time.Hour && m.videoHost != "" && m.videoJS != "" {
		return
	}
	// Throttle failed discovery too, but retry after five minutes.
	if time.Since(m.videoAttempt) < 5*time.Minute {
		return
	}
	m.videoAttempt = time.Now()
	args := append(zCurlArgs(address), "--max-filesize", "8388608", "https://redirector.googlevideo.com/report_mapping?di=no")
	mapping, code := S.Run(15*time.Second, "", "curl", args...)
	if match := zVideoMapping.FindString(mapping); code == 0 && match != "" {
		m.videoHost = "rr1---" + match + ".googlevideo.com"
	}
	args = append(zCurlArgs(address), "-L", "--compressed", "--max-filesize", "8388608", "-A", "Mozilla/5.0", "https://www.youtube.com/")
	page, pageCode := S.Run(18*time.Second, "", "curl", args...)
	if pageCode == 0 {
		if path := zPlayerJS.FindString(strings.ReplaceAll(page, `\/`, `/`)); path != "" {
			m.videoJS = "https://www.youtube.com" + path
		}
		if m.videoHost == "" {
			m.videoHost = zVideoHostname.FindString(page)
		}
	}
	if m.videoHost == "" {
		args = append(zCurlArgs(address), "-L", "--compressed", "--max-filesize", "8388608", "https://www.youtube.com/watch?v=jNQXAC9IVRw")
		page, code = S.Run(18*time.Second, "", "curl", args...)
		if code == 0 {
			m.videoHost = zVideoHostname.FindString(page)
		}
	}
	if m.videoHost != "" || m.videoJS != "" {
		m.videoAt = time.Now()
	}
}

// Arbitrary target URLs may contain local names, credentials or signed paths.
func reportTarget(target string, index int) string {
	switch target {
	case "ytvideo":
		return "YouTube · видеосервер"
	case "ytspeed":
		return "YouTube · загрузка JS плеера"
	}
	for _, known := range strings.Split(zapretDefaultTargets, ",") {
		if target == known {
			return strings.TrimPrefix(known, "https://")
		}
	}
	return fmt.Sprintf("Своя цель №%d", index+1)
}

func (m *zapret2) checkTarget(address, target string) ([]string, string, bool) {
	label, url := target, target
	speed := target == "ytspeed"
	if speed {
		label = "YouTube: скорость загрузки (JS плеера)"
		url = m.videoJS
	}
	if target == "ytvideo" {
		label = "YouTube: видеосервер (googlevideo)"
		if m.videoHost != "" {
			url = "https://" + m.videoHost + "/generate_204"
		} else {
			url = ""
		}
	}
	if url == "" {
		return []string{label, "не проверено", "Не удалось определить адрес напрямую через zapret2"}, "не проверено · не удалось определить адрес цели", false
	}
	args := zCurlArgs(address)
	if speed {
		args = append(args, "-L", "--max-time", "18", "--max-filesize", "16777216", "-A", "Mozilla/5.0")
	} else {
		args = append(args, "-I")
	}
	args = append(args, "-o", "/dev/null", "-w", "%{http_code} %{size_download} %{time_total} %{time_connect} %{time_appconnect}", url)
	out, code := S.Run(22*time.Second, "", "curl", args...)
	r := parseZProbe(out, code, speed)
	state := "не проходит"
	if r.OK {
		state = "проходит"
	}
	return []string{label, state, r.Detail + " · " + url}, state + " · " + r.Detail, r.OK
}
