// Веб-сервер: страницы из папки web (встроены в исполняемый файл) и API. С этого компьютера — без пароля,
// из сети — по паролю web.token. Изменения принимаются только POST-запросом с заголовком X-VG.
package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"time"
)

//go:embed web
var webFS embed.FS

type ruleView struct {
	Rule
	Eff   string `json:"eff"`
	State string `json:"state"`
	Why   string `json:"why"`
}

func viewRules(rs []Rule) []ruleView {
	out := make([]ruleView, 0, len(rs))
	for _, r := range rs {
		e, s, w := resolveExit(r.Exit, rt.Policy)
		out = append(out, ruleView{r, e, s, w})
	}
	return out
}
func buildState() map[string]any {
	var mods, exits []map[string]any
	level, problems := 0, []string{}
	for _, m := range Mods {
		st := m.Status()
		if st.KV == nil {
			st.KV = [][2]string{}
		}
		if st.Level > 0 && m.ID() != "direct" && !isAux(m) {
			if st.Level > level {
				level = st.Level
			}
			problems = append(problems, m.Name()+": "+st.State)
		}
		acts := m.Actions()
		mods = append(mods, map[string]any{"id": m.ID(), "name": m.Name(), "color": m.Color(), "status": st, "fields": m.Fields(),
			"actions": acts, "tables": m.Tables(), "exit": m.Exit() != nil, "metrics": m.Metrics(), "page": hasPage(m), "fieldsTop": fieldsFirst(m), "aux": isAux(m)})
		if m.Exit() != nil {
			p, has := rt.Policy[m.ID()]
			exits = append(exits, map[string]any{"id": m.ID(), "name": m.Name(), "color": m.Color(), "up": st.Up, "level": st.Level, "state": st.State,
				"why": st.Why, "policy": m.ID() != "direct" && m.ID() != "block", "reserve": p.Reserve, "ifDown": map[bool]string{true: p.IfDown, false: "block"}[has && p.IfDown != ""]})
		}
	}
	applyMu.Lock()
	info, canRb := applyInfo, previousState != nil
	applyMu.Unlock()
	rtMu.Lock()
	var profs []map[string]any
	for _, p := range rt.Profiles {
		profs = append(profs, map[string]any{"id": p.ID, "name": p.Name, "rules": viewRules(p.Rules)})
	}
	var clients []map[string]any
	for _, c := range wgMod.Clients() {
		clients = append(clients, map[string]any{"ip": c.IP, "name": c.Name, "on": c.On, "off": c.Off, "tx": c.Tx, "rx": c.Rx, "seen": c.Seen,
			"profile": profileOf(c.IP), "overrides": viewRules(rt.Overrides[c.IP])})
	}
	rtMu.Unlock()
	var pres []map[string]string
	for _, k := range []string{"yt", "bank", "tg", "games"} {
		pres = append(pres, map[string]string{"id": k, "title": presets[k][0], "match": presets[k][1]})
	}
	title := []string{"Всё работает", "Есть предупреждения", "Сбой"}[level]
	resources, resourceErr := currentRouteResources()
	out := map[string]any{"version": Version, "sim": Sim, "routingReady": !routesStarting.Load(), "releases": releases, "updates": updateHistory(), "development": development, "time": time.Now().Format("15:04:05"), "modules": mods,
		"hero":      map[string]any{"level": level, "title": title, "text": strings.Join(problems, " · ")},
		"routes":    map[string]any{"profiles": profs, "clients": clients, "exits": exits, "presets": pres, "applyInfo": info, "canRollback": canRb, "pending": pendingRouteView(), "events": routeHistory()},
		"decisions": snapshotLog(&decRing)}
	out["routeResources"] = resources
	out["networkTelemetry"] = networkTelemetryView()
	out["dnsService"] = dnsMod.clientStatus()
	if resourceErr != nil {
		out["routeResourceError"] = resourceErr.Error()
	}
	if sim, ok := S.(*simSys); ok {
		f := sim.Faults()
		var fl []map[string]any
		for _, x := range simFaults {
			fl = append(fl, map[string]any{"id": x[0], "title": x[1], "on": f[x[0]]})
		}
		out["faults"] = fl
	}
	return out
}
func webToken() string {
	t := cfg("web.token", "")
	if t == "" {
		b := make([]byte, 9)
		_, _ = rand.Read(b)
		t = hex.EncodeToString(b)
		setCfg("web.token", t)
	}
	return t
}
func allowed(r *http.Request) bool {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	if c, err := r.Cookie("vg"); err == nil && c.Value == webToken() {
		return true
	}
	return r.Header.Get("X-VG-Token") == webToken()
}
func startWeb(listen string) error {
	listenAddr = listen
	mux := http.NewServeMux()
	sub, _ := fs.Sub(webFS, "web")
	files := http.FileServer(http.FS(sub))
	// удалённая диагностика: запросы с заголовком X-Token (корень — список отчётов), веб-интерфейс — без него
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && r.Header.Get("X-Token") != "" {
			remoteServe(w, r)
			return
		}
		files.ServeHTTP(w, r)
	})
	for _, p := range remotePaths[1:] {
		mux.HandleFunc(p, remoteServe)
	}
	js := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(v)
	}
	// api: get — чтение, post — изменение (нужен заголовок X-VG, защита от запросов с чужих сайтов)
	api := func(path string, post bool, h func(body map[string]json.RawMessage) (any, error)) {
		mux.HandleFunc("/api/"+path, func(w http.ResponseWriter, r *http.Request) {
			if !allowed(r) {
				w.WriteHeader(http.StatusUnauthorized)
				js(w, map[string]string{"error": "нужен пароль"})
				return
			}
			body := map[string]json.RawMessage{}
			if post {
				if r.Method != http.MethodPost || r.Header.Get("X-VG") == "" {
					w.WriteHeader(http.StatusForbidden)
					js(w, map[string]string{"error": "изменения принимаются только POST-запросом из веб-интерфейса"})
					return
				}
				_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body)
			}
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			body["_remoteIP"], _ = json.Marshal(host)
			body["_routeProtocol"], _ = json.Marshal(r.Header.Get("X-VG-Route-Confirm"))
			res, err := h(body)
			if err != nil {
				js(w, map[string]any{"error": err.Error()})
				return
			}
			js(w, map[string]any{"ok": true, "result": res})
		})
	}
	str := func(b map[string]json.RawMessage, k string) string {
		var s string
		_ = json.Unmarshal(b[k], &s)
		return s
	}
	routeProtocol := func(body map[string]json.RawMessage) error {
		if str(body, "_routeProtocol") != "1" {
			return fmt.Errorf("обновите страницу перед изменением маршрутов: требуется автоматическая проверка связи после применения")
		}
		return nil
	}
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.FormValue("token") == webToken() {
			http.SetCookie(w, &http.Cookie{Name: "vg", Value: webToken(), Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 86400 * 30})
			js(w, map[string]any{"ok": true})
			return
		}
		time.Sleep(time.Second)
		w.WriteHeader(http.StatusUnauthorized)
		js(w, map[string]string{"error": "неверный пароль"})
	})
	api("repository/check", false, func(map[string]json.RawMessage) (any, error) {
		r, err := fetchRelease()
		if err != nil {
			return nil, err
		}
		return map[string]any{"version": r.Version, "available": newerRelease(r.Version, Version)}, nil
	})
	api("repository/install", true, func(b map[string]json.RawMessage) (any, error) {
		return "Обновление запущено", startRepositoryUpdate(str(b, "version"), str(b, "_remoteIP"))
	})
	api("repository/confirm", true, func(b map[string]json.RawMessage) (any, error) {
		return "Обновление подтверждено", confirmRepositoryUpdate(str(b, "job"), str(b, "_remoteIP"))
	})
	api("meduzalocations", false, func(map[string]json.RawMessage) (any, error) {
		m, ok := mod("meduza").(*meduza)
		if !ok {
			return nil, errNoModule
		}
		return m.locationAction()
	})
	api("state", false, func(body map[string]json.RawMessage) (any, error) {
		state := buildState()
		state["clientIP"] = str(body, "_remoteIP")
		if !Sim {
			if receipt, err := readInstallReceipt(); err == nil {
				state["repositoryInstall"] = map[string]any{"status": receipt.Status, "version": receipt.Version, "job": receipt.Job, "message": receipt.Message, "canConfirm": receipt.Job != "" && receipt.Version == Version && receipt.Status == "installed" && receipt.Requester == state["clientIP"]}
			}
		}
		return state, nil
	})
	api("log", false, func(map[string]json.RawMessage) (any, error) { return snapshotLog(&logRing), nil })
	api("nft", false, func(map[string]json.RawMessage) (any, error) {
		s, ip := Compile()
		return map[string]any{"script": s, "ip": ip}, nil
	})
	api("diag", false, func(map[string]json.RawMessage) (any, error) {
		diagMu.Lock()
		defer diagMu.Unlock()
		return diagRes, nil
	})
	api("history", false, func(map[string]json.RawMessage) (any, error) {
		store := telemetry
		if store == nil {
			store = &historyStore{}
		}
		return store.view(time.Now().Unix()), nil
	})
	api("diagrun", true, func(map[string]json.RawMessage) (any, error) { return runChecks(), nil })
	api("fix", true, func(b map[string]json.RawMessage) (any, error) { return fixCheck(str(b, "id")) })
	api("rollback", true, func(body map[string]json.RawMessage) (any, error) {
		if err := routeProtocol(body); err != nil {
			return nil, err
		}
		return "Правила возвращены к предыдущему набору", RollbackFrom(str(body, "_remoteIP"))
	})
	api("routeconfirm", true, func(body map[string]json.RawMessage) (any, error) {
		return "Связь после изменения маршрутов подтверждена", confirmRouteChangeFrom(str(body, "id"), str(body, "_remoteIP"))
	})
	api("do", true, func(b map[string]json.RawMessage) (any, error) {
		m := mod(str(b, "module"))
		if m == nil {
			return nil, errNoModule
		}
		if m.ID() == "wg" {
			applyMu.Lock()
			defer applyMu.Unlock()
			if hasRoutePending() {
				return nil, errRoutePending
			}
		}
		args := map[string]string{}
		_ = json.Unmarshal(b["args"], &args)
		msg, err := m.Do(str(b, "action"), args)
		if err == nil {
			Log("INFO", "веб: %s → %s: %s", m.Name(), str(b, "action"), msg)
		}
		return msg, err
	})
	api("set", true, func(b map[string]json.RawMessage) (any, error) {
		m := mod(str(b, "module"))
		if m == nil {
			return nil, errNoModule
		}
		if m.ID() == "wg" {
			applyMu.Lock()
			defer applyMu.Unlock()
			if hasRoutePending() {
				return nil, errRoutePending
			}
		}
		key := str(b, "key")
		for _, f := range m.Fields() { // менять можно только поля, которые модуль сам объявил
			if f.Key == key {
				Log("INFO", "веб: настройка %s изменена", key)
				if m.ID() == "inet" && (key == "net.pinFlows" || key == "net.localNetworks") {
					if err := routeProtocol(b); err != nil {
						return nil, err
					}
					return "Сохранено, проверяется связь", setNetworkPolicyFrom(key, str(b, "value"), str(b, "_remoteIP"))
				}
				return "Сохранено", m.Set(key, str(b, "value"))
			}
		}
		return nil, errNoField
	})
	api("routes", true, func(b map[string]json.RawMessage) (any, error) {
		if err := routeProtocol(b); err != nil {
			return nil, err
		}
		var n Routes
		if err := json.Unmarshal(b["routes"], &n); err != nil {
			return nil, err
		}
		return "Маршруты применены, проверяется связь", setRoutesFrom(n, str(b, "_remoteIP"))
	})
	api("sim", true, func(b map[string]json.RawMessage) (any, error) {
		sim, ok := S.(*simSys)
		if !ok {
			return nil, errNoSim
		}
		var on bool
		_ = json.Unmarshal(b["on"], &on)
		sim.SetFault(str(b, "id"), on)
		for _, m := range Mods {
			go m.Tick()
		}
		return "Имитация: состояние изменено", nil
	})
	Log("INFO", "веб-интерфейс: http://%s/", listen)
	return http.ListenAndServe(listen, mux)
}
