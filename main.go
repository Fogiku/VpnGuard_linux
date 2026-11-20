// VpnGuard для Linux (Ubuntu Server LTS). Запуск: vpnguard [--sim] [--listen адрес:порт] [--data папка] [--import папка].
// --sim — режим имитации: система не затрагивается, работает на любой ОС, включая Windows.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
)

var (
	errNoModule = errors.New("модуль не найден")
	errNoField  = errors.New("такой настройки у модуля нет")
	errNoSim    = errors.New("доступно только в режиме имитации")
)

func main() {
	sim := flag.Bool("sim", runtime.GOOS != "linux", "режим имитации: система не затрагивается")
	listen := flag.String("listen", "", "адрес веб-интерфейса (по умолчанию 127.0.0.1:8765, в имитации 127.0.0.1:8766)")
	data := flag.String("data", "", "папка данных (по умолчанию /var/lib/vpnguard, в имитации ./data-sim)")
	imp := flag.String("import", "", "перенести WG-Server из Windows-версии и выйти")
	writeWg := flag.Bool("write-wg-config", false, "вместе с --import записать /etc/wireguard; службы не запускать")
	version := flag.Bool("version", false, "показать версию и выйти")
	networkCheck := flag.Bool("check-network-settings", false, "проверить сетевые настройки без запуска служб")
	flag.Parse()
	if *version {
		fmt.Println(Version)
		return
	}
	if *writeWg && (*imp == "" || *sim || runtime.GOOS != "linux") {
		fmt.Fprintln(os.Stderr, "--write-wg-config требует --import на Linux без --sim")
		os.Exit(2)
	}
	Sim = *sim
	if runtime.GOOS != "linux" && !Sim {
		fmt.Println("На этой системе доступен только режим имитации: запустите с --sim")
		os.Exit(2)
	}
	DataDir, S = "/var/lib/vpnguard", realSys{}
	addr := "127.0.0.1:8765"
	if Sim {
		DataDir, S, addr = "data-sim", newSim(), "127.0.0.1:8766"
	}
	if *data != "" {
		DataDir = *data
	}
	if *listen != "" {
		addr = *listen
	}
	if err := os.MkdirAll(DataDir, 0o700); err != nil {
		fmt.Println("не удалось создать папку данных:", err)
		os.Exit(1)
	}
	loadCfg()
	if *networkCheck {
		if _, err := parseLocalNetworks(cfg("net.localNetworks", "")); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		pin := cfg("net.pinFlows", "false")
		if pin != "true" && pin != "false" {
			fmt.Fprintln(os.Stderr, "net.pinFlows: нужно true или false")
			os.Exit(2)
		}
		dnsSettings, err := readDNSClientSettings(nil)
		if err == nil {
			_, err = dnsSettings.plans(Sim)
		}
		if err == nil {
			err = validateWGExportDNS(cfg("wg.dns", "1.1.1.1"))
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Println("NETWORK_POLICY_OK")
		return
	}
	if err := recoverRoutesOnStartup(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	loadCfg()
	if *imp != "" {
		r, err := importWindows(*imp)
		if err != nil {
			fmt.Println("импорт не выполнен:", err)
			os.Exit(1)
		}
		if *writeWg {
			if err := os.MkdirAll("/etc/wireguard", 0o700); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if err := S.WriteFile(wgMod.confPath(), wgMod.conf(false), 0o600); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		fmt.Print(r)
		return
	}
	initTelemetry()
	initDNS()
	Log("INFO", "VpnGuard %s запущен (имитация: %v, данные: %s)", Version, Sim, DataDir)
	if Sim {
		seedSim()
	}
	routesStarting.Store(true)
	routeSimulationRunning = Sim
	routeAgentRunning = true
	startRoutes()
	startModules()
	startDiag()
	if Sim {
		fmt.Printf("VpnGuard %s — режим имитации. Откройте в браузере: http://%s/\n", Version, addr)
	}
	if err := startWeb(addr); err != nil {
		fmt.Println("веб-сервер не запустился:", err)
		os.Exit(1)
	}
}

// seedSim наполняет имитацию примером: шесть клиентов и три профиля.
func seedSim() {
	wgMod.ensure()
	if len(wgMod.d.Clients) > 0 {
		return
	}
	loadRoutes()
	for _, n := range []string{"Телефон", "Ноутбук", "Планшет", "Телевизор", "Приставка", "Рабочий ноутбук"} {
		_, _ = wgMod.add(n)
	}
	sub := wgMod.subnet()
	rt.Profiles = append(rt.Profiles,
		Profile{ID: "p2", Name: "Телевизоры", Rules: []Rule{{ID: "r1", Title: "YouTube и Discord", Preset: "yt", Exit: "zapret"}, {ID: "r2", Title: "Всё остальное", Exit: "direct", Last: true}}},
		Profile{ID: "p3", Name: "Работа", Rules: []Rule{{ID: "r1", Title: "Всё остальное", Exit: "awg", Last: true}}})
	rt.Profiles[0].Rules = []Rule{{ID: "r1", Title: "YouTube и Discord", Preset: "yt", Exit: "zapret"},
		{ID: "r3", Title: "Банки и госуслуги", Preset: "bank", Exit: "direct"}, {ID: "r2", Title: "Всё остальное", Exit: "meduza", Last: true}}
	rt.Clients = map[string]string{sub + ".5": "p2", sub + ".6": "p2", sub + ".7": "p3"}
	saveJSON("routes.json", rt)
	setCfg("wg.endpoint", "vpn.example.org")
}
