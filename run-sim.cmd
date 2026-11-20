@echo off
rem VpnGuard для Linux: режим имитации. Систему не затрагивает, работает рядом с обычным VpnGuard (порт 8766).
cd /d "%~dp0"
start "" http://127.0.0.1:8766/
bin\vpnguard.exe --sim
