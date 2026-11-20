@echo off
setlocal
set "VPNGUARD_WRITE_SCRIPT=%~dp0WRITE-USB.ps1"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$p = $env:VPNGUARD_WRITE_SCRIPT; Start-Process -FilePath powershell.exe -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -NoExit -File ""' + $p + '""')"
