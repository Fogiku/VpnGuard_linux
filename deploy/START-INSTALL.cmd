@echo off
setlocal
set "VPNGUARD_USB_ROOT=%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$script = Join-Path $env:VPNGUARD_USB_ROOT 'Start-UsbInstall.ps1'; Start-Process -FilePath powershell.exe -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -NoExit -File ""' + $script + '""')"
