#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([int]$UsbDiskNumber=-1, [string]$EraseUsbSerial='')
$ErrorActionPreference='Stop'
Get-Disk | Where-Object BusType -EQ 'USB' | Format-Table Number,FriendlyName,SerialNumber,Size,IsBoot,IsSystem
if ($UsbDiskNumber -lt 0) { $UsbDiskNumber=[int](Read-Host 'Номер USB-диска из таблицы') }
if (-not $EraseUsbSerial) { $EraseUsbSerial=Read-Host 'Серийный номер USB из таблицы (его содержимое будет удалено)' }
$root=$PSScriptRoot
$iso=Join-Path $root 'ubuntu-24.04.5-live-server-amd64.iso'
$bundle=Join-Path $root 'usb-kit'
& (Join-Path $bundle 'Prepare-Usb.ps1') -IsoPath $iso -IsoSha256 '97f3d7ffb032c3eb3b23d2c8be9cc76e60c2c1f2c0146ba5ba9fe01cafae0fd8' -BundlePath $bundle -UsbDiskNumber $UsbDiskNumber -EraseUsbSerial $EraseUsbSerial
