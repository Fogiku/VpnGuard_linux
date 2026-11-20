#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [string]$WindowsRoot = '',
    [int]$TargetDiskNumber = -1,
    [switch]$InstallAmneziaWG,
    [switch]$CheckOnly,
    [string]$CancelBootOption = ''
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Capture-Windows.ps1')
Add-Type -Path (Join-Path $PSScriptRoot 'UefiBoot.cs')
if ($CancelBootOption) {
    if ($PSCmdlet.ShouldProcess($CancelBootOption, 'Отменить однократную загрузку USB')) { [VpnGuardUefiBoot]::Cancel($CancelBootOption) }
    return
}
$root = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$letter = [IO.Path]::GetPathRoot($root).Substring(0,1)
$usbPart = Get-Partition -DriveLetter $letter
$usb = Get-Disk -Number $usbPart.DiskNumber
if ($usb.BusType -ne 'USB' -or $usb.PartitionStyle -ne 'GPT' -or $usb.IsBoot -or $usb.IsSystem) { throw 'Запустите скрипт с подготовленной USB-флешки' }
if (($usbPart | Get-Volume).FileSystem -ne 'FAT32') { throw 'UEFI раздел должен быть FAT32' }
if (-not (Test-Path -LiteralPath (Join-Path $root 'EFI\BOOT\BOOTX64.EFI'))) { throw 'Нет загрузчика флешки' }
$meta = Get-Content -LiteralPath (Join-Path $root 'bundle.json') -Raw -Encoding UTF8 | ConvertFrom-Json
foreach ($pair in @(@('autoinstall.yaml',$meta.autoinstallSha256), @('vpnguard\manifest.json',$meta.manifestSha256), @('nocloud\user-data',$meta.seedSha256), @('nocloud\meta-data',$meta.seedMetaSha256))) {
    if ((Get-FileHash -LiteralPath (Join-Path $root $pair[0]) -Algorithm SHA256).Hash -ne $pair[1]) { throw 'Комплект повреждён' }
}
$manifest = Get-Content -LiteralPath (Join-Path $root 'vpnguard\manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$payload = [IO.Path]::GetFullPath((Join-Path $root 'vpnguard')) + '\'
foreach ($p in $manifest.PSObject.Properties) {
    $file = [IO.Path]::GetFullPath((Join-Path $payload $p.Name))
    if (-not $file.StartsWith($payload, [StringComparison]::OrdinalIgnoreCase)) { throw 'Недопустимый путь в manifest' }
    if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $p.Value) { throw "Комплект повреждён: $($p.Name)" }
}
if ($TargetDiskNumber -lt 0) {
    $osPart = Get-Partition -DriveLetter $env:SystemDrive.Substring(0,1)
    $TargetDiskNumber = $osPart.DiskNumber
}
$target = Get-Disk -Number $TargetDiskNumber
if ($meta.captureReady -and $meta.diskSerial -cne $target.SerialNumber.Trim()) { throw 'Captured USB is bound to another computer; do not run START-INSTALL on the preparation PC' }
if (-not $target.SerialNumber -or $target.BusType -eq 'USB' -or $target.Number -eq $usb.Number -or $target.Size -lt 32GB) { throw 'Недопустимый целевой диск' }
if ($target.SerialNumber.Trim() -match '[*?\[\]\r\n]') { throw 'Неоднозначный серийный номер целевого диска' }
$network = Get-VgNetwork
$WindowsRoot = Find-VgRoot $WindowsRoot
if ($InstallAmneziaWG -and (Confirm-SecureBootUEFI)) { throw 'Для AmneziaWG нужен выключенный Secure Boot. Без -InstallAmneziaWG отключать его не нужно.' }
[VpnGuardUefiBoot]::Enable()
Write-Host "VpnGuard: $WindowsRoot"
Write-Host "Будет полностью стёрт диск $($TargetDiskNumber): $($target.FriendlyName), $($target.SerialNumber)"
Write-Host "После установки откройте: http://$($network.ip):8765/"
Write-Host 'AmneziaWG по умолчанию не устанавливается. MeduzaVPN будет ждать входа.'
if ($CheckOnly) { Write-Host 'Только проверка: файлы и BootNext не изменялись.'; return }
if (-not $PSCmdlet.ShouldProcess($target.SerialNumber, 'Собрать актуальные настройки на USB и назначить установку Ubuntu вместо Windows на следующую перезагрузку')) { return }
$settings = Save-VgCapture $root $WindowsRoot $target $network ([bool]$InstallAmneziaWG)
$sector = [uint64]$usb.LogicalSectorSize
if ($sector -eq 0 -or $usbPart.Offset % $sector -or $usbPart.Size % $sector) { throw 'Неверная геометрия USB-раздела' }
$id = [VpnGuardUefiBoot]::Arm([uint32]$usbPart.PartitionNumber, [uint64]($usbPart.Offset / $sector), [uint64]($usbPart.Size / $sector), [string]$usbPart.Guid)
Write-Host "Готово. Однократная загрузка флешки назначена: $id"
Write-Host "Отмена до перезагрузки: .\Start-UsbInstall.ps1 -CancelBootOption $id"
Write-Host 'Теперь перезагрузите ПК вручную и дождитесь установки.'
Write-Host "Затем: http://$($network.ip):8765/ . Пароль записан на флешке в AFTER-INSTALL.txt."
Write-Host 'Настройки и закрытые ключи скопированы на флешку; не публикуйте её содержимое.'
