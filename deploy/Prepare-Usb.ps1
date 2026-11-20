#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true)][string]$IsoPath,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$IsoSha256,
    [Parameter(Mandatory=$true)][string]$BundlePath,
    [Parameter(Mandatory=$true)][int]$UsbDiskNumber,
    [Parameter(Mandatory=$true)][string]$EraseUsbSerial
)
$ErrorActionPreference = 'Stop'
function Initialize-VgUsbPartitionTable([int]$DiskNumber, [string]$ExpectedSerial) {
    $current = Get-Disk -Number $DiskNumber
    if (-not $current.SerialNumber -or $current.SerialNumber.Trim() -cne $ExpectedSerial.Trim() -or $current.IsBoot -or $current.IsSystem -or $current.BusType -ne 'USB') {
        throw 'USB-диск изменился после очистки; подготовка остановлена'
    }
    if (@(Get-Partition -DiskNumber $DiskNumber -ErrorAction SilentlyContinue).Count -gt 0) {
        throw 'На USB остались разделы; изменение таблицы разделов остановлено'
    }
    switch ([string]$current.PartitionStyle) {
        'RAW' { Initialize-Disk -Number $DiskNumber -PartitionStyle GPT | Out-Null }
        'MBR' { Set-Disk -Number $DiskNumber -PartitionStyle GPT | Out-Null }
        'GPT' { } # Clear-Disk may keep an already initialized GPT disk.
        default { throw "Неизвестный стиль разделов USB: $($current.PartitionStyle)" }
    }
    $verified = Get-Disk -Number $DiskNumber
    if (-not $verified.SerialNumber -or $verified.SerialNumber.Trim() -cne $ExpectedSerial.Trim() -or $verified.PartitionStyle -ne 'GPT' -or $verified.IsBoot -or $verified.IsSystem -or $verified.BusType -ne 'USB') {
        throw 'Не удалось подтвердить GPT на выбранной флешке'
    }
}

$bundle = (Resolve-Path -LiteralPath $BundlePath).Path
$iso = (Resolve-Path -LiteralPath $IsoPath).Path
$meta = Get-Content -LiteralPath (Join-Path $bundle 'bundle.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ((Get-FileHash -LiteralPath $iso -Algorithm SHA256).Hash -ne $IsoSha256) { throw 'SHA256 ISO не совпадает' }
foreach ($item in @(@('autoinstall.yaml', $meta.autoinstallSha256), @('vpnguard\manifest.json', $meta.manifestSha256), @('nocloud\user-data', $meta.seedSha256), @('nocloud\meta-data', $meta.seedMetaSha256))) {
    if ((Get-FileHash -LiteralPath (Join-Path $bundle $item[0]) -Algorithm SHA256).Hash -ne $item[1]) { throw "Комплект повреждён: $($item[0])" }
}
$disk = Get-Disk -Number $UsbDiskNumber
if ($disk.IsBoot -or $disk.IsSystem -or $disk.BusType -ne 'USB') { throw 'Выбран не USB-диск либо системный диск' }
if (-not $EraseUsbSerial.Trim() -or $disk.SerialNumber.Trim() -cne $EraseUsbSerial.Trim()) { throw 'Серийный номер USB не совпадает' }
if ($disk.SerialNumber.Trim() -ceq $meta.diskSerial) { throw 'USB совпадает с диском установки Ubuntu' }
# Do not format a drive containing the ISO or prepared payload.
foreach ($path in @($bundle, $iso)) {
    $letter = [IO.Path]::GetPathRoot($path).TrimEnd('\').TrimEnd(':')
    if ($letter.Length -eq 1) {
        $sourcePart = Get-Partition -DriveLetter $letter
        if ($sourcePart.DiskNumber -eq $UsbDiskNumber) { throw 'На USB находятся исходные файлы комплекта или ISO' }
    }
}
$mountedHere = $false
try {
    $image = Get-DiskImage -ImagePath $iso
    if (-not $image.Attached) { $image = Mount-DiskImage -ImagePath $iso -PassThru; $mountedHere = $true }
    $volume = $image | Get-Volume
    $source = "$($volume.DriveLetter):\"
    if (-not (Test-Path -LiteralPath (Join-Path $source 'EFI\BOOT\BOOTX64.EFI'))) { throw 'ISO не содержит UEFI x64 загрузчик' }
    if (-not (Test-Path -LiteralPath (Join-Path $source 'casper\install-sources.yaml'))) { throw 'Нужен Ubuntu Server 24.04 amd64 ISO' }
    if (Get-ChildItem -LiteralPath $source -File -Recurse | Where-Object Length -GT 4294967295) { throw 'В ISO есть файл больше 4 GiB: FAT32 не подходит; этот ISO не поддерживается' }
    $need = (Get-ChildItem -LiteralPath $source -File -Recurse | Measure-Object Length -Sum).Sum +
            (Get-ChildItem -LiteralPath $bundle -File -Recurse | Measure-Object Length -Sum).Sum + 1GB
    $partSize = [Math]::Min(28GB, [double]$disk.Size - 16MB)
    if ($need -gt $partSize) { throw 'Комплект не помещается в FAT32-раздел флешки' }
    if (-not $PSCmdlet.ShouldProcess("USB $UsbDiskNumber / $EraseUsbSerial", 'Удалить все разделы USB и записать установщик Ubuntu')) { return }
    # Re-read identity immediately before mutation.
    $again = Get-Disk -Number $UsbDiskNumber
    if ($again.SerialNumber.Trim() -cne $EraseUsbSerial.Trim() -or $again.IsBoot -or $again.IsSystem -or $again.BusType -ne 'USB') { throw 'USB-диск изменился' }
    $again | Clear-Disk -RemoveData -RemoveOEM -Confirm:$false
    Initialize-VgUsbPartitionTable -DiskNumber $UsbDiskNumber -ExpectedSerial $EraseUsbSerial
    $part = New-Partition -DiskNumber $UsbDiskNumber -Size $partSize -GptType '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}' -AssignDriveLetter
    $part | Format-Volume -FileSystem FAT32 -NewFileSystemLabel 'VPNGUARD' -Confirm:$false | Out-Null
    $dest = "$($part.DriveLetter):\"
    # Include hidden .disk metadata from the Ubuntu ISO.
    Get-ChildItem -LiteralPath $source -Force | Copy-Item -Destination $dest -Recurse -Force
    Get-ChildItem -LiteralPath $bundle -Force | Copy-Item -Destination $dest -Recurse -Force
    $grub = Join-Path $dest 'boot\grub\grub.cfg'
    (Get-Item -LiteralPath $grub).IsReadOnly = $false
    $text = Get-Content -LiteralPath $grub -Raw
    $text = [regex]::Replace($text, '(?m)^set timeout=.*$', 'set timeout=0')
    $text = [regex]::Replace($text, '(?m)^(\s*linux\s+/casper/(?:hwe-)?vmlinuz[^\r\n]*?)(\s+---[^\r\n]*)$', '$1 autoinstall ds=nocloud\;s=/cdrom/nocloud/$2')
    if ($text -notmatch 'autoinstall') { throw 'Не удалось добавить параметр autoinstall в GRUB' }
    [IO.File]::WriteAllText($grub, $text, (New-Object Text.UTF8Encoding($false)))
    $sumsPath = Join-Path $dest 'md5sum.txt'
    (Get-Item -LiteralPath $sumsPath).IsReadOnly = $false
    $sums = Get-Content -LiteralPath $sumsPath -Raw
    if ($sums -notmatch '(?m)^[0-9a-f]{32}  \./boot/grub/grub\.cfg$') { throw 'No GRUB entry in media checksums' }
    $grubMd5 = (Get-FileHash -LiteralPath $grub -Algorithm MD5).Hash.ToLowerInvariant()
    $sums = [regex]::Replace($sums, '(?m)^[0-9a-f]{32}(  \./boot/grub/grub\.cfg)$', $grubMd5+'$1')
    [IO.File]::WriteAllText($sumsPath, $sums, (New-Object Text.UTF8Encoding($false)))
    Write-Host "Флешка готова: $dest. Загрузка ещё не назначена."
    Write-Host "На ЦЕЛЕВОМ ПК запустите с флешки START-INSTALL.cmd."
} finally {
    if ($mountedHere) { Dismount-DiskImage -ImagePath $iso }
}
