#Requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$Validator)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Capture-Windows.ps1')
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('vpnguard-capture-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
$oldProgramData=$env:ProgramData
try {
    $env:ProgramData=Join-Path $testRoot 'programdata'
    $win=Join-Path $testRoot 'windows'
    $usb=Join-Path $testRoot 'usb'
    $payload=Join-Path $usb 'vpnguard'
    foreach ($dir in @("$win\data\wg","$win\data\clients","$payload\tools","$payload\migration")) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    Copy-Item -LiteralPath $Validator -Destination "$payload\tools\validator.exe"
    $key=[Convert]::ToBase64String([byte[]](1..32))
    $pub=[Convert]::ToBase64String([byte[]](2..33))
    $conf="[Interface]" + [Environment]::NewLine + "Address = 192.168.15.1/24" + [Environment]::NewLine +
        "ListenPort = 51820" + [Environment]::NewLine + "PrivateKey = $key" + [Environment]::NewLine +
        "[Peer]" + [Environment]::NewLine + "# Name = Router" + [Environment]::NewLine +
        "PublicKey = $pub" + [Environment]::NewLine + "AllowedIPs = 192.168.15.2"
    [IO.File]::WriteAllText("$win\data\wg\wg_server.conf",$conf)
    Write-VgJson "$win\config.json" @{wg=@{endpoint='home.example.test';clientOff=@('192.168.15.2')}}
    Write-VgJson "$payload\install.json" @{
        schema=2;captureReady=$false;diskSerial='UNARMED';wanMac='00:00:00:00:00:00'
        username='vpnadmin';installAwg=$false;awgEnabled=$false;migrationDir='migration'
    }
    Write-VgJson "$usb\autoinstall.yaml" @{
        autoinstall=@{
            storage=@{layout=@{match=@{serial='UNARMED'}}}
            network=@{ethernets=@{wan=@{dhcp4=$true}}}
        }
    }
    New-Item -ItemType Directory -Path "$usb\nocloud" -Force | Out-Null
    [IO.File]::WriteAllText("$usb\nocloud\user-data", '#cloud-config'+"`n"+'{"autoinstall":{}}')
    $net=[pscustomobject]@{mac='00:11:22:33:44:55';ip='192.168.1.66';prefix=24;gateway='192.168.1.1';dns=@('1.1.1.1')}
    $disk=[pscustomobject]@{SerialNumber='TEST-SSD'}
    $settings=Save-VgCapture $usb $win $disk $net $false
    if (-not $settings.captureReady -or $settings.installAwg -or $settings.diskSerial -ne 'TEST-SSD') { throw 'Bad capture settings' }
    $ai=Get-Content "$usb\autoinstall.yaml" -Raw | ConvertFrom-Json
    if ($ai.autoinstall.network.ethernets.wan.addresses[0] -ne '192.168.1.66/24') { throw 'LAN IP was not preserved' }
    if (-not $ai.autoinstall.network.ethernets.wan.dhcp4) { throw 'Expected DHCP alongside retained static IPv4' }
    $migration=Join-Path $payload $settings.migrationDir
    $data=Get-Content "$migration\validated\wg.json" -Raw | ConvertFrom-Json
    if (-not $data.Clients[0].off) { throw 'Disabled Windows client was re-enabled' }
    if (Test-Path "$usb\CAPTURE-INCOMPLETE") { throw 'Success did not clear marker' }
    if (-not (Test-Path "$usb\AFTER-INSTALL.txt")) { throw 'No access instructions' }
    $manifest=Get-Content "$payload\manifest.json" -Raw | ConvertFrom-Json
    foreach ($p in $manifest.PSObject.Properties) {
        if ((Get-FileHash -LiteralPath (Join-Path $payload $p.Name)).Hash -ne $p.Value) { throw 'Capture manifest mismatch' }
    }
    $bundle = Get-Content "$usb\bundle.json" -Raw -Encoding UTF8 | ConvertFrom-Json
    if ((Get-FileHash "$usb\nocloud\user-data").Hash -ne $bundle.seedSha256) { throw 'Seed checksum mismatch' }
    $seed = ((Get-Content "$usb\nocloud\user-data" -Raw -Encoding UTF8) -replace '^#cloud-config\r?\n','') | ConvertFrom-Json
    if ($seed.autoinstall.storage.layout.match.serial -ne $disk.SerialNumber) { throw 'Seed target differs from capture' }
    if ($seed.autoinstall.network.ethernets.wan.addresses[0] -ne '192.168.1.66/24') { throw 'Seed network differs from capture' }
    # A conflicting snapshot must stop before the caller can arm BootNext.
    $external="$env:ProgramData\VpnGuard\clients"
    New-Item -ItemType Directory -Path $external -Force | Out-Null
    [IO.File]::WriteAllText("$win\data\clients\same.conf",'a')
    [IO.File]::WriteAllText("$external\same.conf",'b')
    $rejected=$false
    try { Save-VgCapture $usb $win $disk $net $false | Out-Null } catch { $rejected=$true }
    if (-not $rejected -or -not (Test-Path "$usb\CAPTURE-INCOMPLETE")) { throw 'Incomplete capture was not blocked' }
    Write-Output 'Capture integration tests passed; no disk, service or firmware operations executed.'
} finally {
    $env:ProgramData=$oldProgramData
    $full=[IO.Path]::GetFullPath($testRoot)
    $temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
    if (-not $full.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected test cleanup path' }
    Remove-Item -LiteralPath $full -Recurse -Force
}
