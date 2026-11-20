# Shared helpers. Loading this file does not change disks or firmware.
Set-StrictMode -Version 2.0
function Get-VgValue($Object, [string]$Name, $Default = $null) {
    if ($null -ne $Object -and $Object.PSObject.Properties[$Name]) { return $Object.$Name }; return $Default
}
function Write-VgJson([string]$Path, $Value) {
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 100), (New-Object Text.UTF8Encoding($false)))
}
function New-VgSecret {
    $bytes = New-Object byte[] 24
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return -join ($bytes | ForEach-Object { $_.ToString('x2') })
}
function Find-VgRoot([string]$Explicit) {
    if ($Explicit) {
        $resolved = (Resolve-Path -LiteralPath $Explicit).Path
        if (-not (Test-Path -LiteralPath (Join-Path $resolved 'config.json'))) { throw 'Нет config.json в папке VpnGuard' }
        return $resolved
    }
    $candidates = @("$env:SystemDrive\VpnGuard", "$env:SystemDrive\auto_contol_vpn", "$env:ProgramData\VpnGuard")
    foreach ($pr in @(Get-CimInstance Win32_Process -Filter "Name='VpnGuardAgent.exe' OR Name='VpnGuardWeb.exe'" -ErrorAction SilentlyContinue)) {
        if ($pr.ExecutablePath) { $candidates += Split-Path -Parent (Split-Path -Parent $pr.ExecutablePath) }
    }
    foreach ($task in @(Get-ScheduledTask -TaskName '*VpnGuard*' -ErrorAction SilentlyContinue)) {
        foreach ($action in $task.Actions) {
            if ($action.Arguments -match '(?i)"([^"]*\\VpnGuard\.ps1)"') { $candidates += Split-Path -Parent $matches[1] }
        }
    }
    $found = @($candidates | Where-Object { $_ -and (Test-Path -LiteralPath (Join-Path $_ 'config.json')) } | ForEach-Object { (Resolve-Path -LiteralPath $_).Path } | Select-Object -Unique)
    if ($found.Count -ne 1) { throw 'Укажите папку рабочего VpnGuard: -WindowsRoot ПАПКА' }
    return $found[0]
}
function Find-VgServer([string]$WindowsRoot, $Config) {
    $wg = Get-VgValue $Config 'wg' (Get-VgValue $Config 'ws4w')
    $paths = @()
    $configured = Get-VgValue $wg 'configPath' ''
    if ($configured) {
        if (-not [IO.Path]::IsPathRooted($configured)) { $configured = Join-Path $WindowsRoot $configured }
        $paths += $configured
    }
    $statusPath = Join-Path $WindowsRoot 'data\status.json'
    if (Test-Path -LiteralPath $statusPath) {
        $status = Get-Content -LiteralPath $statusPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $statusConf = Get-VgValue $status 'wgConfPath' ''
        if ($statusConf) { $paths += $statusConf }
    }
    $paths += Join-Path $WindowsRoot 'data\wg\wg_server.conf'
    foreach ($p in $paths) {
        if (Test-Path -LiteralPath $p -PathType Leaf) { return (Resolve-Path -LiteralPath $p).Path }
    }
    throw 'Не найден wg_server.conf с настоящими ключами'
}
function Get-VgNetwork {
    $physical = @(Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' -and (Get-VgValue $_ 'NdisPhysicalMedium' 0) -eq 14 })
    foreach ($route in @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric)) {
        $adapter = @($physical | Where-Object ifIndex -EQ $route.InterfaceIndex)
        if ($adapter.Count -ne 1) { continue }
        $ips = @(Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 |
            Where-Object { $_.AddressState -eq 'Preferred' -and $_.IPAddress -notlike '169.254.*' -and -not $_.SkipAsSource })
        if ($ips.Count -ne 1) { continue }
        $dns = @((Get-DnsClientServerAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4).ServerAddresses)
        if (-not $dns.Count) { $dns = @('1.1.1.1','8.8.8.8') }
        return [pscustomobject]@{
            mac = $adapter[0].MacAddress.Replace('-',':').ToLowerInvariant()
            ip = $ips[0].IPAddress; prefix = [int]$ips[0].PrefixLength
            gateway = $route.NextHop; dns = $dns
        }
    }
    throw 'Не найден физический адаптер с одним IPv4-адресом и шлюзом'
}
function Save-VgCapture([string]$UsbRoot, [string]$WindowsRoot, $TargetDisk, $Network, [bool]$InstallAwg) {
    $payload = Join-Path $UsbRoot 'vpnguard'
    $settings = Get-Content -LiteralPath (Join-Path $payload 'install.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $marker = Join-Path $UsbRoot 'CAPTURE-INCOMPLETE'
    [IO.File]::WriteAllText($marker, 'Capture in progress')
    $configPath = Join-Path $WindowsRoot 'config.json'
    $config = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $server = Find-VgServer $WindowsRoot $config
    $relative = 'migration/' + [Guid]::NewGuid().ToString('N')
    $stage = Join-Path $payload $relative
    New-Item -ItemType Directory -Path (Join-Path $stage 'clients') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $stage 'awg') -Force | Out-Null
    Copy-Item -LiteralPath $configPath -Destination (Join-Path $stage 'config.json')
    Copy-Item -LiteralPath $server -Destination (Join-Path $stage 'wg_server.conf')
    foreach ($dir in @((Join-Path $WindowsRoot 'data\clients'), "$env:ProgramData\VpnGuard\clients")) {
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $dir -Filter '*.conf' -File)) {
            $dest = Join-Path $stage ('clients\' + $file.Name)
            if ((Test-Path -LiteralPath $dest) -and (Get-FileHash -LiteralPath $dest).Hash -ne (Get-FileHash -LiteralPath $file.FullName).Hash) {
                throw "Разные конфигурации клиентов с именем $($file.Name)"
            }
            Copy-Item -LiteralPath $file.FullName -Destination $dest -Force
        }
    }
    $awgDir = Join-Path $WindowsRoot 'data\amnezia'
    if (Test-Path -LiteralPath $awgDir) {
        foreach ($file in @(Get-ChildItem -LiteralPath $awgDir -Filter '*.conf' -File)) {
            Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $stage ('awg\' + $file.Name))
        }
    }
    & (Join-Path $payload 'tools\validator.exe') --sim --data (Join-Path $stage 'validated') --import $stage | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Импорт не прошёл проверку. Загрузка USB не назначена; Windows работает.' }
    $settings.diskSerial = $TargetDisk.SerialNumber.Trim()
    $settings.wanMac = $Network.mac; $settings.installAwg = $InstallAwg
    $settings.awgEnabled = $false; $settings.migrationDir = $relative
    foreach ($pair in @{
        webToken = (Get-VgValue $settings 'consolePassword' (New-VgSecret)); remoteToken = (New-VgSecret)
        lanIp = $Network.ip; lanPrefix = $Network.prefix; lanGateway = $Network.gateway
    }.GetEnumerator()) {
        $settings | Add-Member -NotePropertyName $pair.Key -NotePropertyValue $pair.Value -Force
    }
    $settings.captureReady = $true
    Write-VgJson (Join-Path $payload 'install.json') $settings
    $aiPath = Join-Path $UsbRoot 'autoinstall.yaml'
    $template = Get-Content -LiteralPath $aiPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $template.autoinstall.storage.layout.match = @{serial = $settings.diskSerial}
    $template.autoinstall.network.ethernets.wan = @{
        match = @{macaddress = $Network.mac}
        dhcp4 = $true; dhcp6 = $false; optional = $true; 'dhcp4-overrides' = @{'route-metric'=100}; addresses = @("$($Network.ip)/$($Network.prefix)")
        routes = @(@{to = 'default'; via = $Network.gateway; metric = 600}); nameservers = @{addresses = @($Network.dns)}
    }
    Write-VgJson $aiPath $template
    Write-VgJson (Join-Path $UsbRoot 'nocloud\network-config') $template.autoinstall.network
    $seedPath = Join-Path $UsbRoot 'nocloud\user-data'
    if (-not (Test-Path -LiteralPath $seedPath)) { throw 'No installer recovery seed; rebuild the USB kit' }
    $seedText = Get-Content -LiteralPath $seedPath -Raw -Encoding UTF8
    $seed = ($seedText -replace '^#cloud-config\r?\n','') | ConvertFrom-Json
    $seed.autoinstall = $template.autoinstall
    [IO.File]::WriteAllText($seedPath, "#cloud-config`n" + ($seed | ConvertTo-Json -Depth 100), (New-Object Text.UTF8Encoding($false)))
    Write-VgJson (Join-Path $UsbRoot 'nocloud\meta-data') @{ 'instance-id'=('vpnguard-'+[Guid]::NewGuid().ToString('N')); 'local-hostname'='vpnguard-installer' }
    $hashes = [ordered]@{}
    foreach ($file in @(Get-ChildItem -LiteralPath $payload -File -Recurse | Sort-Object FullName)) {
        if ($file.Name -eq 'manifest.json' -or $file.Extension -in @('.pyc','.pyo') -or $file.FullName -match '[\\/]__pycache__[\\/]') { continue }
        if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Ссылки в комплекте запрещены' }
        $name = $file.FullName.Substring($payload.Length).TrimStart('\').Replace('\','/')
        $hashes[$name] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    Write-VgJson (Join-Path $payload 'manifest.json') $hashes
    Write-VgJson (Join-Path $UsbRoot 'bundle.json') @{
        schema = 3; captureReady = $true; diskSerial = $settings.diskSerial; wanMac = $Network.mac
        autoinstallSha256 = (Get-FileHash -LiteralPath $aiPath).Hash.ToLowerInvariant()
        manifestSha256 = (Get-FileHash -LiteralPath (Join-Path $payload 'manifest.json')).Hash.ToLowerInvariant()
        seedSha256 = (Get-FileHash -LiteralPath $seedPath).Hash.ToLowerInvariant()
        seedMetaSha256 = (Get-FileHash -LiteralPath (Join-Path $UsbRoot 'nocloud\meta-data')).Hash.ToLowerInvariant()
    }
    $access = "После установки: http://$($Network.ip):8765/" + [Environment]::NewLine +
        "Логин SSH: $($settings.username)" + [Environment]::NewLine +
        "Пароль веба: $($settings.webToken)" + [Environment]::NewLine +
        'Выполните вход MeduzaVPN через веб. SSH использует подготовленный ключ.'
    [IO.File]::WriteAllText((Join-Path $UsbRoot 'AFTER-INSTALL.txt'), $access, (New-Object Text.UTF8Encoding($true)))
    $consolePassword = Get-VgValue $settings 'consolePassword' ''
    if ($consolePassword) { [IO.File]::WriteAllText((Join-Path $UsbRoot 'LOGIN.txt'), ('User: '+$settings.username+"`nPassword for console, SSH and web: "+$consolePassword+"`nWeb: http://"+$Network.ip+':8765/'), (New-Object Text.UTF8Encoding($false))) }
    Remove-Item -LiteralPath $marker -Force
    return $settings
}
