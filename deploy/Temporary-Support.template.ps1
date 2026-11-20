#Requires -Version 5.1
#Requires -RunAsAdministrator
# Временный доступ для диагностики USB. Не устанавливает службу или автозапуск.
$ErrorActionPreference='Stop'
$AllowedIP='__ALLOWED_IP__'
$Token='__TOKEN__'
$Port=8766
$Deadline=[DateTime]::UtcNow.AddMinutes(30)
$RuleName='VpnGuard-TemporarySupport-__ID__'
$listener=New-Object Net.HttpListener
$listener.Prefixes.Add("http://+:$Port/")
function Send-SupportJson($Context,$Value,[int]$Status=200) {
    $text=$Value | ConvertTo-Json -Depth 8 -Compress
    $bytes=[Text.Encoding]::UTF8.GetBytes($text)
    $Context.Response.StatusCode=$Status
    $Context.Response.ContentType='application/json; charset=utf-8'
    $Context.Response.ContentLength64=$bytes.Length
    $Context.Response.OutputStream.Write($bytes,0,$bytes.Length)
    $Context.Response.Close()
}
function Test-SupportToken([string]$Value) {
    if (-not $Value -or $Value.Length -ne $Token.Length) { return $false }
    $different=0
    for ($i=0;$i -lt $Token.Length;$i++) { $different=$different -bor ([int][char]$Value[$i] -bxor [int][char]$Token[$i]) }
    return $different -eq 0
}
try {
    New-NetFirewallRule -Name $RuleName -DisplayName 'VpnGuard temporary USB support (30 min)' -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port -RemoteAddress $AllowedIP -Profile Any | Out-Null
    $listener.Start()
    Write-Host "Временный доступ включён на порту $Port только для $AllowedIP."
    Write-Host 'Оставьте это окно открытым. Исправления выполняются удалённо; запуск установки ОС и перезагрузка сюда не входят.'
    Write-Host 'Через 30 минут доступ и временное правило брандмауэра будут выключены.'
    $stop=$false
    while (-not $stop -and [DateTime]::UtcNow -lt $Deadline) {
        $pending=$listener.BeginGetContext($null,$null)
        while (-not $pending.AsyncWaitHandle.WaitOne(1000)) {
            if ([DateTime]::UtcNow -ge $Deadline) { $stop=$true; break }
        }
        if ($stop) { break }
        $context=$listener.EndGetContext($pending)
        try {
            $address=$context.Request.RemoteEndPoint.Address
            if ($address.IsIPv4MappedToIPv6) { $address=$address.MapToIPv4() }
            if ($address.ToString() -ne $AllowedIP -or -not (Test-SupportToken $context.Request.Headers['X-Vg-Support'])) {
                Send-SupportJson $context @{ok=$false;error='Access denied'} 403; continue
            }
            $path=$context.Request.Url.AbsolutePath
            if ($path -eq '/health' -and $context.Request.HttpMethod -eq 'GET') {
                Send-SupportJson $context @{ok=$true;computer=$env:COMPUTERNAME;expires=$Deadline.ToString('o');user=[Security.Principal.WindowsIdentity]::GetCurrent().Name};continue
            }
            if ($path -eq '/stop' -and $context.Request.HttpMethod -eq 'POST') {
                Send-SupportJson $context @{ok=$true};$stop=$true;continue
            }
            if ($path -ne '/run' -or $context.Request.HttpMethod -ne 'POST' -or $context.Request.ContentLength64 -lt 0 -or $context.Request.ContentLength64 -gt 65536) {
                Send-SupportJson $context @{ok=$false;error='Unsupported request'} 400;continue
            }
            $reader=New-Object IO.StreamReader($context.Request.InputStream,[Text.Encoding]::UTF8)
            try { $body=$reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
            if (-not $body.script -or $body.script.Length -gt 60000) { throw 'Empty or oversized command' }
            Write-Host ("[{0}] Команда диагностики/ремонта USB" -f (Get-Date -Format 'HH:mm:ss'))
            try {
                $output=& ([scriptblock]::Create([string]$body.script)) 2>&1 | Out-String -Width 240
                if ($output.Length -gt 1048576) { $output=$output.Substring(0,1048576) }
                Send-SupportJson $context @{ok=$true;output=$output}
            } catch {
                Send-SupportJson $context @{ok=$false;error=$_.Exception.Message;details=($_ | Out-String)}
            }
        } catch {
            try { Send-SupportJson $context @{ok=$false;error=$_.Exception.Message} 500 } catch {}
        } finally { $pending.AsyncWaitHandle.Close() }
    }
} finally {
    if ($listener.IsListening) { $listener.Stop() }
    $listener.Close()
    Remove-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue
    Write-Host 'Временный доступ закрыт, правило брандмауэра удалено.'
}
