[CmdletBinding()]
param(
  [string]$LogPath = "$env:TEMP\EnsureFirewall-script.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference = 'Stop'
$HostName = $env:COMPUTERNAME
$LogMaxKB = 100
$LogKeep  = 5

function Write-Log {
  param([string]$Message, [ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level = 'INFO')
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line = "[$ts][$Level] $Message"
  switch ($Level) {
    'ERROR' { Write-Host $line -ForegroundColor Red }
    'WARN'  { Write-Host $line -ForegroundColor Yellow }
    'DEBUG' { if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')) { Write-Verbose $line } }
    default { Write-Host $line }
  }
  Add-Content -Path $LogPath -Value $line
}

function Rotate-Log {
  if (Test-Path $LogPath -PathType Leaf) {
    if ((Get-Item $LogPath).Length / 1KB -gt $LogMaxKB) {
      for ($i = $LogKeep - 1; $i -ge 0; $i--) {
        $old = "$LogPath.$i"
        $new = "$LogPath." + ($i + 1)
        if (Test-Path $old) { Rename-Item $old $new -Force }
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

function Ensure-FirewallProfile {
  param([string]$Profile)

  Write-Log "Checking $Profile firewall profile..." 'INFO'

  $status = Get-NetFirewallProfile -Profile $Profile
  $changes = @()

  if (-not $status.Enabled) {
    Write-Log "$Profile firewall was disabled. Enabling it." 'WARN'
    Set-NetFirewallProfile -Profile $Profile -Enabled True
    $changes += 'enabled'
  }

  if (-not $status.LoggingAllowed) {
    Write-Log "$Profile firewall logging was disabled. Enabling logging." 'WARN'
    Set-NetFirewallProfile -Profile $Profile -LogAllowed True
    $changes += 'log_allowed'
  }

  if (-not $status.LoggingBlocked) {
    Write-Log "$Profile firewall logging for blocked connections was disabled. Enabling it." 'WARN'
    Set-NetFirewallProfile -Profile $Profile -LogBlocked True
    $changes += 'log_blocked'
  }

  if (-not $status.LogFileName) {
    Write-Log "$Profile log file path is empty. Setting to default." 'WARN'
    Set-NetFirewallProfile -Profile $Profile -LogFileName "%systemroot%\system32\LogFiles\Firewall\$Profile.log"
    $changes += 'log_path'
  }

  return @{
    profile = $Profile
    changes = $changes
    enabled = $true
  }
}

Rotate-Log
$runStart = Get-Date
Write-Log "=== SCRIPT START : Ensure Firewall Enabled ==="

try {
  $results = @{
    timestamp = (Get-Date).ToString('o')
    host      = $HostName
    action    = 'ensure_firewall_enabled'
    enforced  = @()
  }

  foreach ($profile in @('Domain', 'Private', 'Public')) {
    $results.enforced += Ensure-FirewallProfile -Profile $profile
  }

  $results | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
  Write-Log "Firewall enforcement JSON appended to $ARLog" 'INFO'
}
catch {
  Write-Log $_.Exception.Message 'ERROR'
  $errorObj = [pscustomobject]@{
    timestamp = (Get-Date).ToString('o')
    host      = $HostName
    action    = 'ensure_firewall_enabled'
    status    = 'error'
    error     = $_.Exception.Message
  }
  $errorObj | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
}
finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
