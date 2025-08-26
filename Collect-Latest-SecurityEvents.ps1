[CmdletBinding()]
param (
  [int]$HoursBack = 24,
  [switch]$IncludeSysmon,
  [string]$Arg1,
  [string]$Arg2,
  [string]$LogPath = "$env:TEMP\Collect-Latest-SecurityEvents.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

if ($Arg1) { $HoursBack = [int]$Arg1 }
if ($Arg2) { if ($Arg2 -eq 'true' -or $Arg2 -eq '1') { $IncludeSysmon = $true } }

$ErrorActionPreference = 'Stop'
$HostName  = $env:COMPUTERNAME
$LogMaxKB  = 100
$LogKeep   = 5
$MaxMessageLen = 500

$SecurityIDs  = @(4624,4625,4648,4672,4688)
$DefenderIDs  = @(1116,1117,5007)
$SysmonIDs    = @(1,3,6,7,10)

$SecurityLog = 'Security'
$DefenderLog = 'Microsoft-Windows-Windows Defender/Operational'
$SysmonLog   = 'Microsoft-Windows-Sysmon/Operational'
function Rotate-Log {
  param ([string]$Path, [int]$MaxKB, [int]$Keep)
  if (Test-Path $Path) {
    $SizeKB = (Get-Item $Path).Length / 1KB
    if ($SizeKB -ge $MaxKB) {
      for ($i = $Keep; $i -ge 1; $i--) {
        $Old = "$Path.$i"; $New = "$Path.$($i + 1)"
        if (Test-Path $Old) { Rename-Item $Old $New -Force }
      }
      Rename-Item $Path "$Path.1" -Force
    }
  }
}

function Write-Log {
  param ([string]$Level, [string]$Message)
  $Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line = "[$Timestamp][$Level] $Message"
  Add-Content -Path $LogPath -Value $line
  switch ($Level) {
    'ERROR' { Write-Host $line -ForegroundColor Red }
    'WARN'  { Write-Host $line -ForegroundColor Yellow }
    default { Write-Host $line }
  }
}

function NowZ { (Get-Date).ToString('yyyy-MM-dd HH:mm:sszzz') }

function Write-NDJSONLines {
  param([string[]]$JsonLines,[string]$Path=$ARLog)
  $tmp = Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
  Set-Content -Path $tmp -Value ($JsonLines -join [Environment]::NewLine) -Encoding ascii -Force
  try { Move-Item -Path $tmp -Destination $Path -Force } catch { Move-Item -Path $tmp -Destination ($Path + '.new') -Force }
}

function Test-Channel {
  param([string]$Name)
  $c = Get-WinEvent -ListLog $Name -ErrorAction SilentlyContinue
  return [bool]$c
}

function Get-EventsSafe {
  param(
    [string]$LogName,
    [int[]]$Ids,
    [datetime]$Since
  )
  if (-not (Test-Channel -Name $LogName)) {
    Write-Log 'WARN' ("Channel missing or disabled: {0}" -f $LogName)
    return @()
  }

  try {
    Get-WinEvent -FilterHashtable @{ LogName=$LogName; StartTime=$Since; Id=$Ids } -ErrorAction Stop |
      Select-Object Id, ProviderName, TimeCreated, LevelDisplayName, Message
  }
  catch {
    Write-Log 'WARN' ("FilterHashtable failed for {0}: {1}. Falling back to manual filter." -f $LogName, $_.Exception.Message)
    try {
      Get-WinEvent -LogName $LogName -ErrorAction Stop |
        Where-Object { $_.TimeCreated -ge $Since -and ($Ids -contains $_.Id) } |
        Select-Object Id, ProviderName, TimeCreated, LevelDisplayName, Message
    } catch {
      Write-Log 'ERROR' ("Failed querying {0}: {1}" -f $LogName, $_.Exception.Message)
      @()
    }
  }
}

Rotate-Log -Path $LogPath -MaxKB $LogMaxKB -Keep $LogKeep
Write-Log 'INFO' "=== SCRIPT START : Collect Latest Security Events (Last $HoursBack hrs) ==="

$since = (Get-Date).AddHours(-$HoursBack)
Write-Log 'INFO' ("Collecting events since {0} (Sysmon={1}) ..." -f $since, [bool]$IncludeSysmon)

$ts = NowZ
$lines = @()

try {
  $securityEvents = Get-EventsSafe -LogName $SecurityLog -Ids $SecurityIDs -Since $since
  $defenderEvents = Get-EventsSafe -LogName $DefenderLog -Ids $DefenderIDs -Since $since
  $sysmonEvents   = if ($IncludeSysmon) { Get-EventsSafe -LogName $SysmonLog -Ids $SysmonIDs -Since $since } else { @() }

  $allEvents = $securityEvents + $defenderEvents + $sysmonEvents
  $summary = [pscustomobject]@{
    timestamp       = $ts
    host            = $HostName
    action          = 'collect_security_events'
    copilot_action  = $true
    type            = 'summary'
    hours_collected = $HoursBack
    total_events    = $allEvents.Count
    security_events = $securityEvents.Count
    defender_events = $defenderEvents.Count
    sysmon_events   = $sysmonEvents.Count
    channels        = @{
      security_present = (Test-Channel $SecurityLog)
      defender_present = (Test-Channel $DefenderLog)
      sysmon_present   = (Test-Channel $SysmonLog)
    }
  }
  $lines += ($summary | ConvertTo-Json -Compress -Depth 5)

  foreach ($evt in $allEvents) {
    $msg = if ($evt.Message) {
      if ($evt.Message.Length -gt $MaxMessageLen) { $evt.Message.Substring(0,$MaxMessageLen) + '...' } else { $evt.Message }
    } else { '' }

    $lines += ([pscustomobject]@{
      timestamp      = $ts
      host           = $HostName
      action         = 'collect_security_events'
      copilot_action = $true
      type           = 'event'
      id             = $evt.Id
      source         = $evt.ProviderName
      time           = $evt.TimeCreated
      level          = $evt.LevelDisplayName
      message        = $msg
    } | ConvertTo-Json -Compress)
  }

  Write-NDJSONLines -JsonLines $lines -Path $ARLog
  Write-Log 'INFO' ("Collected {0} Security, {1} Defender, {2} Sysmon (total {3})" -f $securityEvents.Count, $defenderEvents.Count, $sysmonEvents.Count, $allEvents.Count)
}
catch {
  Write-Log 'ERROR' ("Collection failed: {0}" -f $_.Exception.Message)
  $err = [pscustomobject]@{
    timestamp      = $ts
    host           = $HostName
    action         = 'collect_security_events'
    copilot_action = $true
    type           = 'error'
    error          = $_.Exception.Message
  }
  Write-NDJSONLines -JsonLines @(($err | ConvertTo-Json -Compress)) -Path $ARLog
  Write-Log 'WARN' "Error NDJSON written."
}

Write-Log 'INFO' "=== SCRIPT END : Collect Latest Security Events ==="
