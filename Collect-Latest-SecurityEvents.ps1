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
$runStart  = Get-Date

$SecurityIDs  = @(4624,4625,4648,4672,4688)
$DefenderIDs  = @(1116,1117,5007)
$SysmonIDs    = @(1,3,6,7,10)

$SecurityLog = 'Security'
$DefenderLog = 'Microsoft-Windows-Windows Defender/Operational'
$SysmonLog   = 'Microsoft-Windows-Sysmon/Operational'

function Write-Log {
  param ([string]$Message, [ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
  $Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line = "[$Timestamp][$Level] $Message"
  switch ($Level) {
    'ERROR' { Write-Host $line -ForegroundColor Red }
    'WARN'  { Write-Host $line -ForegroundColor Yellow }
    'DEBUG' { if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')) { Write-Verbose $line } }
    default { Write-Host $line }
  }
  Add-Content -Path $LogPath -Value $line -Encoding utf8
}

function Rotate-Log {
  if (Test-Path $LogPath -PathType Leaf) {
    if ((Get-Item $LogPath).Length / 1KB -gt $LogMaxKB) {
      for ($i = $LogKeep - 1; $i -ge 0; $i--) {
        $old = "$LogPath.$i"; $new = "$LogPath." + ($i + 1)
        if (Test-Path $old) { Rename-Item $old $new -Force }
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

function To-ISO8601 {
  param($dt)
  if ($dt -and $dt -is [datetime] -and $dt.Year -gt 1900) { $dt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
}

function New-NdjsonLine { param([hashtable]$Data) ($Data | ConvertTo-Json -Compress -Depth 7) }

function Write-NDJSONLines {
  param([string[]]$JsonLines,[string]$Path=$ARLog)
  $tmp = Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
  $payload = ($JsonLines -join [Environment]::NewLine) + [Environment]::NewLine
  Set-Content -Path $tmp -Value $payload -Encoding ascii -Force
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
    Write-Log ("Channel missing or disabled: {0}" -f $LogName) 'WARN'
    return @()
  }
  try {
    Get-WinEvent -FilterHashtable @{ LogName=$LogName; StartTime=$Since; Id=$Ids } -ErrorAction Stop |
      Select-Object Id, ProviderName, TimeCreated, LevelDisplayName, Message
  }
  catch {
    Write-Log ("FilterHashtable failed for {0}: {1}. Falling back to manual filter." -f $LogName, $_.Exception.Message) 'WARN'
    try {
      Get-WinEvent -LogName $LogName -ErrorAction Stop |
        Where-Object { $_.TimeCreated -ge $Since -and ($Ids -contains $_.Id) } |
        Select-Object Id, ProviderName, TimeCreated, LevelDisplayName, Message
    } catch {
      Write-Log ("Failed querying {0}: {1}" -f $LogName, $_.Exception.Message) 'ERROR'
      @()
    }
  }
}

Rotate-Log
Write-Log "=== SCRIPT START : Collect Latest Security Events (host=$HostName, last ${HoursBack}h, sysmon=$([bool]$IncludeSysmon)) ==="

$since = (Get-Date).AddHours(-$HoursBack)
$tsNow = To-ISO8601 (Get-Date)

$lines = New-Object System.Collections.ArrayList

try {
  [void]$lines.Add( (New-NdjsonLine @{
    timestamp      = $tsNow
    host           = $HostName
    action         = 'collect_security_events'
    copilot_action = $true
    item           = 'verify_source'
    description    = "Collecting events since $($since.ToString('u'))"
    channels       = @{
      security_log = $SecurityLog
      defender_log = $DefenderLog
      sysmon_log   = $SysmonLog
    }
    ids = @{
      security_ids = $SecurityIDs
      defender_ids = $DefenderIDs
      sysmon_ids   = $SysmonIDs
    }
    include_sysmon = [bool]$IncludeSysmon
    hours_back     = $HoursBack
  }) )

  $securityEvents = Get-EventsSafe -LogName $SecurityLog -Ids $SecurityIDs -Since $since
  $defenderEvents = Get-EventsSafe -LogName $DefenderLog -Ids $DefenderIDs -Since $since
  $sysmonEvents   = if ($IncludeSysmon) { Get-EventsSafe -LogName $SysmonLog -Ids $SysmonIDs -Since $since } else { @() }

  $allEvents = $securityEvents + $defenderEvents + $sysmonEvents

  foreach ($evt in $allEvents) {
    $msg =
      if ($evt.Message) {
        if ($evt.Message.Length -gt $MaxMessageLen) { $evt.Message.Substring(0,$MaxMessageLen) + '...' } else { $evt.Message }
      } else { '' }

    [void]$lines.Add( (New-NdjsonLine @{
      timestamp      = $tsNow
      host           = $HostName
      action         = 'collect_security_events'
      copilot_action = $true
      item           = 'event'
      description    = "Event $($evt.Id) from $($evt.ProviderName) at $($evt.TimeCreated)"
      id             = $evt.Id
      source         = $evt.ProviderName
      time_utc       = To-ISO8601 $evt.TimeCreated
      level          = $evt.LevelDisplayName
      message        = $msg
    }) )
  }


  if ($allEvents.Count -eq 0) {
    [void]$lines.Add( (New-NdjsonLine @{
      timestamp      = $tsNow
      host           = $HostName
      action         = 'collect_security_events'
      copilot_action = $true
      item           = 'status'
      status         = 'no_results'
      description    = 'No events matched the filters in the specified window'
    }) )
  }


  $summary = New-NdjsonLine @{
    timestamp       = $tsNow
    host            = $HostName
    action          = 'collect_security_events'
    copilot_action  = $true
    item            = 'summary'
    description     = 'Run summary and counts'
    hours_collected = $HoursBack
    total_events    = $allEvents.Count
    security_events = $securityEvents.Count
    defender_events = $defenderEvents.Count
    sysmon_events   = $sysmonEvents.Count
    channels_present = @{
      security_present = (Test-Channel $SecurityLog)
      defender_present = (Test-Channel $DefenderLog)
      sysmon_present   = (Test-Channel $SysmonLog)
    }
    since_utc       = To-ISO8601 $since
    duration_s      = [math]::Round(((Get-Date)-$runStart).TotalSeconds,1)
  }
  $lines = ,$summary + $lines

  Write-NDJSONLines -JsonLines $lines -Path $ARLog
  Write-Log ("Wrote {0} NDJSON record(s) to {1}" -f $lines.Count, $ARLog) 'INFO'
  Write-Log ("Collected {0} Security, {1} Defender, {2} Sysmon (total {3})" -f $securityEvents.Count, $defenderEvents.Count, $sysmonEvents.Count, $allEvents.Count) 'INFO'
}
catch {
  Write-Log ("Collection failed: {0}" -f $_.Exception.Message) 'ERROR'
  $err = New-NdjsonLine @{
    timestamp      = To-ISO8601 (Get-Date)
    host           = $HostName
    action         = 'collect_security_events'
    copilot_action = $true
    item           = 'error'
    description    = 'Unhandled error during collection'
    error          = $_.Exception.Message
  }
  Write-NDJSONLines -JsonLines @($err) -Path $ARLog
  Write-Log 'Error NDJSON written.' 'WARN'
}
finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : Collect Latest Security Events (duration ${dur}s) ===" 'INFO'
}
