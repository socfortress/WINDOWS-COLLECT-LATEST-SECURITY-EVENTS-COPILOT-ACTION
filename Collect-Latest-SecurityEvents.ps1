[CmdletBinding()]
param (
    [int]$HoursBack = 24,
    [switch]$IncludeSysmon,
    [string]$LogPath = "$env:TEMP\Collect-Latest-SecurityEvents.log",
    [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)
if ($Arg1 -and -not $HoursBack) { $HoursBack = [int]$Arg1 }
if ($Arg2 -and -not $IncludeSysmon) {
    if ($Arg2 -eq "true" -or $Arg2 -eq "1") { $IncludeSysmon = $true }
}

$ErrorActionPreference = 'Stop'
$HostName  = $env:COMPUTERNAME
$LogMaxKB  = 100
$LogKeep   = 5
$MaxMessageLen = 500
$BatchSize = 50

$SecurityIDs  = @(4624,4625,4648,4672,4688)
$DefenderIDs  = @(1116,1117,5007)
$SysmonIDs    = @(1,3,6,7,10)

function Rotate-Log {
    param ([string]$Path, [int]$MaxKB, [int]$Keep)
    if (Test-Path $Path) {
        $SizeKB = (Get-Item $Path).Length / 1KB
        if ($SizeKB -ge $MaxKB) {
            for ($i = $Keep; $i -ge 1; $i--) {
                $Old = "$Path.$i"
                $New = "$Path.$($i + 1)"
                if (Test-Path $Old) { Rename-Item $Old $New -Force }
            }
            Rename-Item $Path "$Path.1" -Force
        }
    }
}

function Write-Log {
    param ([string]$Level, [string]$Message)
    $Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    Add-Content -Path $LogPath -Value "[$Timestamp][$Level] $Message"
}

function Build-JSONReport {
    param ($Events)
    $summaryObj = [pscustomobject]@{
        timestamp       = (Get-Date).ToString('o')
        host            = $HostName
        action          = 'collect_security_events'
        hours_collected = $HoursBack
        total_events    = $Events.Count
    }

    $jsonLines = @()
    $jsonLines += ($summaryObj | ConvertTo-Json -Compress)

    foreach ($evt in $Events) {
        $msg = if ($evt.Message) {
            if ($evt.Message.Length -gt $MaxMessageLen) {
                $evt.Message.Substring(0, $MaxMessageLen) + "..."
            } else { $evt.Message }
        } else { "" }

        $eventObj = [pscustomobject]@{
            id        = $evt.Id
            source    = $evt.ProviderName
            time      = $evt.TimeCreated
            level     = $evt.LevelDisplayName
            message   = $msg
        }
        $jsonLines += ($eventObj | ConvertTo-Json -Compress)
    }

    return $jsonLines -join "`n"
}

Rotate-Log -Path $LogPath -MaxKB $LogMaxKB -Keep $LogKeep

$StartMsg = "=== SCRIPT START : Collect Latest Security Events (Last $HoursBack hrs) ==="
Write-Log INFO $StartMsg
Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff')][INFO] $StartMsg"

try {
    $since = (Get-Date).AddHours(-$HoursBack)
    Write-Log INFO "Collecting events since $since (Sysmon=$IncludeSysmon)..."
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff')][INFO] Collecting events since $since ..."

    $securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$since; Id=$SecurityIDs} -ErrorAction SilentlyContinue |
                      Select-Object Id, ProviderName, TimeCreated, LevelDisplayName, Message

    $defenderEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; StartTime=$since; Id=$DefenderIDs} -ErrorAction SilentlyContinue |
                      Select-Object Id, ProviderName, TimeCreated, LevelDisplayName, Message

    $sysmonEvents = @()
    if ($IncludeSysmon) {
        $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=$since; Id=$SysmonIDs} -ErrorAction SilentlyContinue |
                        Select-Object Id, ProviderName, TimeCreated, LevelDisplayName, Message
    }

    $allEvents = $securityEvents + $defenderEvents + $sysmonEvents
    $jsonReport = Build-JSONReport -Events $allEvents
    $tempFile = "$env:TEMP\arlog.tmp"
    Set-Content -Path $tempFile -Value $jsonReport -Encoding ascii -Force
    try {
        Move-Item -Path $tempFile -Destination $ARLog -Force
        Write-Log INFO "Log file replaced at $ARLog"
    } catch {
        Move-Item -Path $tempFile -Destination "$ARLog.new" -Force
        Write-Log WARN "Log locked, wrote results to $ARLog.new"
    }

    $Total = $allEvents.Count
    $SysmonCount = $sysmonEvents.Count
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff')][INFO] Collected $($securityEvents.Count) Security, $($defenderEvents.Count) Defender, $SysmonCount Sysmon events (total: $Total) from last $HoursBack hours." -ForegroundColor Cyan
}
catch {
    Write-Log ERROR "Failed to collect events: $_"

    $errorObj = [pscustomobject]@{
        timestamp = (Get-Date).ToString('o')
        host      = $HostName
        action    = 'collect_security_events'
        status    = 'error'
        error     = $_.Exception.Message
        copilot_soar = $true
    }
    $json = $errorObj | ConvertTo-Json -Compress
    $fallback = "$ARLog.new"
    Set-Content -Path $fallback -Value $json -Encoding ascii -Force
    Write-Log WARN "Error logged to $fallback"
}

$EndMsg = "=== SCRIPT END : Collect Latest Security Events ==="
Write-Log INFO $EndMsg
Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff')][INFO] $EndMsg"
