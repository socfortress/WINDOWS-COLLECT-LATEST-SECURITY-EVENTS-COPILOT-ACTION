[CmdletBinding()]
param (
    [int]$HoursBack = 24,
    [switch]$IncludeSysmon,
    [string]$LogPath = "$env:TEMP\Collect-Latest-SecurityEvents.log",
    [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

# Map Velociraptor arguments
if ($Arg1 -and -not $HoursBack) { $HoursBack = [int]$Arg1 }
if ($Arg2 -and -not $IncludeSysmon) {
    if ($Arg2 -eq "true" -or $Arg2 -eq "1") { $IncludeSysmon = $true }
}

$ErrorActionPreference = 'Stop'
$HostName  = $env:COMPUTERNAME
$LogMaxKB  = 100
$LogKeep   = 5

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

function Safe-Append {
    param ([string]$Content)
    for ($i = 0; $i -lt 3; $i++) {
        try {
            Add-Content -Path $ARLog -Value $Content
            break
        } catch {
            Start-Sleep -Milliseconds 200
            if ($i -eq 2) { Write-Log ERROR "Failed to write to $ARLog after 3 tries: $_" }
        }
    }
}

function Log-JSON {
    param ($Data)
    # Write summary entry first
    $Summary = @{
        timestamp       = (Get-Date).ToString('o')
        hostname        = $HostName
        type            = 'latest_security_events'
        hours_collected = $HoursBack
        total_events    = $Data.Count
    } | ConvertTo-Json -Compress
    Safe-Append -Content $Summary

    # Write each event as a separate JSON object
    foreach ($evt in $Data) {
        $eventObj = [pscustomobject]@{
            id        = $evt.Id
            source    = $evt.ProviderName
            time      = $evt.TimeCreated
            level     = $evt.LevelDisplayName
            message   = $evt.Message
        }
        $line = $eventObj | ConvertTo-Json -Compress
        Safe-Append -Content $line
    }
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

    Log-JSON -Data $allEvents

    $Total = $allEvents.Count
    $SysmonCount = $sysmonEvents.Count
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff')][INFO] Collected $($securityEvents.Count) Security, $($defenderEvents.Count) Defender, $SysmonCount Sysmon events (total: $Total) from last $HoursBack hours." -ForegroundColor Cyan
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff')][INFO] JSON report appended to $ARLog" -ForegroundColor Gray

    Write-Log INFO "Collected $($securityEvents.Count) Security, $($defenderEvents.Count) Defender, $SysmonCount Sysmon events (total $Total) from last $HoursBack hrs. JSON appended."
}
catch {
    Write-Log ERROR "Failed to collect events: $_"
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff')][ERROR] Failed to collect events. See $LogPath for details." -ForegroundColor Red
}

$EndMsg = "=== SCRIPT END : Collect Latest Security Events ==="
Write-Log INFO $EndMsg
Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff')][INFO] $EndMsg"
