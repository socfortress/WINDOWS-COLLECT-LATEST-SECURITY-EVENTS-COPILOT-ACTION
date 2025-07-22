[CmdletBinding()]
param(
  [ValidateSet('menu','quick','full','custom')] [string]$ScanType='menu',
  [string]$Path,
  [int]$MaxWaitSeconds=900,
  [string]$LogPath="$env:TEMP\DefenderScan-script.log",
  [string]$ARLog = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference = 'Stop'
$EventLog = 'Microsoft-Windows-Windows Defender/Operational'
$HostName = $env:COMPUTERNAME
$ScanMap = @{ quick='QuickScan'; full='FullScan'; custom='CustomScan' }
$LogMaxKB = 100; $LogKeep = 5; $WaitStep = 5

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
        $old = "$LogPath.$i"; $new = "$LogPath." + ($i + 1)
        if (Test-Path $old) { Rename-Item $old $new -Force }
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

Rotate-Log
$runStart = Get-Date
Write-Log "=== SCRIPT START : $ScanType ==="

try {
  if ($ScanType -eq 'menu') {
    do {
      Write-Host "`n1) Quick`n2) Full`n3) Custom"
      $choice = Read-Host 'Choose [1-3]'
      switch ($choice) {
        '1' { $ScanType = 'quick'; $valid = $true }
        '2' { $ScanType = 'full';  $valid = $true }
        '3' { $ScanType = 'custom'; $Path = Read-Host 'Enter full path'; $valid = $true }
        default { Write-Warning 'Invalid'; $valid = $false }
      }
    } until ($valid)
  }

  $status = Get-MpComputerStatus
  if ($status.AntivirusScanInProgress -or $status.FullScanRunning) {
    Write-Log 'Scan already running — exit' 'WARN'; return
  }

  if ($ScanType -eq 'custom') {
    if (-not(Test-Path $Path)) { throw "Path $Path not found" }
    if (-not(Get-Item $Path).PSIsContainer) { throw 'CustomScan requires directory' }
    if ($Path -notmatch '\\$') { $Path += '\' }
    $scanParams = @{ ScanPath = $Path; ScanType = 'CustomScan' }
  } else {
    $scanParams = @{ ScanType = $ScanMap[$ScanType] }
  }

  Write-Log "Launching $($ScanMap[$ScanType]) path=$Path" 'INFO'
  Start-MpScan @scanParams
  $startTime = Get-Date

  Write-Log 'Waiting for events' 'DEBUG'
  $events = @(); $elapsed = 0
  while ($elapsed -lt $MaxWaitSeconds) {
    Start-Sleep $WaitStep; $elapsed += $WaitStep
    $new = Get-WinEvent -LogName $EventLog -MaxEvents 20 -ErrorAction SilentlyContinue |
           Where-Object { $_.TimeCreated -ge $startTime -and $_.Id -in 1000,1001,1116,1117 }
    if ($new) { $events += $new }
    if ($events | Where-Object { $_.Id -eq 1001 }) { break }
    if (($events | Where-Object { $_.Id -eq 1117 }) -and $elapsed -ge 60) { break }
    Write-Progress -Activity "Defender $ScanType" -Status "Elapsed ${elapsed}s" -PercentComplete ([math]::Min(99, $elapsed / $MaxWaitSeconds * 100))
  }
  Write-Progress -Activity 'Defender' -Completed

  $items = 0; $threats = 0; $names = @(); $statusTag = 'unknown_or_timed_out'
  $evt1001 = $events | Where-Object { $_.Id -eq 1001 } | Select-Object -First 1
  if ($evt1001) {
    $xml = [xml]$evt1001.ToXml()
    $items = [int]($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ItemsScanned' } | ForEach-Object { $_.'#text' })
    $threats = [int]($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ThreatsFound' } | ForEach-Object { $_.'#text' })
  }
  $names = $events | Where-Object { $_.Id -in 1116, 1117 } | ForEach-Object {
    ([xml]$_.ToXml()).Event.EventData.Data | Where-Object { $_.Name -eq 'ThreatName' } | ForEach-Object { $_.'#text' }
  } | Sort-Object -Unique
  if ($names) { $threats = $names.Count }
  $statusTag = if ($names) { 'detections_found' } elseif ($evt1001) { 'clean' } else { 'unknown_or_timed_out' }

  Write-Log "Result: items=$items threats=$threats status=$statusTag" 'INFO'
  if ($names) { Write-Log "Detected: $($names -join ', ')" 'WARN' }

  $logObj = [pscustomobject]@{
    timestamp     = (Get-Date).ToString('o')
    host          = $HostName
    scan_type     = $ScanMap[$ScanType]
    target_path   = if ($ScanType -eq 'custom') { $Path } else { $null }
    items_scanned = $items
    threats_found = $threats
    detections    = $names
    status        = $statusTag
  }
  $logObj | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
  Write-Log "JSON appended to $ARLog" 'INFO'

} catch {
  Write-Log $_.Exception.Message 'ERROR'; throw
} finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
