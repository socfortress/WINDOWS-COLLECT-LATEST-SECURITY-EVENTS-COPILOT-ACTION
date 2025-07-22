[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$TargetPath,
  [switch]$Quarantine,
  [string]$LogPath = "$env:TEMP\RemoveRogueSoftware-script.log",
  [string]$ARLog = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference = 'Stop'
$HostName = $env:COMPUTERNAME
$LogMaxKB = 100
$LogKeep = 5
$Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

function Write-Log {
  param([string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
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
    if ((Get-Item $LogPath).Length/1KB -gt $LogMaxKB) {
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
Write-Log "=== SCRIPT START : Remove Rogue Software at $TargetPath ==="

# Normalize path
$FullPath = (Resolve-Path $TargetPath -ErrorAction SilentlyContinue).Path
if (-not $FullPath) {
  Write-Log "Target path $TargetPath not found, exiting." 'ERROR'
  $result = @{
    timestamp = (Get-Date).ToString('o')
    host      = $HostName
    action    = 'remove_rogue_software'
    status    = 'error'
    target    = $TargetPath
    error     = 'Path not found'
  }
  $result | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
  exit 1
}

$actionsTaken = @()

try {
  Get-Process | ForEach-Object {
    try {
      if ($_.Path -and ($_.Path -like "$FullPath*")) {
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        $actionsTaken += "Killed process $($_.Name)"
      }
    } catch { }
  }

$taskMatches = schtasks /Query /FO LIST /V | Select-String -SimpleMatch -Pattern $FullPath -Context 0,10

  if ($taskMatches) {
    foreach ($line in $taskMatches) {
      if ($line -match "TaskName:\s+(.+)") {
        $taskName = $Matches[1].Trim()
        schtasks /Delete /TN "$taskName" /F | Out-Null
        $actionsTaken += "Deleted scheduled task $taskName"
      }
    }
  }


  if ($Quarantine) {
    $QuarantineDir = "C:\Quarantine"
    if (-not (Test-Path $QuarantineDir)) { New-Item -Path $QuarantineDir -ItemType Directory -Force | Out-Null }
    $dest = Join-Path $QuarantineDir (Split-Path $FullPath -Leaf)
    Move-Item -Path $FullPath -Destination $dest -Force
    # Remove execute permissions
    icacls $dest /inheritance:r /grant:r "Everyone:(R)" /deny "Everyone:(X)" | Out-Null
    $actionsTaken += "Quarantined $FullPath to $dest"
  } else {
    Remove-Item -Path $FullPath -Recurse -Force -ErrorAction Stop
    $actionsTaken += "Deleted $FullPath"
  }

  $RegPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
  )
  foreach ($regBase in $RegPaths) {
    Get-ChildItem $regBase | ForEach-Object {
      try {
        $DisplayIcon = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DisplayIcon
        if ($DisplayIcon -and ($DisplayIcon -like "$FullPath*")) {
          Remove-Item -Path $_.PSPath -Recurse -Force
          $actionsTaken += "Removed registry uninstall entry for $FullPath"
        }
      } catch { }
    }
  }

  # Log JSON result
  $result = @{
    timestamp = (Get-Date).ToString('o')
    host      = $HostName
    action    = 'remove_rogue_software'
    target    = $FullPath
    status    = 'success'
    actions   = $actionsTaken
  }
  $result | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
  Write-Log "Completed rogue software removal for $FullPath" 'INFO'
}
catch {
  Write-Log $_.Exception.Message 'ERROR'
  $result = @{
    timestamp = (Get-Date).ToString('o')
    host      = $HostName
    action    = 'remove_rogue_software'
    target    = $FullPath
    status    = 'error'
    error     = $_.Exception.Message
  }
  $result | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
}
finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
