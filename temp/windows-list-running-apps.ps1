[CmdletBinding()]
param(
  [int]$MaxWaitSeconds = 300,
  [string]$LogPath = "$env:TEMP\ListRunningApps-script.log",
  [string]$ARLog = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference = 'Stop'
$HostName = $env:COMPUTERNAME
$LogMaxKB = 100
$LogKeep = 5

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

Rotate-Log
$runStart = Get-Date
Write-Log "=== SCRIPT START : List Running Applications ==="

try {
  Write-Log "Querying running processes..." 'INFO'

  $processes = Get-CimInstance Win32_Process |
    Where-Object { $_.ExecutablePath -and $_.Name -ne "" } |
    Select-Object Name, ProcessId, ExecutablePath |
    Sort-Object Name

  if (-not $processes) {
    Write-Log "No user-level applications found running." 'WARN'
  }
  else {
    Write-Log "Found $($processes.Count) running applications." 'INFO'
    foreach ($proc in $processes) {
      Write-Log "[$($proc.ProcessId)] $($proc.Name) => $($proc.ExecutablePath)" 'DEBUG'
    }
  }

  # Convert to JSON-safe array for logging
  $apps = $processes | ForEach-Object {
    [PSCustomObject]@{
      name = $_.Name
      pid  = $_.ProcessId
      path = $_.ExecutablePath
    }
  }

  $logObj = [pscustomobject]@{
    timestamp = (Get-Date).ToString('o')
    host      = $HostName
    action    = "list_running_apps"
    count     = $apps.Count
    apps      = $apps
  }

  $logObj | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
  Write-Log "JSON appended to $ARLog" 'INFO'
}
catch {
  Write-Log $_.Exception.Message 'ERROR'
  $logObj = [pscustomobject]@{
    timestamp = (Get-Date).ToString('o')
    host      = $HostName
    action    = "list_running_apps"
    status    = "error"
    error     = $_.Exception.Message
  }
  $logObj | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
}
finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
