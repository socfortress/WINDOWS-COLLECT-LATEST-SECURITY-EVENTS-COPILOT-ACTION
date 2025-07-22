[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$TargetHash,

  [string]$LogPath = "$env:TEMP\KillProcessByHash-script.log",
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
    if ((Get-Item $LogPath).Length/1KB -gt $LogMaxKB) {
      for ($i = $LogKeep - 1; $i -ge 0; $i--) {
        $old = "$LogPath.$i"; $new = "$LogPath." + ($i + 1)
        if (Test-Path $old) { Rename-Item $old $new -Force }
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

function Get-FileHashSafe {
  param([string]$Path)
  try {
    if (Test-Path $Path -PathType Leaf) {
      return (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
    }
  } catch {
    Write-Log "Could not hash ${Path}: $_" 'WARN'
  }
  return $null
}


Rotate-Log
$runStart = Get-Date
Write-Log "=== SCRIPT START : Kill processes by hash $TargetHash ==="

$killed = @()

try {
  $allProcs = Get-Process | ForEach-Object {
    $proc = $_
    $exe = $null
    try { $exe = $_.Path } catch {}
    if (-not $exe) { return }

    $hash = Get-FileHashSafe -Path $exe
    if ($hash -and ($hash -eq $TargetHash.ToLower())) {
      Write-Log "MATCH: Killing PID $($_.Id) ($exe)" 'INFO'
      try {
        Stop-Process -Id $_.Id -Force -ErrorAction Stop
        $killed += [PSCustomObject]@{
          pid       = $_.Id
          process   = $_.ProcessName
          path      = $exe
          hash      = $hash
        }
      } catch {
        Write-Log "Failed to kill PID $($_.Id): $_" 'ERROR'
      }
    }
  }

  $results = [PSCustomObject]@{
    timestamp = (Get-Date).ToString('o')
    host      = $HostName
    action    = 'kill_process_by_hash'
    target    = $TargetHash
    killed    = $killed
    status    = if ($killed.Count -gt 0) { 'success' } else { 'not_found' }
  }

  $results | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
  Write-Log "Results JSON logged to $ARLog" 'INFO'

} catch {
  Write-Log $_.Exception.Message 'ERROR'
  $errorObj = [PSCustomObject]@{
    timestamp = (Get-Date).ToString('o')
    host      = $HostName
    action    = 'kill_process_by_hash'
    status    = 'error'
    error     = $_.Exception.Message
  }
  $errorObj | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
}
finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
