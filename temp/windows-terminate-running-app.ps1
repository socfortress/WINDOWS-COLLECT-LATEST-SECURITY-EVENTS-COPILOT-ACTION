[CmdletBinding()]
param(
  [string]$LogPath = "$env:TEMP\TerminateApp-script.log",
  [string]$ARLog = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference = 'Stop'
$HostName = $env:COMPUTERNAME
$LogMaxKB = 100
$LogKeep = 5

function Write-Log {
 param([string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
 $ts=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
 $line="[$ts][$Level] $Message"
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
Write-Log "=== SCRIPT START : Terminate App (auto) ==="

try {
  $Target = Read-Host "Enter the application name or PID to terminate"
  $killed = @(); $notFound = $false

  if ($Target -match '^\d+$') {
    $SearchMode = 'pid'
  } else {
    $SearchMode = 'name'
  }

  if ($SearchMode -eq 'pid') {
    $proc = Get-Process -Id $Target -ErrorAction SilentlyContinue
    if ($proc) {
      Stop-Process -Id $proc.Id -Force
      Write-Log "Terminated process PID $($proc.Id) [$($proc.ProcessName)]" 'INFO'
      $killed += [pscustomobject]@{ name = $proc.ProcessName; pid = $proc.Id }
    } else {
      Write-Log "No process found with PID $Target" 'WARN'
      $notFound = $true
    }
  } else {
    $procs = Get-Process -Name $Target -ErrorAction SilentlyContinue
    if ($procs) {
      foreach ($p in $procs) {
        Stop-Process -Id $p.Id -Force
        Write-Log "Terminated [$($p.Id)] $($p.ProcessName)" 'INFO'
        $killed += [pscustomobject]@{ name = $p.ProcessName; pid = $p.Id }
      }
    } else {
      Write-Log "No process found matching name '$Target'" 'WARN'
      $notFound = $true
    }
  }

  # Write JSON log
  $logObj = [pscustomobject]@{
    timestamp = (Get-Date).ToString('o')
    host      = $HostName
    action    = "terminate_app"
    mode      = $SearchMode
    target    = $Target
    status    = if ($notFound) { "not_found" } else { "terminated" }
    killed    = $killed
  }

  $logObj | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
  Write-Log "JSON appended to $ARLog" 'INFO'
}
catch {
  Write-Log $_.Exception.Message 'ERROR'
  $logObj = [pscustomobject]@{
    timestamp = (Get-Date).ToString('o')
    host      = $HostName
    action    = "terminate_app"
    status    = "error"
    error     = $_.Exception.Message
  }
  $logObj | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
}
finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
