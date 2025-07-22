[CmdletBinding()]
param(
  [switch]$RebootAfter,
  [string]$LogPath = "$env:TEMP\EnableCredentialGuard-script.log",
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

function To-ISO8601($dt) {
  if ($dt -and $dt -is [datetime] -and $dt.Year -gt 1900) {
    return $dt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  } else {
    return $null
  }
}

Rotate-Log
$runStart = Get-Date
Write-Log "=== SCRIPT START : Enable Windows Credential Guard ==="

$status = 'success'
$errorMsg = $null

try {
  Write-Log "Enabling Credential Guard policies..." 'INFO'

  $RegPaths = @(
    "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
  )

  if (-not (Test-Path $RegPaths[0])) { New-Item -Path $RegPaths[0] -Force | Out-Null }
  Set-ItemProperty -Path $RegPaths[0] -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord -Force
  Set-ItemProperty -Path $RegPaths[0] -Name "RequirePlatformSecurityFeatures" -Value 1 -Type DWord -Force

  if (-not (Test-Path $RegPaths[1])) { New-Item -Path $RegPaths[1] -Force | Out-Null }
  Set-ItemProperty -Path $RegPaths[1] -Name "RunAsPPL" -Value 1 -Type DWord -Force

  Write-Log "Credential Guard enabled. A reboot is required for changes to take effect." 'INFO'

  if ($RebootAfter) {
    Write-Log "Rebooting system as requested..." 'INFO'
    Restart-Computer -Force
  }

} catch {
  $status = 'error'
  $errorMsg = $_.Exception.Message
  Write-Log "Failed to enable Credential Guard: $errorMsg" 'ERROR'
}

$results = [pscustomobject]@{
  timestamp = (Get-Date).ToString('o')
  host      = $HostName
  action    = 'enable_credential_guard'
  status    = $status
  error     = $errorMsg
}

try {
  $results | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
  Write-Log "Action JSON logged to $ARLog" 'INFO'
} catch {
  Write-Log "Failed to write JSON log: $($_.Exception.Message)" 'WARN'
}

$dur = [int]((Get-Date) - $runStart).TotalSeconds
Write-Log "=== SCRIPT END : duration ${dur}s ==="
