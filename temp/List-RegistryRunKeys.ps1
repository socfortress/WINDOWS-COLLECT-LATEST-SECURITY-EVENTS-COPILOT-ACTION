[CmdletBinding()]
param(
  [string]$LogPath = "$env:TEMP\ListRegistryRunKeys-script.log",
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

function Check-Signature {
  param([string]$Path)
  try {
    if (-not (Test-Path $Path)) { return @{ signed = $false; trusted = $false } }
    $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction SilentlyContinue
    return @{
      signed  = ($sig.Status -eq 'Valid')
      trusted = ($sig.SignerCertificate.Subject -like '*Microsoft*')
    }
  } catch {
    return @{ signed = $false; trusted = $false }
  }
}

Rotate-Log
$runStart = Get-Date
Write-Log "=== SCRIPT START : List Registry Run Keys ==="

$keysToCheck = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)

$entries = @()

foreach ($key in $keysToCheck) {
  try {
    if (Test-Path $key) {
      $vals = Get-ItemProperty -Path $key
      foreach ($name in $vals.PSObject.Properties.Name | Where-Object { $_ -ne 'PSPath' -and $_ -ne 'PSParentPath' -and $_ -ne 'PSChildName' -and $_ -ne 'PSDrive' -and $_ -ne 'PSProvider' }) {
        $rawPath = $vals.$name
        # Extract executable path (strip args and quotes)
        $exe = ($rawPath -replace '^[^"]*"?([^"]+\.exe).*$', '$1')
        $sigInfo = Check-Signature -Path $exe
        $entries += [PSCustomObject]@{
          registry_key = $key
          value_name   = $name
          command      = $rawPath
          executable   = $exe
          signed       = $sigInfo.signed
          trusted_microsoft = $sigInfo.trusted
        }
      }
    }
  } catch {
Write-Log "Failed to read ${key}: $_" 'WARN'

  }
}

$results = @{
  timestamp      = (Get-Date).ToString('o')
  host           = $HostName
  action         = "list_registry_run_keys"
  run_key_entries = $entries
}

try {
  $results | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
  Write-Log "Registry Run keys JSON appended to $ARLog" 'INFO'
} catch {
  Write-Log $_.Exception.Message 'ERROR'
}

$dur = [int]((Get-Date) - $runStart).TotalSeconds
Write-Log "=== SCRIPT END : duration ${dur}s ==="
