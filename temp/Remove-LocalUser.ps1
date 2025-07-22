[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$TargetUser,

  [string]$LogPath = "$env:TEMP\RemoveLocalUser-script.log",
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

Rotate-Log
$runStart = Get-Date
Write-Log "=== SCRIPT START : Remove Local User [$TargetUser] ==="

try {
  $user = Get-LocalUser -Name $TargetUser -ErrorAction Stop

  if ($user.Name -in @('Administrator', 'DefaultAccount', 'Guest', 'WDAGUtilityAccount')) {
    throw "Refusing to delete protected system account '$TargetUser'"
  }

  Remove-LocalUser -Name $TargetUser -ErrorAction Stop
  Write-Log "User '$TargetUser' has been removed." 'INFO'

  $result = @{
    host      = $HostName
    timestamp = (Get-Date).ToString('o')
    action    = "remove_local_user"
    user      = $TargetUser
    status    = "removed"
  }

  $result | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
  Write-Log "Result JSON appended to $ARLog" 'INFO'

} catch {
  Write-Log $_.Exception.Message 'ERROR'
  $errorObj = [pscustomobject]@{
    timestamp = (Get-Date).ToString('o')
    host      = $HostName
    action    = 'remove_local_user'
    target    = $TargetUser
    status    = 'error'
    error     = $_.Exception.Message
  }
  $errorObj | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
}
finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
