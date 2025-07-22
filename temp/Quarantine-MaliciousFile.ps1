[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$TargetPath,

  [string]$LogPath = "$env:TEMP\QuarantineFile-script.log",
  [string]$ARLog = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference = 'Stop'
$HostName = $env:COMPUTERNAME
$LogMaxKB = 100
$LogKeep = 5
$QuarantineDir = "C:\Quarantine"

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
Write-Log "=== SCRIPT START : Quarantine File [$TargetPath] ==="

try {
  if (-not (Test-Path $TargetPath -PathType Leaf)) {
    throw "Target file not found: $TargetPath"
  }

  if (-not (Test-Path $QuarantineDir)) {
    New-Item -Path $QuarantineDir -ItemType Directory -Force | Out-Null
  }

  $timestamp = Get-Date -Format "yyyyMMddHHmmss"
  $fileName = [System.IO.Path]::GetFileNameWithoutExtension($TargetPath)
  $ext = [System.IO.Path]::GetExtension($TargetPath)
  $newName = "${fileName}_${timestamp}.quarantined"
  $quarantinePath = Join-Path $QuarantineDir $newName

  Move-Item -Path $TargetPath -Destination $quarantinePath -Force
  Write-Log "Moved file to quarantine: $quarantinePath" 'INFO'

  # Restrict permissions: Remove all, allow only Administrators
  $acl = New-Object System.Security.AccessControl.FileSecurity
  $admins = [System.Security.Principal.NTAccount]"BUILTIN\Administrators"
  $acl.SetOwner($admins)
  $acl.SetAccessRuleProtection($true, $false)  # disable inheritance
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($admins, "FullControl", "Allow")
  $acl.AddAccessRule($rule)
  Set-Acl -Path $quarantinePath -AclObject $acl
  Write-Log "Stripped file permissions and restricted to Administrators" 'INFO'

  $results = @{
    host      = $HostName
    timestamp = (Get-Date).ToString('o')
    action    = "quarantine_file"
    original  = $TargetPath
    quarantined_as = $quarantinePath
  }

  $results | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
  Write-Log "Result JSON appended to $ARLog" 'INFO'

} catch {
  Write-Log $_.Exception.Message 'ERROR'
  $errorObj = [pscustomobject]@{
    timestamp = (Get-Date).ToString('o')
    host      = $HostName
    action    = 'quarantine_file'
    status    = 'error'
    error     = $_.Exception.Message
  }
  $errorObj | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
}
finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
