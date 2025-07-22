[CmdletBinding()]
param(
  [string]$LogPath = "$env:TEMP\EnforcePasswordPolicy-script.log",
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
Write-Log "=== SCRIPT START : Enforce Strong Password Policy ==="

try {
  $enforced = @()
  $minLength = (Get-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -Name "MinimumPasswordLength" -ErrorAction SilentlyContinue).MinimumPasswordLength
  if ($minLength -lt 12) {
    net accounts /minpwlen:12 | Out-Null
    Write-Log "Minimum password length set to 12" 'INFO'
    $enforced += @{ setting = "min_password_length"; value = 12 }
  }

  $complexity = (Get-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -Name "PasswordComplexity" -ErrorAction SilentlyContinue).PasswordComplexity
  if ($complexity -ne 1) {
    secedit /export /cfg "$env:TEMP\secpol.cfg" | Out-Null
    (Get-Content "$env:TEMP\secpol.cfg").ForEach{
      if ($_ -match '^PasswordComplexity') { $_ -replace '\d', '1' }
      else { $_ }
    } | Set-Content "$env:TEMP\secpol.cfg"
    secedit /configure /db secedit.sdb /cfg "$env:TEMP\secpol.cfg" /quiet | Out-Null
    Write-Log "Password complexity enforced" 'INFO'
    $enforced += @{ setting = "password_complexity"; value = "enabled" }
  }

$lockoutRaw = (net accounts) -match 'Lockout threshold' | ForEach-Object { ($_ -split ":")[1].Trim() }
$lockout = if ($lockoutRaw -match '^\d+$') { [int]$lockoutRaw } else { 0 }
if ($lockout -gt 5) {
    net accounts /lockoutthreshold:5 | Out-Null
    Write-Log "Account lockout threshold set to 5" 'INFO'
    $enforced += @{ setting = "lockout_threshold"; value = 5 }
  }
  
  $usersToPrompt = Get-LocalUser | Where-Object {
    -not $_.PasswordRequired -and $_.Enabled -and $_.Name -notin @('Administrator','DefaultAccount','Guest')
  }

try {
  $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
  Set-ItemProperty -Path $regPath -Name "AutoAdminLogon" -Value "0" -Force
  Remove-ItemProperty -Path $regPath -Name "DefaultPassword" -ErrorAction SilentlyContinue
  Write-Log "Auto logon disabled to enforce login screen." 'INFO'
  $enforced += @{ setting = "autologon"; value = "disabled" }
} catch {
  Write-Log "Failed to disable autologon: $($_.Exception.Message)" 'ERROR'
}

foreach ($user in $usersToPrompt) {
  try {
    Write-Log "User '$($user.Name)' has no password. Forcing password change on next logon." 'INFO'
    $temporaryPassword = "123"  
    net user $($user.Name) $temporaryPassword | Out-Null
    net user $($user.Name) /logonpasswordchg:yes | Out-Null
    Write-Log "Temporary password set for '$($user.Name)'. Forced change at next logon." 'INFO'
    $enforced += @{ setting = "force_password_change"; user = $user.Name }
  } catch {
    Write-Log "Failed to set password change for '$($user.Name)': $($_.Exception.Message)" 'ERROR'
  }
}

  $results = @{
    host      = $HostName
    timestamp = (Get-Date).ToString('o')
    action    = "enforce_strong_password_policy"
    enforced  = $enforced
  }

  $results | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
  Write-Log "JSON appended to $ARLog" 'INFO'

} catch {
  Write-Log $_.Exception.Message 'ERROR'
  $errorObj = [pscustomobject]@{
    timestamp = (Get-Date).ToString('o')
    host      = $HostName
    action    = 'enforce_strong_password_policy'
    status    = 'error'
    error     = $_.Exception.Message
  }
  $errorObj | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
}
finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
