[CmdletBinding()]
param(
  [string]$LogPath = "$env:TEMP\ListWindowsUsers-script.log",
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
Write-Log "=== SCRIPT START : List Windows Users ==="

try {
  $allGroups = Get-LocalGroup
  $users = Get-LocalUser | Where-Object { $_.Name -match '^\w' }

  $userList = foreach ($u in $users) {
    $uname = $u.Name.Trim()
    $userGroups = @()

    foreach ($group in $allGroups) {
      try {
        $members = Get-LocalGroupMember -Group $group.Name -ErrorAction Stop
        if ($members | Where-Object { $_.Name -eq $uname }) {
          $userGroups += $group.Name
        }
      } catch {}
    }

    [PSCustomObject]@{
      username           = $uname
      fullname           = $u.FullName
      enabled            = $u.Enabled
      description        = $u.Description
      password_required  = $u.PasswordRequired
      password_changeable= $u.PasswordChangeable
      password_expired   = $u.PasswordExpired
      user_may_change_pw = $u.UserMayChangePassword
      lastlogon          = if ($u.LastLogon) { $u.LastLogon.ToString("o") } else { $null }
      account_expires    = if ($u.AccountExpires) { $u.AccountExpires.ToString("o") } else { $null }
      groups             = ($userGroups | Sort-Object -Unique) -join ", "
    }
  }

  $results = @{
    timestamp = (Get-Date).ToString('o')
    host      = $HostName
    action    = "list_windows_users"
    users     = $userList
  }

  $results | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
  Write-Log "User list JSON appended to $ARLog" 'INFO'

} catch {
  Write-Log $_.Exception.Message 'ERROR'
  $errorObj = [pscustomobject]@{
    timestamp = (Get-Date).ToString('o')
    host      = $HostName
    action    = 'list_windows_users'
    status    = 'error'
    error     = $_.Exception.Message
  }
  $errorObj | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
}
finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
