[CmdletBinding()]
param(
  [string]$LogPath = "$env:TEMP\BrowserHistory-script.log",
  [string]$ARLog = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference = 'Stop'
$HostName = $env:COMPUTERNAME
$LogMaxKB = 100
$LogKeep = 5

function Write-Log {
  param([string]$Message, [ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level = 'INFO')
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

function Ensure-SqliteModule {
  if (-not (Get-Module -ListAvailable -Name PSSQLite)) {
    Write-Log "PSSQLite module not found. Attempting install..." 'INFO'
    try {
      Install-PackageProvider -Name NuGet -Force -Scope CurrentUser | Out-Null
      Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
      Install-Module -Name PSSQLite -Scope CurrentUser -Force -ErrorAction Stop
      Write-Log "PSSQLite installed successfully." 'INFO'
    } catch {
      Write-Log "Failed to install PSSQLite: $($_.Exception.Message)" 'ERROR'
      throw
    }
  }
  Import-Module PSSQLite -Force
}

function Query-Sqlite($dbPath, $query) {
  $temp = "$env:TEMP\" + [IO.Path]::GetFileName($dbPath)
  try {
    Copy-Item $dbPath $temp -Force -ErrorAction Stop
    return Invoke-SqliteQuery -DataSource $temp -Query $query
  } catch {
    Write-Log ("Cannot access database {0}: {1}" -f $dbPath, $_.Exception.Message) 'ERROR'
    return @()
  }
}

function Read-ChromeArtifacts {
  $path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
  if (-not (Test-Path $path)) { return @{} }

  return @{
    history   = Query-Sqlite "$path\History" "SELECT url, title, datetime(last_visit_time/1000000-11644473600,'unixepoch') as last_visit FROM urls ORDER BY last_visit_time DESC LIMIT 50"
    bookmarks = Get-Content "$path\Bookmarks" -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
    downloads = Query-Sqlite "$path\History" "SELECT target_path, tab_url, datetime(start_time/1000000-11644473600,'unixepoch') as start_time FROM downloads ORDER BY start_time DESC LIMIT 50"
    cookies   = Query-Sqlite "$path\Network\Cookies" "SELECT host_key, name, value, datetime(expires_utc/1000000-11644473600,'unixepoch') as expires FROM cookies LIMIT 50"
  }
}

function Read-EdgeArtifacts {
  Stop-Process -Name "msedge" -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 2

  $path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
  if (-not (Test-Path $path)) { return @{} }

  return @{
    history   = Query-Sqlite "$path\History" "SELECT url, title, datetime(last_visit_time/1000000-11644473600,'unixepoch') as last_visit FROM urls ORDER BY last_visit_time DESC LIMIT 50"
    bookmarks = Get-Content "$path\Bookmarks" -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
    downloads = Query-Sqlite "$path\History" "SELECT target_path, tab_url, datetime(start_time/1000000-11644473600,'unixepoch') as start_time FROM downloads ORDER BY start_time DESC LIMIT 50"
    cookies   = Query-Sqlite "$path\Network\Cookies" "SELECT host_key, name, value, datetime(expires_utc/1000000-11644473600,'unixepoch') as expires FROM cookies LIMIT 50"
  }
}

function Read-FirefoxArtifacts {
  $results = @{}
  $profiles = Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Directory -ErrorAction SilentlyContinue
  foreach ($profile in $profiles) {
    $p = $profile.FullName
    $places = "$p\places.sqlite"
    $cookies = "$p\cookies.sqlite"
    $downloads = "$p\downloads.sqlite"
    if (Test-Path $places) {
      $results.history = Query-Sqlite $places "SELECT url, title, datetime(last_visit_date/1000000,'unixepoch') as last_visit FROM moz_places ORDER BY last_visit_date DESC LIMIT 50"
    }
    if (Test-Path $cookies) {
      $results.cookies = Query-Sqlite $cookies "SELECT host, name, value, datetime(expiry,'unixepoch') as expires FROM moz_cookies LIMIT 50"
    }
    if (Test-Path $downloads) {
      $results.downloads = Query-Sqlite $downloads "SELECT name, source, datetime(endTime/1000000,'unixepoch') as end_time FROM moz_downloads LIMIT 50"
    }
    break
  }
  return $results
}

# === MAIN ===
Rotate-Log
$runStart = Get-Date
Write-Log "=== SCRIPT START : Browser History Collection ==="

try {
  Ensure-SqliteModule

  $results = @{
    timestamp = (Get-Date).ToString('o')
    host      = $HostName
    action    = 'collect_browser_artifacts'
    chrome    = Read-ChromeArtifacts
    edge      = Read-EdgeArtifacts
    firefox   = Read-FirefoxArtifacts
  }

  $results | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
  Write-Log "JSON appended to $ARLog" 'INFO'
}
catch {
  Write-Log $_.Exception.Message 'ERROR'
  $errorObj = [pscustomobject]@{
    timestamp = (Get-Date).ToString('o')
    host      = $HostName
    action    = 'collect_browser_artifacts'
    status    = 'error'
    error     = $_.Exception.Message
  }
  $errorObj | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
}
finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
