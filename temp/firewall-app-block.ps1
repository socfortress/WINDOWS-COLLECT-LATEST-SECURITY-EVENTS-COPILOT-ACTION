[CmdletBinding()]
param(
  [int]$MaxWaitSeconds = 300,
  [string]$LogPath = "$env:TEMP\BlockApp-script.log",
  [string]$ARLog = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference = 'Stop'
$HostName = $env:COMPUTERNAME
$LogMaxKB = 100
$LogKeep = 5

function Write-Log {
 param([string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
 $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
 $line="[$ts][$Level] $Message"
 switch($Level){
  'ERROR' { Write-Host $line -ForegroundColor Red }
  'WARN'  { Write-Host $line -ForegroundColor Yellow }
  'DEBUG' { if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')) { Write-Verbose $line } }
  default { Write-Host $line }
 }
 Add-Content -Path $LogPath -Value $line
}

function Rotate-Log {
 if(Test-Path $LogPath -PathType Leaf){
  if((Get-Item $LogPath).Length/1KB -gt $LogMaxKB){
   for($i=$LogKeep-1;$i -ge 0;$i--){
    $old="$LogPath.$i";$new="$LogPath."+($i+1)
    if(Test-Path $old){Rename-Item $old $new -Force}
   }
   Rename-Item $LogPath "$LogPath.1" -Force
  }
 }
}

Rotate-Log
$runStart = Get-Date
Write-Log "=== SCRIPT START : Block Application ==="

try {
  # Prompt for EXE path
  $ExePath = Read-Host "Enter full path of the application (.exe)"
  if (-not (Test-Path $ExePath)) {
    throw "File not found: $ExePath"
  }

  # Prompt for app name
  $AppName = Read-Host "Enter application name (label for rule)"
  if (-not $AppName) {
    throw "Application name is required."
  }

  # Prepare rule names
  $RuleBase = "BlockApp_$($AppName.Replace(' ', '_'))"
  $RuleInbound = "$RuleBase`_In"
  $RuleOutbound = "$RuleBase`_Out"

  # Check for existing rules
  $existingIn = Get-NetFirewallRule -DisplayName $RuleInbound -ErrorAction SilentlyContinue
  $existingOut = Get-NetFirewallRule -DisplayName $RuleOutbound -ErrorAction SilentlyContinue

  if ($existingIn -or $existingOut) {
    Write-Log "One or both rules already exist — skipping" 'WARN'
    $status = "already_exists"
  }
  else {
    # Block Outbound
    New-NetFirewallRule -DisplayName $RuleOutbound `
                        -Direction Outbound `
                        -Program $ExePath `
                        -Action Block `
                        -Enabled True `
                        -Profile Any `
                        -Protocol Any | Out-Null

    # Block Inbound
    New-NetFirewallRule -DisplayName $RuleInbound `
                        -Direction Inbound `
                        -Program $ExePath `
                        -Action Block `
                        -Enabled True `
                        -Profile Any `
                        -Protocol Any | Out-Null

    Write-Log "Firewall rules created to block app: $AppName" 'INFO'
    $status = "app_blocked"
  }

  # JSON log output
  $logObj = [pscustomobject]@{
    timestamp     = (Get-Date).ToString('o')
    host          = $HostName
    action        = "block_app"
    app_name      = $AppName
    exe_path      = $ExePath
    status        = $status
    rule_inbound  = $RuleInbound
    rule_outbound = $RuleOutbound
  }

  $logObj | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
  Write-Log "JSON appended to $ARLog" 'INFO'
}
catch {
  Write-Log $_.Exception.Message 'ERROR'
  $logObj = [pscustomobject]@{
    timestamp = (Get-Date).ToString('o')
    host      = $HostName
    action    = "block_app"
    status    = "error"
    error     = $_.Exception.Message
  }
  $logObj | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
}
finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
