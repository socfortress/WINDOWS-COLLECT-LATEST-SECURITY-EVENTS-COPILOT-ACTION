[CmdletBinding()]
param(
  [int]$MaxWaitSeconds = 300,
  [string]$LogPath = "$env:TEMP\UnblockApp-script.log",
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
Write-Log "=== SCRIPT START : Unblock Application ==="

try {
  # Prompt for application name
  $AppName = Read-Host "Enter the application name used during blocking"
  if (-not $AppName) {
    throw "Application name is required."
  }

  $RuleBase = "BlockApp_$($AppName.Replace(' ', '_'))"
  $RuleInbound = "$RuleBase`_In"
  $RuleOutbound = "$RuleBase`_Out"

  $removedIn = $false
  $removedOut = $false

  $ruleIn = Get-NetFirewallRule -DisplayName $RuleInbound -ErrorAction SilentlyContinue
  $ruleOut = Get-NetFirewallRule -DisplayName $RuleOutbound -ErrorAction SilentlyContinue

  if ($ruleIn) {
    Remove-NetFirewallRule -DisplayName $RuleInbound
    Write-Log "Removed Inbound rule: $RuleInbound" 'INFO'
    $removedIn = $true
  } else {
    Write-Log "Inbound rule not found: $RuleInbound" 'WARN'
  }

  if ($ruleOut) {
    Remove-NetFirewallRule -DisplayName $RuleOutbound
    Write-Log "Removed Outbound rule: $RuleOutbound" 'INFO'
    $removedOut = $true
  } else {
    Write-Log "Outbound rule not found: $RuleOutbound" 'WARN'
  }

  $status = if ($removedIn -or $removedOut) { 'unblocked' } else { 'not_found' }

  # JSON log
  $logObj = [pscustomobject]@{
    timestamp     = (Get-Date).ToString('o')
    host          = $HostName
    action        = "unblock_app"
    app_name      = $AppName
    rule_inbound  = $RuleInbound
    rule_outbound = $RuleOutbound
    status        = $status
  }

  $logObj | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
  Write-Log "JSON appended to $ARLog" 'INFO'
}
catch {
  Write-Log $_.Exception.Message 'ERROR'
  $logObj = [pscustomobject]@{
    timestamp = (Get-Date).ToString('o')
    host      = $HostName
    action    = "unblock_app"
    status    = "error"
    error     = $_.Exception.Message
  }
  $logObj | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
}
finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
