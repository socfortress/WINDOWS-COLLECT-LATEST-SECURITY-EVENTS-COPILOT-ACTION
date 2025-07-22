<#
  List-ScheduledTasks.ps1
  Enumerate all scheduled tasks, include last 5 run attempts, output JSON.
  Keeps logs in SOC-friendly format.
#>

[CmdletBinding()]
param(
  [string]$LogPath = "$env:TEMP\ListScheduledTasks-script.log",
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
Write-Log "=== SCRIPT START : List Scheduled Tasks ==="

try {
  $taskList = Get-ScheduledTask | ForEach-Object {
    $task = $_
    $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue

    $history = @()
    try {
      $filter = @{
        LogName   = 'Microsoft-Windows-TaskScheduler/Operational'
        Id        = 201 
        StartTime = (Get-Date).AddDays(-7)
      }
      $events = Get-WinEvent -FilterHashtable $filter -MaxEvents 200 -ErrorAction SilentlyContinue |
        Where-Object { $_.Properties[0].Value -eq ($task.TaskPath + $task.TaskName) } |
        Sort-Object TimeCreated -Descending | Select-Object -First 5

      foreach ($ev in $events) {
        $time = To-ISO8601 $ev.TimeCreated
        $result = $ev.Properties[1].Value
        $history += @{ time = $time; result = $result }
      }
    } catch { }

    [PSCustomObject]@{
      task_name       = $task.TaskName
      path            = $task.TaskPath
      state           = $info.State
      last_run_time   = To-ISO8601 $info.LastRunTime
      next_run_time   = To-ISO8601 $info.NextRunTime
      last_task_result= $info.LastTaskResult
      author          = $task.Author
      run_level       = $task.Principal.RunLevel
      triggers        = ($task.Triggers | ForEach-Object { $_.TriggerType } | Sort-Object -Unique) -join "; "
      actions         = ($task.Actions | ForEach-Object { $_.Execute }) -join "; "
      history         = $history
    }
  }

  $results = @{
    timestamp       = (Get-Date).ToString('o')
    host            = $HostName
    action          = "list_scheduled_tasks"
    scheduled_tasks = $taskList
  }

  $results | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
  Write-Log "Scheduled tasks JSON (with history) appended to $ARLog" 'INFO'

} catch {
  Write-Log $_.Exception.Message 'ERROR'
  $errorObj = [pscustomobject]@{
    timestamp = (Get-Date).ToString('o')
    host      = $HostName
    action    = 'list_scheduled_tasks'
    status    = 'error'
    error     = $_.Exception.Message
  }
  $errorObj | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
}
finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
