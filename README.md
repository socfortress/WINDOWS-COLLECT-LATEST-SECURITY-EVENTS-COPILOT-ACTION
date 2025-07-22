# PowerShell Collect Latest Security Events Template

This repository provides a template for PowerShell-based active response scripts for security automation and incident response. The template ensures consistent logging, error handling, and execution flow for collecting recent security, Defender, and (optionally) Sysmon events from the Windows Event Log.

---

## Overview

The `Collect-Latest-SecurityEvents.ps1` script collects Windows Security, Defender, and optionally Sysmon events from the last N hours, based on event IDs relevant to authentication, privilege escalation, process creation, and malware detection. All actions, results, and errors are logged in both a script log and an active-response log, making the script suitable for integration with SOAR platforms, SIEMs, and incident response workflows.

---

## Template Structure

### Core Components

- **Parameter Definitions**: Configurable script parameters
- **Logging Framework**: Consistent logging with timestamps and rotation
- **Event Collection Logic**: Filters and collects relevant event logs
- **JSON Output**: Standardized response format
- **Execution Timing**: Performance monitoring

---

## How Scripts Are Invoked

### Command Line Execution

```powershell
.\Collect-Latest-SecurityEvents.ps1 [-HoursBack <int>] [-IncludeSysmon] [-LogPath <string>] [-ARLog <string>]
```

### Parameters

| Parameter      | Type    | Default Value                                                    | Description                                  |
|----------------|---------|------------------------------------------------------------------|----------------------------------------------|
| `HoursBack`    | int     | `24`                                                             | How many hours back to collect events        |
| `IncludeSysmon`| switch  | (off)                                                            | Include Sysmon events in the collection      |
| `LogPath`      | string  | `$env:TEMP\Collect-Latest-SecurityEvents.log`                    | Path for execution logs                      |
| `ARLog`        | string  | `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log` | Path for active response JSON output         |

---

### Example Invocations

```powershell
# Basic execution with default parameters
.\Collect-Latest-SecurityEvents.ps1

# Collect last 48 hours and include Sysmon events
.\Collect-Latest-SecurityEvents.ps1 -HoursBack 48 -IncludeSysmon

# Custom log path
.\Collect-Latest-SecurityEvents.ps1 -LogPath "C:\Logs\SecurityEvents.log"

# Integration with OSSEC/Wazuh active response
.\Collect-Latest-SecurityEvents.ps1 -ARLog "C:\ossec\active-responses.log"
```

---

## Template Functions

### `Write-Log`
**Purpose**: Standardized logging with severity levels.

**Parameters**:
- `Level` (string): Log level - 'INFO', 'WARN', 'ERROR', 'DEBUG'
- `Message` (string): The log message

**Features**:
- Timestamped output
- File logging

**Usage**:
```powershell
Write-Log INFO "Collected $($securityEvents.Count) Security, $($defenderEvents.Count) Defender, $SysmonCount Sysmon events (total $Total) from last $HoursBack hrs. JSON appended."
Write-Log ERROR "Failed to collect events: $_"
```

---

### `Rotate-Log`
**Purpose**: Manages log file size and rotation.

**Features**:
- Monitors log file size (default: 100KB)
- Maintains a configurable number of backups (default: 5)
- Rotates logs automatically

**Configuration Variables**:
- `$LogMaxKB`: Max log file size in KB
- `$LogKeep`: Number of rotated logs to retain

---

### `Log-JSON`
**Purpose**: Appends structured JSON results to the active response log.

**Parameters**:
- `Data`: The collected events array

---

## Script Execution Flow

1. **Initialization**
   - Parameter validation and assignment
   - Error action preference
   - Log rotation

2. **Execution**
   - Collects Security, Defender, and optionally Sysmon events from the last N hours
   - Filters by relevant event IDs
   - Logs findings

3. **Completion**
   - Outputs collected events as JSON to the active response log
   - Logs script end and duration
   - Displays summary in console

4. **Error Handling**
   - Catches and logs exceptions
   - Outputs error details to the log

---

## JSON Output Format

### Events Example

```json
{
  "timestamp": "2025-07-22T10:30:45.123Z",
  "hostname": "HOSTNAME",
  "type": "latest_security_events",
  "hours_collected": 24,
  "total_events": 12,
  "data": [
    {
      "Id": 4624,
      "ProviderName": "Microsoft-Windows-Security-Auditing",
      "TimeCreated": "2025-07-22T09:00:00.000Z",
      "LevelDisplayName": "Information",
      "Message": "An account was successfully logged on."
    }
  ]
}
```

---

## Implementation Guidelines

1. Use the provided logging and error handling functions.
2. Customize the event IDs as needed for your environment.
3. Ensure JSON output matches your SOAR/SIEM requirements.
4. Test thoroughly in a non-production environment.

---

## Security Considerations

- Run with the minimum required privileges.
- Validate all input parameters.
- Secure log files and output locations.
- Monitor for errors and failed event collection.

---

## Troubleshooting

- **Permission Errors**: Run as Administrator.
- **Event Log Access Issues**: Ensure the script has access to all relevant logs.
- **Log Output**: Check file permissions and disk space.

---

## License

This template is provided as-is for security automation and incident
