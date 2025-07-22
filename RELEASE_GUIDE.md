# Release Guide

This guide explains how to use the automated release system for PowerShell active response scripts.

## Quick Start

### 1. Create a Release via Git Tag
```bash
# Create and push a version tag
git tag v1.0.0
git push origin v1.0.0
```

### 2. Manual Release via GitHub Actions
1. Go to **GitHub Actions** tab
2. Click on **"Create PowerShell Script Release"**
3. Click **"Run workflow"**
4. Fill in the details:
   - **Version**: `v1.0.0` (or your desired version)
   - **Script name**: `automation-template` (or your script name without .ps1)
5. Click **"Run workflow"**

## What Gets Created

Each release automatically generates:

- **Production Scripts**:
  - `script-name.ps1` - Generic named script with metadata
  - `script-name-v1.0.0.ps1` - Version-specific script
  
- **Installation Tools**:
  - `install.ps1` - Automated installer with integrity checking
  - `checksums.txt` - SHA256 checksums for verification
  
- **Documentation**:
  - `README.md` - Release-specific usage instructions

## Usage Examples

### For End Users (Downloading Scripts)

#### Option 1: Automated Installation
```powershell
# Download installer
Invoke-WebRequest -Uri "https://github.com/socfortress/ActiveResponsePowershell-Template/releases/download/v1.0.0/install.ps1" -OutFile "install.ps1"

# Run installer (includes integrity verification)
.\install.ps1

# Or install to specific directory
.\install.ps1 -InstallPath "C:\Scripts\ActiveResponse"
```

#### Option 2: Direct Download
```powershell
# Download script directly
Invoke-WebRequest -Uri "https://github.com/socfortress/ActiveResponsePowershell-Template/releases/download/v1.0.0/automation-template.ps1" -OutFile "automation-template.ps1"

# Execute the script
PowerShell.exe -ExecutionPolicy Bypass -File "automation-template.ps1"
```

#### Option 3: One-liner (Use with caution in production)
```powershell
# Execute directly from URL
Invoke-WebRequest -Uri "https://github.com/socfortress/ActiveResponsePowershell-Template/releases/download/v1.0.0/automation-template.ps1" | Invoke-Expression
```

## Versioning

Use semantic versioning (semver) format:
- `v1.0.0` - Major release (breaking changes)
- `v1.1.0` - Minor release (new features, backward compatible)
- `v1.0.1` - Patch release (bug fixes)

## Security Features

- **Integrity Verification**: All files include SHA256 checksums
- **Source Transparency**: Full script source code is visible
- **Metadata Tracking**: Version, build date, and commit info embedded
- **Automated Verification**: Install script checks file integrity by default

## Testing Locally

To test the build process locally:

```bash
cd /path/to/your/repo

# Set environment variables
export SCRIPT_NAME="automation-template"
export VERSION="v1.0.0-test"
export GITHUB_REPOSITORY="socfortress/ActiveResponsePowershell-Template"
export GITHUB_SHA="$(git rev-parse HEAD)"

# Run build script
pwsh ./scripts/build-release.ps1

# Check results
ls release/
```

## Troubleshooting

### Common Issues

1. **Workflow fails with "Script not found"**
   - Ensure the script name matches the actual .ps1 file in the repository root
   - Check the `script_name` parameter doesn't include the .ps1 extension

2. **Permission denied when running installer**
   - Run PowerShell as Administrator or use `-ExecutionPolicy Bypass`

3. **Checksum verification fails**
   - File may have been corrupted during download
   - Re-download the script and try again

### GitHub Actions Permissions

Ensure your repository has the following permissions enabled:
- **Actions**: Read and write
- **Contents**: Read and write
- **Metadata**: Read

These are typically enabled by default but may need to be checked in repository settings.
