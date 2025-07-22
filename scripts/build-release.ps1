# PowerShell Build Script for GitHub Release
param(
    [string]$ScriptName = $env:SCRIPT_NAME,
    [string]$Version = $env:VERSION,
    [string]$Repository = $env:GITHUB_REPOSITORY,
    [string]$CommitSha = $env:GITHUB_SHA
)

$ErrorActionPreference = 'Stop'

Write-Host "🚀 Building release for $ScriptName $Version" -ForegroundColor Green

# Create release directory
$releaseDir = "release"
if (Test-Path $releaseDir) {
    Remove-Item $releaseDir -Recurse -Force
}
New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null

# Validate source script exists
$sourceScript = "./${ScriptName}.ps1"
if (-not (Test-Path $sourceScript)) {
    Write-Error "Source script not found: $sourceScript"
    exit 1
}

# Read the original script
$scriptContent = Get-Content $sourceScript -Raw
$buildDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'

# Create metadata header
$header = @"
<#
.SYNOPSIS
    $ScriptName - PowerShell Active Response Script $Version
    
.DESCRIPTION
    Production release of $ScriptName for active response automation.
    
.METADATA
    Repository: https://github.com/$Repository
    Release Version: $Version
    Build Date: $buildDate
    Commit SHA: $CommitSha
    
.NOTES
    This script is part of the PowerShell Active Response framework.
    For documentation and updates, visit: https://github.com/$Repository
#>

"@

# Create production scripts
$productionScript = $header + $scriptContent

# Save versioned script
$versionedPath = "${releaseDir}/${ScriptName}-${Version}.ps1"
$productionScript | Out-File -FilePath $versionedPath -Encoding UTF8

# Save generic script
$genericPath = "${releaseDir}/${ScriptName}.ps1"
$productionScript | Out-File -FilePath $genericPath -Encoding UTF8

Write-Host "✅ Production scripts created:"
Write-Host "  - $versionedPath"
Write-Host "  - $genericPath"

# Generate checksums
$checksumFile = "${releaseDir}/checksums.txt"
if (Test-Path $checksumFile) { Remove-Item $checksumFile }
Get-ChildItem $releaseDir -Filter "*.ps1" | ForEach-Object {
    $hash = Get-FileHash $_.FullName -Algorithm SHA256
    "${_.Name}: $($hash.Hash)" | Out-File -FilePath $checksumFile -Append -Encoding UTF8
}
Write-Host "✅ Checksums generated"

# Create installation script
$installScript = @"
<#
.SYNOPSIS
    Automated installer for $ScriptName $Version
    
.DESCRIPTION
    Downloads and installs the $ScriptName PowerShell script from GitHub releases.
    
.PARAMETER InstallPath
    Directory where the script will be installed. Default: Current directory
    
.PARAMETER Verify
    Verify script integrity using checksums. Default: True
    
.EXAMPLE
    # Download and run installer
    Invoke-WebRequest -Uri "https://github.com/$Repository/releases/download/$Version/install.ps1" -OutFile "install.ps1"
    .\install.ps1
    
.EXAMPLE
    # Install to specific directory
    .\install.ps1 -InstallPath "C:\Scripts\ActiveResponse"
#>

param(
    [string]`$InstallPath = ".",
    [bool]`$Verify = `$true
)

`$ErrorActionPreference = 'Stop'

# Release configuration
`$RepoUrl = "https://github.com/$Repository"
`$Version = "$Version"
`$ScriptName = "$ScriptName"
`$BaseUrl = "`$RepoUrl/releases/download/`$Version"
`$ScriptUrl = "`$BaseUrl/`$ScriptName.ps1"
`$ChecksumUrl = "`$BaseUrl/checksums.txt"

Write-Host "🚀 Installing `$ScriptName `$Version..." -ForegroundColor Green
Write-Host "📍 Install Path: `$InstallPath"

# Create install directory if needed
if (-not (Test-Path `$InstallPath)) {
    New-Item -ItemType Directory -Path `$InstallPath -Force | Out-Null
    Write-Host "📁 Created directory: `$InstallPath"
}

# Download script
`$scriptPath = Join-Path `$InstallPath "`$ScriptName.ps1"
Write-Host "⬇️  Downloading script..."
try {
    Invoke-WebRequest -Uri `$ScriptUrl -OutFile `$scriptPath -UseBasicParsing
    Write-Host "✅ Script downloaded: `$scriptPath"
}
catch {
    Write-Error "❌ Failed to download script: `$(`$_.Exception.Message)"
    exit 1
}

# Verify integrity if requested
if (`$Verify) {
    Write-Host "🔍 Verifying script integrity..."
    try {
        `$checksumContent = Invoke-WebRequest -Uri `$ChecksumUrl -UseBasicParsing | Select-Object -ExpandProperty Content
        `$expectedHash = (`$checksumContent -split "`n" | Where-Object { `$_ -like "`$ScriptName.ps1:*" } -split ": ")[1].Trim()
        
        if (`$expectedHash) {
            `$actualHash = (Get-FileHash `$scriptPath -Algorithm SHA256).Hash
            if (`$actualHash -eq `$expectedHash) {
                Write-Host "✅ Script integrity verified"
            } else {
                Write-Error "❌ Script integrity check failed!"
                Write-Error "Expected: `$expectedHash"
                Write-Error "Got: `$actualHash"
                exit 1
            }
        } else {
            Write-Warning "⚠️  Could not find checksum for verification"
        }
    }
    catch {
        Write-Warning "⚠️  Could not verify script integrity: `$(`$_.Exception.Message)"
    }
}

Write-Host ""
Write-Host "🎉 Installation completed successfully!" -ForegroundColor Green
Write-Host "📄 Script location: `$scriptPath"
Write-Host ""
Write-Host "📖 Usage examples:"
Write-Host "   PowerShell.exe -ExecutionPolicy Bypass -File ""`$scriptPath"""
Write-Host "   # Or with parameters:"
Write-Host "   PowerShell.exe -ExecutionPolicy Bypass -File ""`$scriptPath"" -MaxWaitSeconds 600"
Write-Host ""
Write-Host "🔗 Documentation: `$RepoUrl"
"@

$installScript | Out-File -FilePath "${releaseDir}/install.ps1" -Encoding UTF8
Write-Host "✅ Installation script created"

# Create release documentation
$releaseReadme = @"
# $ScriptName Release $Version

This release contains production-ready PowerShell scripts for active response automation.

## Files

- **$ScriptName.ps1** - Main PowerShell script (generic name)
- **$ScriptName-$Version.ps1** - Versioned PowerShell script
- **install.ps1** - Automated installation script
- **checksums.txt** - SHA256 checksums for integrity verification
- **README.md** - This file

## Quick Installation

### Option 1: Automated Installation (Recommended)
``````powershell
# Download and run installer
Invoke-WebRequest -Uri "https://github.com/$Repository/releases/download/$Version/install.ps1" -OutFile "install.ps1"
.\install.ps1
``````

### Option 2: Manual Download
``````powershell
# Download script directly
Invoke-WebRequest -Uri "https://github.com/$Repository/releases/download/$Version/$ScriptName.ps1" -OutFile "$ScriptName.ps1"
``````

### Option 3: Direct Execution (One-liner)
``````powershell
# Execute directly from URL (use with caution in production)
Invoke-WebRequest -Uri "https://github.com/$Repository/releases/download/$Version/$ScriptName.ps1" | Invoke-Expression
``````

## Usage

``````powershell
# Basic execution
PowerShell.exe -ExecutionPolicy Bypass -File "$ScriptName.ps1"

# With custom parameters
PowerShell.exe -ExecutionPolicy Bypass -File "$ScriptName.ps1" -MaxWaitSeconds 600 -LogPath "C:\Logs\my-script.log"
``````

## Security Considerations

1. **Script Verification**: Always verify script integrity using the provided checksums
2. **Execution Policy**: Scripts may require bypassing execution policy for remote execution
3. **Permissions**: Ensure the script has appropriate permissions for its intended actions
4. **Network Security**: Consider network policies when downloading scripts in production environments

## Integrity Verification

Verify the downloaded script using PowerShell:

``````powershell
# Get file hash
`$actualHash = (Get-FileHash "$ScriptName.ps1" -Algorithm SHA256).Hash

# Compare with expected hash from checksums.txt
# Expected hash: [hash will be shown in checksums.txt]
``````

## Support

- **Repository**: https://github.com/$Repository
- **Issues**: https://github.com/$Repository/issues
- **Documentation**: See repository README for detailed documentation

## Build Information

- **Version**: $Version
- **Build Date**: $buildDate
- **Commit SHA**: $CommitSha
- **Generated by**: GitHub Actions

## License

This script is provided as-is for security automation and incident response purposes.
"@

$releaseReadme | Out-File -FilePath "${releaseDir}/README.md" -Encoding UTF8
Write-Host "✅ Release documentation created"

# List all artifacts
Write-Host ""
Write-Host "📦 Release artifacts:" -ForegroundColor Yellow
Get-ChildItem $releaseDir | ForEach-Object {
    $size = if ($_.Length -lt 1KB) { "$($_.Length) bytes" } 
            elseif ($_.Length -lt 1MB) { "{0:N1} KB" -f ($_.Length / 1KB) }
            else { "{0:N1} MB" -f ($_.Length / 1MB) }
    Write-Host "  📄 $($_.Name) ($size)" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "✅ Release build completed successfully!" -ForegroundColor Green
