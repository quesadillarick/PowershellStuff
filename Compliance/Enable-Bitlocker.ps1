#Requires -RunAsAdministrator
#Requires -Modules BitLocker

<#
.SYNOPSIS
    Enables BitLocker with XTS-AES-256 encryption on all internal fixed drives
    and backs up recovery key protectors to Active Directory.

.DESCRIPTION
    This script:
      - Targets all internal fixed drives (excludes removable/network drives)
      - Skips the OS drive if already encrypted (logs status)
      - Enables XTS-AES-256 encryption with a TPM + PIN protector on the OS drive
      - Enables XTS-AES-256 encryption with a Recovery Password protector on data drives
      - Backs up all Recovery Password protectors to Active Directory
      - Writes a detailed transcript log to C:\Logs\BitLocker

.NOTES
    Requirements:
      - Must run as Administrator
      - TPM must be present and enabled (for OS drive TPM+PIN protector)
      - Domain-joined machine with write access to the AD computer object
      - 'BitLocker Drive Encryption' Windows Feature must be installed
      - Group Policy: "Store BitLocker recovery information in Active Directory Domain
        Services" should be enabled for AD backup to succeed

    Tested on: Windows 10/11, Windows Server 2016/2019/2022
#>

# ─────────────────────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────────────────────
$LogDir      = "C:\Logs\BitLocker"
$LogFile     = Join-Path $LogDir "BitLocker_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$EncryptionMethod = "XtsAes256"   # XTS-AES-256
$OSPin       = $null              # Set to $null to skip PIN (TPM-only) or supply a SecureString

# ─────────────────────────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────────────────────────
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
Start-Transcript -Path $LogFile -Append

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","SUCCESS")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] [$Level] $Message"
    switch ($Level) {
        "WARN"    { Write-Host $entry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $entry -ForegroundColor Red }
        "SUCCESS" { Write-Host $entry -ForegroundColor Green }
        default   { Write-Host $entry }
    }
}

# ─────────────────────────────────────────────────────────────
#  PREREQUISITE CHECKS
# ─────────────────────────────────────────────────────────────
Write-Log "====== BitLocker Deployment Script Started ======"
Write-Log "Host       : $env:COMPUTERNAME"
Write-Log "User       : $env:USERDOMAIN\$env:USERNAME"
Write-Log "Method     : $EncryptionMethod"

# Check domain join
$domainInfo = (Get-WmiObject Win32_ComputerSystem).PartOfDomain
if (-not $domainInfo) {
    Write-Log "Machine is not domain-joined. AD key backup will not be possible." -Level WARN
}

# Check TPM
$tpm = Get-Tpm -ErrorAction SilentlyContinue
if ($null -eq $tpm) {
    Write-Log "TPM module not found or not accessible." -Level WARN
} elseif (-not $tpm.TpmPresent) {
    Write-Log "TPM is not present on this system. TPM-based protectors will be skipped." -Level WARN
} elseif (-not $tpm.TpmReady) {
    Write-Log "TPM is present but not ready (may need to be enabled in firmware)." -Level WARN
} else {
    Write-Log "TPM is present and ready. (Spec: $($tpm.ManufacturerVersion))" -Level SUCCESS
}

# ─────────────────────────────────────────────────────────────
#  HELPER: BACKUP KEY PROTECTOR TO AD
# ─────────────────────────────────────────────────────────────
function Backup-KeyProtectorToAD {
    param(
        [string]$MountPoint,
        [string]$KeyProtectorId
    )
    try {
        Backup-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $KeyProtectorId -ErrorAction Stop
        Write-Log "  [AD Backup] Recovery key backed up to AD for drive $MountPoint." -Level SUCCESS
    } catch {
        Write-Log "  [AD Backup] FAILED for drive $MountPoint : $_" -Level ERROR
        Write-Log "  [AD Backup] Verify that the GPO 'Store BitLocker recovery information in AD DS' is enabled." -Level WARN
    }
}

# ─────────────────────────────────────────────────────────────
#  HELPER: ENSURE RECOVERY PASSWORD PROTECTOR EXISTS AND BACK UP
# ─────────────────────────────────────────────────────────────
function Ensure-RecoveryPasswordAndBackup {
    param([string]$MountPoint)

    $blv = Get-BitLockerVolume -MountPoint $MountPoint

    # Find existing Recovery Password protectors
    $recoveryProtectors = $blv.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }

    if (-not $recoveryProtectors) {
        Write-Log "  Adding Recovery Password protector to $MountPoint..."
        Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector -ErrorAction Stop | Out-Null
        # Re-fetch after adding
        $blv = Get-BitLockerVolume -MountPoint $MountPoint
        $recoveryProtectors = $blv.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
    }

    foreach ($protector in $recoveryProtectors) {
        Write-Log "  Recovery Key ID : $($protector.KeyProtectorId)"
        Write-Log "  Recovery Password: $($protector.RecoveryPassword)"
        Backup-KeyProtectorToAD -MountPoint $MountPoint -KeyProtectorId $protector.KeyProtectorId
    }
}

# ─────────────────────────────────────────────────────────────
#  GET TARGET DRIVES
#  Fixed internal drives only (DriveType 3 = Fixed)
#  Excludes: removable (2), network (4), CD-ROM (5)
# ─────────────────────────────────────────────────────────────
$osDrive = $env:SystemDrive  # Typically C:
Write-Log "OS Drive   : $osDrive"

$fixedDrives = Get-Disk |
    Where-Object { $_.BusType -notin @('USB','1394','MMC') -and $_.BootFromDisk -ne $false } |
    Get-Partition |
    Where-Object { $_.DriveLetter -and $_.Type -ne 'Recovery' } |
    ForEach-Object { "$($_.DriveLetter):" } |
    Sort-Object -Unique

# Fallback to WMI if Get-Disk returns nothing useful
if (-not $fixedDrives) {
    Write-Log "Falling back to WMI drive detection..." -Level WARN
    $fixedDrives = Get-WmiObject Win32_LogicalDisk |
        Where-Object { $_.DriveType -eq 3 -and $_.DeviceID -notmatch '^[A-B]:$' } |
        Select-Object -ExpandProperty DeviceID
}

Write-Log "Target drives found: $($fixedDrives -join ', ')"

# ─────────────────────────────────────────────────────────────
#  PROCESS EACH DRIVE
# ─────────────────────────────────────────────────────────────
foreach ($drive in $fixedDrives) {

    Write-Log ""
    Write-Log "─── Processing Drive: $drive ───────────────────────────"

    # Get current BitLocker status
    try {
        $blv = Get-BitLockerVolume -MountPoint $drive -ErrorAction Stop
    } catch {
        Write-Log "Could not query BitLocker status for $drive : $_" -Level ERROR
        continue
    }

    Write-Log "  Volume Status     : $($blv.VolumeStatus)"
    Write-Log "  Protection Status : $($blv.ProtectionStatus)"
    Write-Log "  Encryption %      : $($blv.EncryptionPercentage)%"

    # ── Already fully encrypted ──────────────────────────────
    if ($blv.VolumeStatus -eq 'FullyEncrypted' -and $blv.ProtectionStatus -eq 'On') {
        Write-Log "  Drive is already fully encrypted and protection is ON." -Level SUCCESS
        # Still ensure AD backup is current
        Ensure-RecoveryPasswordAndBackup -MountPoint $drive
        continue
    }

    # ── Encryption in progress ───────────────────────────────
    if ($blv.VolumeStatus -eq 'EncryptionInProgress') {
        Write-Log "  Encryption is already in progress on $drive. Skipping enable step." -Level WARN
        Ensure-RecoveryPasswordAndBackup -MountPoint $drive
        continue
    }

    # ── Enable BitLocker ─────────────────────────────────────
    try {

        if ($drive -eq $osDrive) {
            # ── OS Drive: TPM + PIN (or TPM-only if PIN not set) ──
            Write-Log "  [OS Drive] Configuring with TPM protector..."

            if ($tpm -and $tpm.TpmReady) {
                if ($null -ne $OSPin) {
                    # TPM + PIN
                    Write-Log "  [OS Drive] Using TPM + PIN protector."
                    Enable-BitLocker -MountPoint $drive `
                        -EncryptionMethod $EncryptionMethod `
                        -TpmAndPinProtector `
                        -Pin $OSPin `
                        -SkipHardwareTest `
                        -ErrorAction Stop | Out-Null
                } else {
                    # TPM only
                    Write-Log "  [OS Drive] Using TPM-only protector (no PIN configured)."
                    Enable-BitLocker -MountPoint $drive `
                        -EncryptionMethod $EncryptionMethod `
                        -TpmProtector `
                        -SkipHardwareTest `
                        -ErrorAction Stop | Out-Null
                }
            } else {
                # No TPM: fall back to Recovery Password only
                Write-Log "  [OS Drive] No TPM available. Using Recovery Password protector only." -Level WARN
                Enable-BitLocker -MountPoint $drive `
                    -EncryptionMethod $EncryptionMethod `
                    -RecoveryPasswordProtector `
                    -SkipHardwareTest `
                    -ErrorAction Stop | Out-Null
            }

        } else {
            # ── Data Drive: Recovery Password protector ──────────
            Write-Log "  [Data Drive] Enabling with Recovery Password protector..."
            Enable-BitLocker -MountPoint $drive `
                -EncryptionMethod $EncryptionMethod `
                -RecoveryPasswordProtector `
                -ErrorAction Stop | Out-Null
        }

        Write-Log "  BitLocker enabled successfully on $drive." -Level SUCCESS

    } catch {
        Write-Log "  Failed to enable BitLocker on $drive : $_" -Level ERROR
        continue
    }

    # ── Ensure recovery password exists and back up to AD ────
    Ensure-RecoveryPasswordAndBackup -MountPoint $drive

    # ── Resume protection if suspended ───────────────────────
    $blv = Get-BitLockerVolume -MountPoint $drive
    if ($blv.ProtectionStatus -eq 'Off') {
        Write-Log "  Resuming BitLocker protection on $drive..."
        Resume-BitLocker -MountPoint $drive -ErrorAction SilentlyContinue
    }
}

# ─────────────────────────────────────────────────────────────
#  SUMMARY REPORT
# ─────────────────────────────────────────────────────────────
Write-Log ""
Write-Log "====== BitLocker Status Summary ======"
foreach ($drive in $fixedDrives) {
    try {
        $blv = Get-BitLockerVolume -MountPoint $drive -ErrorAction Stop
        $status = "{0,-6} | Status: {1,-22} | Protection: {2,-5} | Encrypted: {3,3}% | Method: {4}" -f `
            $drive,
            $blv.VolumeStatus,
            $blv.ProtectionStatus,
            $blv.EncryptionPercentage,
            $blv.EncryptionMethod
        Write-Log $status
    } catch {
        Write-Log "$drive | Unable to retrieve status." -Level WARN
    }
}

Write-Log ""
Write-Log "Log saved to: $LogFile"
Write-Log "====== Script Complete ======"
Stop-Transcript
