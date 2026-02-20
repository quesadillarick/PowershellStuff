$logDir      = "C:\Logs\Splunk"
$keepWeeks   = 4   # Keep 4 weeks of local logs
$cutoffDate  = (Get-Date).AddDays(-($keepWeeks * 7))

Get-ChildItem -Path $logDir -Filter "audit_compliance_*.log" |
    Where-Object { $_.LastWriteTime -lt $cutoffDate } |
    ForEach-Object {
        Remove-Item $_.FullName -Force
        Write-Host "Removed old log: $($_.FullName)"
    }

function Write-AuditLog {
    param (
        [string]$CheckName,
        [string]$Category,
        [string]$Status,
        [string]$Details,
        [string]$Hostname = $env:COMPUTERNAME
    )

    # Creates a filename like: audit_compliance_2025-W07.log
    $weekNumber = Get-Date -UFormat "%Y-W%V"
    $logDir     = "C:\Logs\Splunk"
    $logPath    = "$logDir\audit_compliance_$weekNumber.log"

    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }

    $logEntry = [PSCustomObject]@{
        timestamp  = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
        hostname   = $Hostname
        check_name = $CheckName
        category   = $Category
        status     = $Status
        details    = $Details
        log_week   = $weekNumber
    } | ConvertTo-Json -Compress

    Add-Content -Path $logPath -Value $logEntry
}
# --- BitLocker Status ---
# DriveType values:
# 2 = Removable (USB)
# 3 = Local Fixed (internal)
# 4 = Network
# 5 = CD/DVD

$internalDrives = Get-CimInstance Win32_LogicalDisk | 
    Where-Object { $_.DriveType -eq 3 } | 
    Select-Object -ExpandProperty DeviceID  # Returns drive letters like "C:", "D:"

$drives = Get-BitLockerVolume | Where-Object { $_.MountPoint -in $internalDrives }

foreach ($drive in $drives) {
    $status  = if ($drive.ProtectionStatus -eq "On") { "PASS" } else { "FAIL" }
    $details = "Drive: $($drive.MountPoint) | Status: $($drive.ProtectionStatus) | Method: $($drive.EncryptionMethod)"

    Write-AuditLog -CheckName "BitLocker" -Category "Encryption" `
        -Status $status `
        -Details $details
}

# --- Splunk Universal Forwarder Installed ---
$splunkService = Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue
$splunkInstall = Get-ItemProperty "HKLM:\SOFTWARE\SplunkUniversalForwarder" -ErrorAction SilentlyContinue

if ($null -eq $splunkService -and $null -eq $splunkInstall) {
    Write-AuditLog -CheckName "Splunk UF Installed" -Category "Software Compliance" `
        -Status "FAIL" `
        -Details "SplunkForwarder service and registry key not found. Forwarder is likely not installed."
} else {
    $version = if ($splunkInstall.CurrentVersion) { $splunkInstall.CurrentVersion } else { "Unknown" }
    $running = $splunkService.Status -eq "Running"
    $status  = if ($running) { "PASS" } else { "WARNING" }
    $details = "Version: $version | Service Status: $($splunkService.Status) | StartType: $($splunkService.StartType)"

    Write-AuditLog -CheckName "Splunk UF Installed" -Category "Software Compliance" `
        -Status $status `
        -Details $details
}

# --- Free Disk Space on Internal Drives ---
$internalDrives = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }

foreach ($drive in $internalDrives) {
    if ($drive.Size -gt 0) {
        $freePercent = [math]::Round(($drive.FreeSpace / $drive.Size) * 100, 1)
        $usedPercent = 100 - $freePercent
        $freeGB      = [math]::Round($drive.FreeSpace / 1GB, 2)
        $totalGB     = [math]::Round($drive.Size / 1GB, 2)

        $status  = if ($freePercent -ge 20) { "PASS" } else { "FAIL" }
        $details = "Drive: $($drive.DeviceID) | Total: $($totalGB)GB | Free: $($freeGB)GB | Used: $($usedPercent)% | Free: $($freePercent)%"

        Write-AuditLog -CheckName "Free Disk Space - $($drive.DeviceID)" -Category "Storage" `
            -Status $status `
            -Details $details
    }
}

# --- Advanced Audit Policy Configuration (JSIG Minimum Requirements) ---

# JSIG minimum required audit policy settings
# Format: "Category\Subcategory" = "RequiredSetting"
# RequiredSetting: "Success and Failure", "Success", "Failure"
$jsigRequirements = @{
    # Account Logon
    "Account Logon\Credential Validation"                  = "Success and Failure"
    "Account Logon\Kerberos Authentication Service"        = "Success and Failure"
    "Account Logon\Kerberos Service Ticket Operations"     = "Success and Failure"

    # Account Management
    "Account Management\Computer Account Management"       = "Success and Failure"
    "Account Management\Other Account Management Events"   = "Success and Failure"
    "Account Management\Security Group Management"         = "Success and Failure"
    "Account Management\User Account Management"           = "Success and Failure"

    # Detailed Tracking
    "Detailed Tracking\Process Creation"                   = "Success"
    "Detailed Tracking\Process Termination"                = "Success"

    # Logon/Logoff
    "Logon/Logoff\Account Lockout"                         = "Success and Failure"
    "Logon/Logoff\Logoff"                                  = "Success"
    "Logon/Logoff\Logon"                                   = "Success and Failure"
    "Logon/Logoff\Special Logon"                           = "Success"

    # Object Access
    "Object Access\File Share"                             = "Success and Failure"
    "Object Access\Other Object Access Events"             = "Success and Failure"
    "Object Access\Removable Storage"                      = "Success and Failure"

    # Policy Change
    "Policy Change\Audit Policy Change"                    = "Success and Failure"
    "Policy Change\Authentication Policy Change"           = "Success and Failure"
    "Policy Change\Authorization Policy Change"            = "Success and Failure"

    # Privilege Use
    "Privilege Use\Sensitive Privilege Use"                = "Success and Failure"

    # System
    "System\IPsec Driver"                                  = "Success and Failure"
    "System\Security State Change"                         = "Success and Failure"
    "System\Security System Extension"                     = "Success and Failure"
    "System\System Integrity"                              = "Success and Failure"

    # DS Access
    "DS Access\Directory Service Access"                   = "Success and Failure"
    "DS Access\Directory Service Changes"                  = "Success and Failure"
}

# Pull current audit policy settings using auditpol
$auditPolOutput = auditpol /get /category:* /r | ConvertFrom-Csv

# Build a lookup hashtable from current settings
# auditpol /r columns: Machine Name, Policy Target, Subcategory, Subcategory GUID, Inclusion Setting, Exclusion Setting
$currentSettings = @{}
foreach ($entry in $auditPolOutput) {
    if ($entry.Subcategory) {
        $currentSettings[$entry.Subcategory.Trim()] = $entry.'Inclusion Setting'.Trim()
    }
}

$failedChecks   = @()
$passedChecks   = @()
$missingChecks  = @()

foreach ($requirement in $jsigRequirements.GetEnumerator()) {
    $subcategory = $requirement.Key.Split("\")[1].Trim()
    $required    = $requirement.Value

    if ($currentSettings.ContainsKey($subcategory)) {
        $current = $currentSettings[$subcategory]

        # Check if current setting meets or exceeds the requirement
        $meets = $false
        if ($required -eq "Success and Failure" -and $current -eq "Success and Failure") {
            $meets = $true
        } elseif ($required -eq "Success" -and ($current -eq "Success" -or $current -eq "Success and Failure")) {
            $meets = $true
        } elseif ($required -eq "Failure" -and ($current -eq "Failure" -or $current -eq "Success and Failure")) {
            $meets = $true
        }

        if ($meets) {
            $passedChecks += "$subcategory (Required: $required | Current: $current)"
        } else {
            $failedChecks += "$subcategory (Required: $required | Current: $current)"
        }
    } else {
        $missingChecks += $requirement.Key
    }
}

# Log a summary entry
$overallStatus = if ($failedChecks.Count -eq 0 -and $missingChecks.Count -eq 0) { "PASS" } `
                 elseif ($failedChecks.Count -gt 0) { "FAIL" } `
                 else { "WARNING" }

$details = "Passed: $($passedChecks.Count) | Failed: $($failedChecks.Count) | Missing: $($missingChecks.Count)"

Write-AuditLog -CheckName "Audit Policy - JSIG Summary" -Category "Audit Policy" `
    -Status $overallStatus `
    -Details $details

# Log individual failures so they surface in Splunk
foreach ($failure in $failedChecks) {
    Write-AuditLog -CheckName "Audit Policy - Misconfigured" -Category "Audit Policy" `
        -Status "FAIL" `
        -Details $failure
}

# Log missing subcategories as warnings
foreach ($missing in $missingChecks) {
    Write-AuditLog -CheckName "Audit Policy - Not Found" -Category "Audit Policy" `
        -Status "WARNING" `
        -Details "Could not find subcategory in auditpol output: $missing"
}

# --- Event Log Maximum Size (JSIG Minimum Requirements) ---

# JSIG minimum required event log sizes in bytes
# Security: 1GB, System/Application: 128MB, others: 32MB minimum
$jsigLogRequirements = @{
    "Security"                            = 1GB
    "System"                              = 128MB
    "Application"                         = 128MB
    "Windows PowerShell"                  = 128MB
    "Microsoft-Windows-PowerShell/Operational" = 128MB
    "Microsoft-Windows-TaskScheduler/Operational" = 32MB
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" = 32MB
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" = 32MB
    "Microsoft-Windows-WindowsUpdateClient/Operational" = 32MB
}

foreach ($logEntry in $jsigLogRequirements.GetEnumerator()) {
    $logName     = $logEntry.Key
    $requiredSize = $logEntry.Value
    $requiredMB  = [math]::Round($requiredSize / 1MB, 0)

    try {
        $log = Get-WinEvent -ListLog $logName -ErrorAction Stop

        $currentSize = $log.MaximumSizeInBytes
        $currentMB   = [math]::Round($currentSize / 1MB, 2)

        $status  = if ($currentSize -ge $requiredSize) { "PASS" } else { "FAIL" }
        $details = "Log: $logName | Required: $($requiredMB)MB | Current: $($currentMB)MB | Retention: $($log.LogMode)"

        Write-AuditLog -CheckName "Event Log Size - $logName" -Category "Event Log Configuration" `
            -Status $status `
            -Details $details

    } catch {
        # Log not found or inaccessible
        Write-AuditLog -CheckName "Event Log Size - $logName" -Category "Event Log Configuration" `
            -Status "WARNING" `
            -Details "Log: $logName | Could not be accessed or does not exist. Error: $($_.Exception.Message)"
    }
}

# --- Also check Log Mode (should not be set to AutoBackup which can drop events) ---
$criticalLogs = @("Security", "System", "Application")

foreach ($logName in $criticalLogs) {
    try {
        $log    = Get-WinEvent -ListLog $logName -ErrorAction Stop
        $status = if ($log.LogMode -eq "Circular" -or $log.LogMode -eq "Retain") { "PASS" } else { "WARNING" }

        Write-AuditLog -CheckName "Event Log Mode - $logName" -Category "Event Log Configuration" `
            -Status $status `
            -Details "Log: $logName | Mode: $($log.LogMode) | Expected: Circular or Retain"

    } catch {
        Write-AuditLog -CheckName "Event Log Mode - $logName" -Category "Event Log Configuration" `
            -Status "WARNING" `
            -Details "Log: $logName | Could not be accessed. Error: $($_.Exception.Message)"
    }
}

# --- Event Log Retention (JSIG Requirements) ---
# JSIG requires:
#   - Logs retained for a minimum of 1 year online (accessible)
#   - 3 years total retention (archived)
#   - Logs must NOT be set to overwrite events as needed without archiving
#   - Critical logs must be archived before clearing

# Logs that must have retention enforced per JSIG
$jsigRetentionLogs = @{
    "Security"                                                            = "Critical"
    "System"                                                              = "Critical"
    "Application"                                                         = "Critical"
    "Windows PowerShell"                                                  = "Critical"
    "Microsoft-Windows-PowerShell/Operational"                            = "Critical"
    "Microsoft-Windows-TaskScheduler/Operational"                         = "Standard"
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"  = "Standard"
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" = "Standard"
    "Microsoft-Windows-WindowsUpdateClient/Operational"                   = "Standard"
}

# Where archived logs should be stored locally if AutoBackup is configured
# Adjust this path to match your environment
$archivePaths = @(
    "C:\Windows\System32\winevt\Logs\Archive",
    "D:\LogArchive",
    "C:\LogArchive"
)

# Minimum number of days of archived logs expected to be present
# JSIG wants 1 year online - if Splunk is forwarding, note that in details
$minArchiveDays = 365

# --- Check 1: Log Retention Mode per Log ---
foreach ($logEntry in $jsigRetentionLogs.GetEnumerator()) {
    $logName  = $logEntry.Key
    $logTier  = $logEntry.Value

    try {
        $log = Get-WinEvent -ListLog $logName -ErrorAction Stop

        # Evaluate retention mode
        # JSIG acceptable modes:
        #   Retain        = log fills up, stops recording - NOT acceptable without archiving solution
        #   AutoBackup    = archives when full then clears - acceptable if archives are kept
        #   Circular      = overwrites oldest - only acceptable if Splunk/SIEM is forwarding
        $mode = $log.LogMode

        switch ($mode) {
            "AutoBackup" {
                $status  = "PASS"
                $comment = "AutoBackup mode - log will archive before clearing. Verify archive path is monitored."
            }
            "Circular" {
                # Circular is only OK if a forwarder is collecting events
                # Flag as WARNING to prompt verification that Splunk UF is running
                $status  = "WARNING"
                $comment = "Circular mode - events will be overwritten when full. Acceptable ONLY if Splunk UF is forwarding all events."
            }
            "Retain" {
                # Retain stops logging when full - worst option without manual intervention
                $status  = "FAIL"
                $comment = "Retain mode - log will stop recording when full and will NOT auto-archive. Requires manual intervention."
            }
            default {
                $status  = "WARNING"
                $comment = "Unknown log mode: $mode"
            }
        }

        $details = "Log: $logName | Tier: $logTier | Mode: $mode | MaxSize: $([math]::Round($log.MaximumSizeInBytes / 1MB, 0))MB | Comment: $comment"

        Write-AuditLog -CheckName "Log Retention Mode - $logName" -Category "Log Retention" `
            -Status $status `
            -Details $details

    } catch {
        Write-AuditLog -CheckName "Log Retention Mode - $logName" -Category "Log Retention" `
            -Status "WARNING" `
            -Details "Log: $logName | Could not be accessed or does not exist. Error: $($_.Exception.Message)"
    }
}

# --- Check 2: Archive Directory Presence and Age ---
# If AutoBackup is configured, Windows archives logs to a folder
# Verify the archive path exists and contains logs within the required retention window

$archiveFound = $false

foreach ($archivePath in $archivePaths) {
    if (Test-Path $archivePath) {
        $archiveFound   = $true
        $archiveFiles   = Get-ChildItem -Path $archivePath -Filter "*.evtx" -ErrorAction SilentlyContinue
        $oldestArchive  = $archiveFiles | Sort-Object LastWriteTime | Select-Object -First 1
        $newestArchive  = $archiveFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        $totalFiles     = $archiveFiles.Count
        $totalSizeGB    = [math]::Round(($archiveFiles | Measure-Object -Property Length -Sum).Sum / 1GB, 2)

        if ($totalFiles -eq 0) {
            Write-AuditLog -CheckName "Log Archive Directory" -Category "Log Retention" `
                -Status "WARNING" `
                -Details "Archive path exists but contains no .evtx files. Path: $archivePath"
        } else {
            $oldestDays = if ($oldestArchive) { 
                [math]::Round((New-TimeSpan -Start $oldestArchive.LastWriteTime -End (Get-Date)).TotalDays, 0) 
            } else { 0 }

            $status  = if ($oldestDays -ge $minArchiveDays) { "PASS" } else { "WARNING" }
            $details = "Archive Path: $archivePath | Files: $totalFiles | Total Size: $($totalSizeGB)GB | Oldest: $($oldestArchive.Name) ($($oldestDays) days ago) | Newest: $($newestArchive.Name)"

            Write-AuditLog -CheckName "Log Archive Directory" -Category "Log Retention" `
                -Status $status `
                -Details $details
        }

        break  # Stop after finding the first valid archive path
    }
}

if (-not $archiveFound) {
    Write-AuditLog -CheckName "Log Archive Directory" -Category "Log Retention" `
        -Status "WARNING" `
        -Details "No local archive directory found. If using Splunk for retention, verify UF is forwarding all required logs. Checked paths: $($archivePaths -join ', ')"
}

# --- Check 3: Splunk as Retention Mechanism ---
# If relying on Splunk for the 1-year/3-year retention requirement,
# verify the UF is running and inputs.conf is monitoring the right logs
$splunkInputsPath = "C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf"
$splunkAppInputs  = "C:\Program Files\SplunkUniversalForwarder\etc\apps"

if (Test-Path $splunkInputsPath) {
    $inputsContent   = Get-Content $splunkInputsPath -Raw
    $monitoringWinEL = $inputsContent -match "\[WinEventLog"

    $status  = if ($monitoringWinEL) { "PASS" } else { "WARNING" }
    $details = if ($monitoringWinEL) {
        "Splunk UF inputs.conf contains WinEventLog stanzas. Splunk is configured as retention mechanism."
    } else {
        "Splunk UF inputs.conf found but no WinEventLog stanzas detected. Event logs may not be forwarded."
    }

    Write-AuditLog -CheckName "Splunk Log Retention Config" -Category "Log Retention" `
        -Status $status `
        -Details $details

} else {
    Write-AuditLog -CheckName "Splunk Log Retention Config" -Category "Log Retention" `
        -Status "WARNING" `
        -Details "Splunk UF inputs.conf not found at expected path. Cannot verify log forwarding configuration."
}

# --- Check 4: Security Log Last Cleared ---
# Detect if the Security log was recently cleared, which could indicate tampering
# Event ID 1102 = Security log cleared
try {
    $lastCleared = Get-WinEvent -FilterHashtable @{
        LogName = "Security"
        Id      = 1102
    } -MaxEvents 1 -ErrorAction SilentlyContinue

    if ($lastCleared) {
        $daysSinceCleared = [math]::Round((New-TimeSpan -Start $lastCleared.TimeCreated -End (Get-Date)).TotalDays, 1)
        $status  = if ($daysSinceCleared -gt 30) { "WARNING" } else { "FAIL" }
        $details = "Security log was cleared $($daysSinceCleared) days ago on $($lastCleared.TimeCreated) by $($lastCleared.Properties[1].Value)"

        Write-AuditLog -CheckName "Security Log Cleared" -Category "Log Retention" `
            -Status $status `
            -Details $details
    } else {
        Write-AuditLog -CheckName "Security Log Cleared" -Category "Log Retention" `
            -Status "PASS" `
            -Details "No Security log clear events (Event ID 1102) found. Log has not been manually cleared."
    }
} catch {
    Write-AuditLog -CheckName "Security Log Cleared" -Category "Log Retention" `
        -Status "WARNING" `
        -Details "Could not query Security log for clear events. Error: $($_.Exception.Message)"
}

# --- Registry-Based Hardening (JSIG Requirements) ---
# Each entry defines:
#   Path       = Registry path
#   Name       = Value name
#   Expected   = Expected value (or array of acceptable values)
#   Comparison = "Equals", "GreaterThanOrEqual", "LessThanOrEqual", "NotEquals"
#   Category   = Grouping for Splunk
#   CheckName  = Friendly name
#   Severity   = "FAIL" or "WARNING" if check fails (some are advisory)

$jsigRegistryChecks = @(

    # -------------------------
    # SMB Hardening
    # -------------------------
    @{
        CheckName  = "SMBv1 Disabled"
        Category   = "Network Hardening"
        Path       = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        Name       = "SMB1"
        Expected   = 0
        Comparison = "Equals"
        Severity   = "FAIL"
    },
    @{
        CheckName  = "SMB Packet Signing - Server Required"
        Category   = "Network Hardening"
        Path       = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        Name       = "RequireSecuritySignature"
        Expected   = 1
        Comparison = "Equals"
        Severity   = "FAIL"
    },
    @{
        CheckName  = "SMB Packet Signing - Client Required"
        Category   = "Network Hardening"
        Path       = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
        Name       = "RequireSecuritySignature"
        Expected   = 1
        Comparison = "Equals"
        Severity   = "FAIL"
    },

    # -------------------------
    # NTLM / Authentication
    # -------------------------
    @{
        CheckName  = "LAN Manager Authentication Level (NTLMv2 Only)"
        Category   = "Authentication"
        Path       = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Name       = "LmCompatibilityLevel"
        Expected   = 5
        Comparison = "GreaterThanOrEqual"
        Severity   = "FAIL"
    },
    @{
        CheckName  = "LM Hash Storage Disabled"
        Category   = "Authentication"
        Path       = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Name       = "NoLMHash"
        Expected   = 1
        Comparison = "Equals"
        Severity   = "FAIL"
    },
    @{
        CheckName  = "WDigest Authentication Disabled"
        Category   = "Authentication"
        Path       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        Name       = "UseLogonCredential"
        Expected   = 0
        Comparison = "Equals"
        Severity   = "FAIL"
    },
    @{
        CheckName  = "NTLM Minimum Session Security (128-bit)"
        Category   = "Authentication"
        Path       = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
        Name       = "NTLMMinClientSec"
        Expected   = 537395200
        Comparison = "Equals"
        Severity   = "FAIL"
    },
    @{
        CheckName  = "NTLM Minimum Server Session Security (128-bit)"
        Category   = "Authentication"
        Path       = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
        Name       = "NTLMMinServerSec"
        Expected   = 537395200
        Comparison = "Equals"
        Severity   = "FAIL"
    },

    # -------------------------
    # LSA / Credential Protection
    # -------------------------
    @{
        CheckName  = "LSA Protection Enabled (PPL)"
        Category   = "Credential Protection"
        Path       = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Name       = "RunAsPPL"
        Expected   = 1
        Comparison = "Equals"
        Severity   = "FAIL"
    },
    @{
        CheckName  = "Restrict Anonymous SAM Enumeration"
        Category   = "Credential Protection"
        Path       = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Name       = "RestrictAnonymousSAM"
        Expected   = 1
        Comparison = "Equals"
        Severity   = "FAIL"
    },
    @{
        CheckName  = "Restrict Anonymous Access"
        Category   = "Credential Protection"
        Path       = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Name       = "RestrictAnonymous"
        Expected   = 1
        Comparison = "Equals"
        Severity   = "FAIL"
    },
    @{
        CheckName  = "No Anonymous Enumeration of SAM Accounts and Shares"
        Category   = "Credential Protection"
        Path       = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Name       = "EveryoneIncludesAnonymous"
        Expected   = 0
        Comparison = "Equals"
        Severity   = "FAIL"
    },

    # -------------------------
    # UAC
    # -------------------------
    @{
        CheckName  = "UAC Enabled"
        Category   = "UAC"
        Path       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name       = "EnableLUA"
        Expected   = 1
        Comparison = "Equals"
        Severity   = "FAIL"
    },
    @{
        CheckName  = "UAC Admin Approval Mode"
        Category   = "UAC"
        Path       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name       = "ConsentPromptBehaviorAdmin"
        Expected   = 2
        Comparison = "Equals"
        Severity   = "FAIL"
    },
    @{
        CheckName  = "UAC Prompt for Standard Users"
        Category   = "UAC"
        Path       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name       = "ConsentPromptBehaviorUser"
        Expected   = 0
        Comparison = "Equals"
        Severity   = "FAIL"
    },
    @{
        CheckName  = "UAC Virtualization Enabled"
        Category   = "UAC"
        Path       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name       = "EnableVirtualization"
        Expected   = 1
        Comparison = "Equals"
        Severity   = "WARNING"
    },

    # -------------------------
    # PowerShell Logging
    # -------------------------
    @{
        CheckName  = "PowerShell Script Block Logging Enabled"
        Category   = "PowerShell Hardening"
        Path       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        Name       = "EnableScriptBlockLogging"
        Expected   = 1
        Comparison = "Equals"
        Severity   = "FAIL"
    },
    @{
        CheckName  = "PowerShell Module Logging Enabled"
        Category   = "PowerShell Hardening"
        Path       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        Name       = "EnableModuleLogging"
        Expected   = 1
        Comparison = "Equals"
        Severity   = "FAIL"
    },
    @{
        CheckName  = "PowerShell Transcription Enabled"
        Category   = "PowerShell Hardening"
        Path       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
        Name       = "EnableTranscripting"
        Expected   = 1
        Comparison = "Equals"
        Severity   = "WARNING"
    },

    # -------------------------
    # Remote Desktop
    # -------------------------
    @{
        CheckName  = "RDP Network Level Authentication Required"
        Category   = "Remote Access"
        Path       = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
        Name       = "UserAuthentication"
        Expected   = 1
        Comparison = "Equals"
        Severity   = "FAIL"
    },
    @{
        CheckName  = "RDP Encryption Level High"
        Category   = "Remote Access"
        Path       = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
        Name       = "MinEncryptionLevel"
        Expected   = 3
        Comparison = "GreaterThanOrEqual"
        Severity   = "FAIL"
    },
    @{
        CheckName  = "RDP Security Layer"
        Category   = "Remote Access"
        Path       = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
        Name       = "SecurityLayer"
        Expected   = 2
        Comparison = "Equals"
        Severity   = "FAIL"
    },

    # -------------------------
    # AutoRun / AutoPlay
    # -------------------------
    @{
        CheckName  = "AutoRun Disabled for All Drives"
        Category   = "Removable Media"
        Path       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        Name       = "NoDriveTypeAutoRun"
        Expected   = 255
        Comparison = "Equals"
        Severity   = "FAIL"
    },
    @{
        CheckName  = "AutoPlay Disabled"
        Category   = "Removable Media"
        Path       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        Name       = "NoAutorun"
        Expected   = 1
        Comparison = "Equals"
        Severity   = "FAIL"
    },

    # -------------------------
    # Windows Remote Management (WinRM)
    # -------------------------
    @{
        CheckName  = "WinRM Unencrypted Traffic Disabled"
        Category   = "Remote Management"
        Path       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
        Name       = "AllowUnencryptedTraffic"
        Expected   = 0
        Comparison = "Equals"
        Severity   = "FAIL"
    },
    @{
        CheckName  = "WinRM Basic Auth Disabled (Client)"
        Category   = "Remote Management"
        Path       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
        Name       = "AllowBasic"
        Expected   = 0
        Comparison = "Equals"
        Severity   = "FAIL"
    },
    @{
        CheckName  = "WinRM Basic Auth Disabled (Service)"
        Category   = "Remote Management"
        Path       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
        Name       = "AllowBasic"
        Expected   = 0
        Comparison = "Equals"
        Severity   = "FAIL"
    },

    # -------------------------
    # Secure Channel / Domain
    # -------------------------
    @{
        CheckName  = "Secure Channel Signing Required"
        Category   = "Domain Security"
        Path       = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
        Name       = "RequireSignOrSeal"
        Expected   = 1
        Comparison = "Equals"
        Severity   = "FAIL"
    },
    @{
        CheckName  = "Secure Channel Encryption Required"
        Category   = "Domain Security"
        Path       = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
        Name       = "SealSecureChannel"
        Expected   = 1
        Comparison = "Equals"
        Severity   = "FAIL"
    },
    @{
        CheckName  = "Secure Channel Signing Enabled"
        Category   = "Domain Security"
        Path       = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
        Name       = "SignSecureChannel"
        Expected   = 1
        Comparison = "Equals"
        Severity   = "FAIL"
    },

    # -------------------------
    # Windows Defender
    # -------------------------
    @{
        CheckName  = "Windows Defender Real-Time Protection Enabled"
        Category   = "Antivirus"
        Path       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        Name       = "DisableRealtimeMonitoring"
        Expected   = 0
        Comparison = "Equals"
        Severity   = "FAIL"
    },
    @{
        CheckName  = "Windows Defender Tamper Protection"
        Category   = "Antivirus"
        Path       = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
        Name       = "TamperProtection"
        Expected   = 5
        Comparison = "Equals"
        Severity   = "WARNING"
    },

    # -------------------------
    # Miscellaneous
    # -------------------------
    @{
        CheckName  = "Remote Registry Service Disabled"
        Category   = "Attack Surface Reduction"
        Path       = "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry"
        Name       = "Start"
        Expected   = 4
        Comparison = "Equals"
        Severity   = "WARNING"
    },
    @{
        CheckName  = "Windows Script Host Disabled"
        Category   = "Attack Surface Reduction"
        Path       = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
        Name       = "Enabled"
        Expected   = 0
        Comparison = "Equals"
        Severity   = "WARNING"
    },
    @{
        CheckName  = "Safe DLL Search Mode Enabled"
        Category   = "Attack Surface Reduction"
        Path       = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
        Name       = "SafeDllSearchMode"
        Expected   = 1
        Comparison = "Equals"
        Severity   = "FAIL"
    },
    @{
        CheckName  = "Structured Exception Handling Overwrite Protection (SEHOP)"
        Category   = "Attack Surface Reduction"
        Path       = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
        Name       = "DisableExceptionChainValidation"
        Expected   = 0
        Comparison = "Equals"
        Severity   = "FAIL"
    },
    @{
        CheckName  = "Anonymous Shares Restricted"
        Category   = "Network Hardening"
        Path       = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
        Name       = "RestrictNullSessAccess"
        Expected   = 1
        Comparison = "Equals"
        Severity   = "FAIL"
    },
    @{
        CheckName  = "Send Unencrypted Password to Third-Party SMB Disabled"
        Category   = "Network Hardening"
        Path       = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
        Name       = "EnablePlainTextPassword"
        Expected   = 0
        Comparison = "Equals"
        Severity   = "FAIL"
    }
)

# -----------------------------------------------
# Evaluation Engine
# -----------------------------------------------
$passCount    = 0
$failCount    = 0
$warnCount    = 0
$missingCount = 0

foreach ($check in $jsigRegistryChecks) {
    $checkName = $check.CheckName
    $category  = $check.Category
    $regPath   = $check.Path
    $regName   = $check.Name
    $expected  = $check.Expected
    $comparison = $check.Comparison
    $severity  = $check.Severity

    try {
        # Check if path exists
        if (-not (Test-Path $regPath)) {
            $missingCount++
            Write-AuditLog -CheckName "Registry Hardening - $checkName" -Category $category `
                -Status "WARNING" `
                -Details "Registry path not found: $regPath | This key may not exist on this OS version or the policy is not applied."
            continue
        }

        $regValue = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop
        $current  = $regValue.$regName

        # Evaluate based on comparison type
        $pass = switch ($comparison) {
            "Equals"             { $current -eq $expected }
            "NotEquals"          { $current -ne $expected }
            "GreaterThanOrEqual" { $current -ge $expected }
            "LessThanOrEqual"    { $current -le $expected }
            default              { $false }
        }

        if ($pass) {
            $passCount++
            $status  = "PASS"
            $details = "Check: $checkName | Path: $regPath | Name: $regName | Expected: $expected | Current: $current"
        } else {
            if ($severity -eq "FAIL") { $failCount++ } else { $warnCount++ }
            $status  = $severity
            $details = "Check: $checkName | Path: $regPath | Name: $regName | Expected: $expected | Current: $current | Comparison: $comparison"
        }

        Write-AuditLog -CheckName "Registry Hardening - $checkName" -Category $category `
            -Status $status `
            -Details $details

    } catch [System.Management.Automation.PSArgumentException] {
        # Registry path exists but value name not found
        $missingCount++
        Write-AuditLog -CheckName "Registry Hardening - $checkName" -Category $category `
            -Status "WARNING" `
            -Details "Registry value '$regName' not found at path: $regPath | Policy may not be configured."

    } catch {
        $missingCount++
        Write-AuditLog -CheckName "Registry Hardening - $checkName" -Category $category `
            -Status "WARNING" `
            -Details "Error reading registry: $regPath\$regName | Error: $($_.Exception.Message)"
    }
}

# --- Summary Entry ---
$totalChecks   = $jsigRegistryChecks.Count
$overallStatus = if ($failCount -eq 0 -and $missingCount -eq 0) { "PASS" } `
                 elseif ($failCount -gt 0) { "FAIL" } `
                 else { "WARNING" }

Write-AuditLog -CheckName "Registry Hardening - JSIG Summary" -Category "Registry Hardening" `
    -Status $overallStatus `
    -Details "Total Checks: $totalChecks | Passed: $passCount | Failed: $failCount | Warnings: $warnCount | Missing/Unreadable: $missingCount"
