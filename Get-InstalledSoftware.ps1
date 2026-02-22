# Get-InstalledSoftware.ps1
# Retrieves installed software from registry and displays in GridView

$registryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$softwareList = foreach ($path in $registryPaths) {
    Get-ItemProperty $path -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName } |
    Select-Object @{
        Name = "Name"
        Expression = { $_.DisplayName }
    },
    @{
        Name = "Version"
        Expression = { $_.DisplayVersion }
    },
    @{
        Name = "Publisher"
        Expression = { $_.Publisher }
    },
    @{
        Name = "InstallDate"
        Expression = {
            if ($_.InstallDate -and $_.InstallDate -match '^\d{8}$') {
                [datetime]::ParseExact($_.InstallDate, 'yyyyMMdd', $null)
            } else {
                $_.InstallDate
            }
        }
    },
    @{
        Name = "InstallLocation"
        Expression = { $_.InstallLocation }
    },
    @{
        Name = "UninstallString"
        Expression = { $_.UninstallString }
    },
    @{
        Name = "QuietUninstallString"
        Expression = { $_.QuietUninstallString }
    },
    @{
        Name = "RegistryKey"
        Expression = { $_.PSPath }
    }
}

# Remove duplicates and sort
$softwareList |
    Sort-Object Name -Unique |
    Sort-Object Name |
    Out-GridView -Title "Installed Software Inventory"
