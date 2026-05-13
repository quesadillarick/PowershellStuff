Here's a breakdown of what the script does:

**Drive Detection**
Uses `Get-Disk` (with a WMI fallback) to target only internal fixed drives — USB, 1394, and MMC bus types are excluded automatically.

**Protector Strategy**

| Drive | TPM Available | Protector Applied |
|---|---|---|
| OS (`C:`) | Yes | TPM-only *(or TPM+PIN if `$OSPin` is set)* |
| OS (`C:`) | No | Recovery Password only |
| Data drives | Any | Recovery Password |

**Encryption**
All drives use `XtsAes256` — passed directly to `Enable-BitLocker -EncryptionMethod`.

**AD Backup**
Every Recovery Password protector is backed up via `Backup-BitLockerKeyProtector`. The script also re-runs the backup on drives that are already encrypted, so you can use it to remediate machines that were encrypted without an AD backup.

**Idempotent**
Safe to re-run — already fully encrypted drives are skipped for enablement but still have their keys re-backed-up to AD.

**Logging**
Full transcript written to `C:\Logs\BitLocker\BitLocker_<timestamp>.log`.

---

**A few things to verify before deploying:**

1. **GPO prerequisite** — *Computer Configuration → Administrative Templates → Windows Components → BitLocker Drive Encryption → Store BitLocker recovery information in Active Directory Domain Services* should be **Enabled**, with "Require BitLocker backup to AD DS" checked. Without this, `Backup-BitLockerKeyProtector` may silently succeed locally but not actually commit to AD.

2. **TPM + PIN** — If you want to enforce a PIN on the OS drive, set `$OSPin` to a `SecureString`:
   ```powershell
   $OSPin = Read-Host "Enter BitLocker PIN" -AsSecureString
   ```

3. **Deployment** — You can push this via GPO Startup Script or a software deployment tool. Since it uses `#Requires -RunAsAdministrator`, it'll bail cleanly if not elevated.
