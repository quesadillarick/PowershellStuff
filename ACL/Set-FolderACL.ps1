$path = "C:\Somepath"
$identity = New-Object System.Security.Principal.NTAccount('NT AUTHORITY\SYSTEM')

$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
$acl.SetOwner($identity)
$acl.SetGroup($identity)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule('NT AUTHORITY\SYSTEM', ’FullControl’, ’ContainerInherit, ObjectInherit’, ’None’,’Allow’)
$acl.AddAccessRule($rule)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule('TestUser', ’FullControl’, ’ContainerInherit, ObjectInherit’, ’None’,’Allow’)
$acl.AddAccessRule($rule)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule('BUILTIN\Administrators', ’FullControl’, ’ContainerInherit, ObjectInherit’, ’None’, ’Allow’)
$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $path -AclObject $acl
(Get-Acl -LiteralPath $path).Access # | Format-List
