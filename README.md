# PowerShell Scripts

A collection of some PowerShell scripts I made.

## What the scripts do

* [list_admincount_users.ps1](https://github.com/plcnk/powershell/blob/master/list_admincount_users.ps1) & [list_admincount_groups.ps1](https://github.com/plcnk/powershell/blob/master/list_admincount_groups.ps1): Theses scripts list users and groups that have their AdminCount attribute set to 1, meaning any user or group that is or has been part of a privileged group.
* [list_privileged_users_and_groups.ps1](https://github.com/plcnk/powershell/blob/master/list_privileged_users_and_groups.ps1): This script lists privileged users and groups, meaning any user or group being member of one of these groups:
  * Enterprise Admins
  * Domain Admins
  * Schema Admins
  * Administrators
  * Account Operators
  * Backup Operators
  * Server Operators
* [reset_krbtgt_password.ps1](https://github.com/plcnk/powershell/blob/master/reset_krbtgt_password.ps1): This script allows you to reset the krbtgt account password. It is derived from the interactive script available on [Microsoft's GitHub](https://github.com/microsoft/New-KrbtgtKeys.ps1). This script has 2 mandatory parameters:
  * krbTgtObjectDN: The krbtgt account DN (e.g. "CN=krbtgt,CN=Users,DC=domain,DC=lan" )
  * targetedADdomainRWDC: The targeted Domain Controller (e.g. "dc1.domain.lan")
