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
