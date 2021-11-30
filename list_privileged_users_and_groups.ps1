$Groups                 = 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Backup Operators', 'Server Operators', 'Account Operators'
$Members                =@()
$FilePath               = "$env:userprofile\Desktop\"
$PathCSVPrivilegedUsers = $FilePath + "PrivilegedUsers.csv"

foreach ($Group in $Groups) {
    $Members = Get-ADGroupMember -Identity $Group | Select-Object name, DistinguishedName, ObjectClass, @{Label='Group Name' ;Expression={$Group}}
    $Members | Export-Csv -Path $PathCSVPrivilegedUsers -Delimiter ";" -Encoding UTF8 -Append
}
