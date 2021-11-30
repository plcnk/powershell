$FilePath                = "$env:userprofile\Desktop\"
$PathCSVGroupsAdminCount = $FilePath + "GroupsAdminCount.csv"

$GroupsAdminCount = Get-ADGroup -Filter {admincount -eq 1} -Properties adminCount -ResultSetSize $null | Select-Object Name, DistinguishedName
$GroupsAdminCount | Export-Csv -Path $PathCSVGroupsAdminCount -Delimiter ";" -Encoding UTF8
