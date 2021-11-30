$FilePath               = "$env:userprofile\Desktop\"
$PathCSVUsersAdminCount = $FilePath + "UsersAdminCount.csv"

$UsersAdminCount = Get-ADUser -Filter {admincount -eq 1} -Properties adminCount -ResultSetSize $null | Select-Object Name, DistinguishedName
$UsersAdminCount | Export-Csv -Path $PathCSVUsersAdminCount -Delimiter ";" -Encoding UTF8
