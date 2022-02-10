##################
# PowerShell Script to Reset the krbtgt password
# This script is a simplified version of the one available on Microsoft's GitHub:
# https://github.com/microsoft/New-KrbtgtKeys.ps1
#
# Example: .\reset_krbtgt_password.ps1 -krbTgtObjectDN "CN=krbtgt,CN=Users,DC=domain,DC=lan" -targetedADdomainRWDC "dc1.domain.lan"
#
# Romain PLUCIENNIK - 2022-02-10
##################

param(
    [Parameter(Mandatory=$true)][string]$krbTgtObjectDN,
    [Parameter(Mandatory=$true)][string]$targetedADdomainRWDC
)

# Import Module Active Directory
If ((Get-Module | where {$_.Name -eq "ActiveDirectory"}) -eq $null) {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Verbose -Message "Loading Active Directory module"
}

### FUNCTION: Logging Data To The Log File
Function Logging($dataToLog, $lineType) {
	$datetimeLogLine = "[" + $(Get-Date -format "yyyy-MM-dd HH:mm:ss") + "] : "
	Out-File -filepath "$logFilePath" -append -inputObject "$datetimeLogLine$dataToLog"
    If ($null -eq $lineType) {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Yellow
	}
	If ($lineType -eq "SUCCESS") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Green
	}
	If ($lineType -eq "ERROR") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Red
	}
}

### FUNCTION: Confirm Generated Password Meets Complexity Requirements
# Source: https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements
Function confirmPasswordIsComplex($pwd) {
	Process {
		$criteriaMet = 0
		
		# Upper Case Characters (A through Z, with diacritic marks, Greek and Cyrillic characters)
		If ($pwd -cmatch '[A-Z]') {$criteriaMet++}
		
		# Lower Case Characters (a through z, sharp-s, with diacritic marks, Greek and Cyrillic characters)
		If ($pwd -cmatch '[a-z]') {$criteriaMet++}
		
		# Numeric Characters (0 through 9)
		If ($pwd -match '\d') {$criteriaMet++}
		
		# Special Chracters (Non-alphanumeric characters, currency symbols such as the Euro or British Pound are not counted as special characters for this policy setting)
		If ($pwd -match '[\^~!@#$%^&*_+=`|\\(){}\[\]:;"''<>,.?/]') {$criteriaMet++}
		
		# Check If It Matches Default Windows Complexity Requirements
		If ($criteriaMet -lt 3) {Return $false}
		If ($pwd.Length -lt 8) {Return $false}
		Return $true
	}
}

### FUNCTION: Generate New Complex Password
Function generateNewComplexPassword([int]$passwordNrChars) {
	Process {
		$iterations = 0
        Do {
			If ($iterations -ge 20) {
				Logging "  --> Complex password generation failed after '$iterations' iterations..." "ERROR"
				Logging "" "ERROR"
				EXIT
			}
			$iterations++
			$pwdBytes = @()
			$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
			Do {
				[byte[]]$byte = [byte]1
				$rng.GetBytes($byte)
				If ($byte[0] -lt 33 -or $byte[0] -gt 126) {
					CONTINUE
				}
                $pwdBytes += $byte[0]
			}
			While ($pwdBytes.Count -lt $passwordNrChars)
				$pwd = ([char[]]$pwdBytes) -join ''
			} 
        Until (confirmPasswordIsComplex $pwd)
        Return $pwd
	}
}

### Definition Of Some Constants
$execDateTime = Get-Date
$execDateTimeYEAR = $execDateTime.Year
$execDateTimeMONTH = $execDateTime.Month
$execDateTimeDAY = $execDateTime.Day
$execDateTimeHOUR = $execDateTime.Hour
$execDateTimeMINUTE = $execDateTime.Minute
$execDateTimeSECOND = $execDateTime.Second
$execDateTimeCustom = [STRING]$execDateTimeYEAR + "-" + $("{0:D2}" -f $execDateTimeMONTH) + "-" + $("{0:D2}" -f $execDateTimeDAY) + "_" + $("{0:D2}" -f $execDateTimeHOUR) + "." + $("{0:D2}" -f $execDateTimeMINUTE) + "." + $("{0:D2}" -f $execDateTimeSECOND)
$execDateTimeCustom1 = [STRING]$execDateTimeYEAR + $("{0:D2}" -f $execDateTimeMONTH) + $("{0:D2}" -f $execDateTimeDAY) + $("{0:D2}" -f $execDateTimeHOUR) + $("{0:D2}" -f $execDateTimeMINUTE) + $("{0:D2}" -f $execDateTimeSECOND)
$adRunningUserAccount = $ENV:USERDOMAIN + "\" + $ENV:USERNAME
$scriptFullPath = $MyInvocation.MyCommand.Definition
$currentScriptFolderPath = Split-Path $scriptFullPath
$localComputerName = $(Get-WmiObject -Class Win32_ComputerSystem).Name
[string]$logFilePath = Join-Path $currentScriptFolderPath $($execDateTimeCustom + "_" + $localComputerName + "_Reset-KrbTgt-Password.log")

# Retrieve The KrbTgt Object In The AD Domain BEFORE THE PASSWORD SET
$krbTgtObjectBefore = $null
$krbTgtObjectBefore = Get-ADUser -Identity $krbTgtObjectDN -Properties * -Server $targetedADdomainRWDC

# Get The Password Last Set Value From The KrgTgt Object In The AD Domain BEFORE THE PASSWORD SET
$krbTgtObjectBeforePwdLastSet = $null
$krbTgtObjectBeforePwdLastSet = Get-Date $([datetime]::fromfiletime($krbTgtObjectBefore.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"
Logging "  --> New Password Set Date/Time............: '$krbTgtObjectBeforePwdLastSet'"

# Specify The Number Of Characters The Generate Password Should Contain
$passwordNrChars = 64

# Generate A New Password With The Specified Length (Text)
$newKrbTgtPassword = $null
$newKrbTgtPassword = (generateNewComplexPassword $passwordNrChars).ToString()

# Convert The Text Based Version Of The New Password To A Secure String
$newKrbTgtPasswordSecure = $null
$newKrbTgtPasswordSecure = ConvertTo-SecureString $newKrbTgtPassword -AsPlainText -Force

# Try To Set The New Password On The Targeted KrbTgt Account And If Not Successfull Throw Error
Try {
	Set-ADAccountPassword -Identity $krbTgtObjectDN -Server $targetedADdomainRWDC -Reset -NewPassword $newKrbTgtPasswordSecure
} Catch {
	Logging ""
	Logging "  --> Setting the new password for [$krbTgtObjectDN] FAILED on RWDC [$targetedADdomainRWDC]!..." "ERROR"
	Logging "" "ERROR"
}

# Retrieve The KrbTgt Object In The AD Domain AFTER THE PASSWORD SET
$krbTgtObjectAfter = $null
$krbTgtObjectAfter = Get-ADUser -Identity $krbTgtObjectDN -Properties * -Server $targetedADdomainRWDC

# Get The Password Last Set Value From The KrbTgt Object In The AD Domain AFTER THE PASSWORD SET
$krbTgtObjectAfterPwdLastSet = $null
$krbTgtObjectAfterPwdLastSet = Get-Date $([datetime]::fromfiletime($krbTgtObjectAfter.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"
Logging "  --> New Password Set Date/Time............: '$krbTgtObjectAfterPwdLastSet'"
