<#	
	.NOTES
	===========================================================================
	 Created on:   	20200806
	 Created by:   	jmeyer
	 Organization: 	Helion Technologies
	 Filename:     	StripAdmin.VERSION.ps1
	===========================================================================
	.DESCRIPTION
		This script is designed to remove all users from the local Administrators group and place them in the Users group. Thus removing admin rights.

Parameters:
-"Version"
-"PExcludedGroups"
-"PExcludedAccounts"

Switches for Version:
-"All"
-"Domain"
-"Local"
Explanation:
This Parameter defaults to All. You may provide Domain to run ONLY Domain accounts and groups, or Local to run ONLY Local accounts and groups.
Example: StripAdmin.VERSION.ps1 -Version All

Switches for PExcludedGroups:

Explanation:
This Parameter defaults to $null. You may provide names for groups that you wish to add to the excluded variable.
Example: StripAdmin.VERSION.ps1 -PExcludedGroups 

Switches for PExcludedAccounts:

Explanation:
This Parameter defaults to $null. You may provide names for accounts that you wish to add to the excluded variable.
Example: StripAdmin.VERSION.ps1 -PExcludedAccounts

TASKS:
Add Domain Users and Groups to the removal process

#>

################
## Parameters ##
################

param (
	[Parameter(Mandatory = $false, Position = 0)]
	[String[]]$Version = "All",
	[Parameter(Mandatory = $false)]
	[String[]]$PExcludedAccounts,
	[String[]]$PExcludedGroups
)

###########
## Setup ##
###########

Write-Host "Setting up..." -ForegroundColor Yellow

$ScriptVersion = "StripAdmin.2.0.1"

## Setting colors and preferences for various messages.
$Warningcolor = (Get-Host).PrivateData
$Warningcolor.WarningBackgroundColor = "Red"
$Warningcolor.WarningForegroundColor = "White"
$DebugPreference = 'Continue'
$Debugcolor = (Get-Host).PrivateData
$Debugcolor.DebugBackgroundColor = "White"
$Debugcolor.DebugForegroundColor = "DarkBlue"

#########################
## Creator information ##
#########################

$INFO = "
Strip Local Admin script written by Josh Meyer.
Please contact the author if you have any questions or concerns.
Contact info: jmeyer@heliontechnologies.com
**For complete ChangeLog, please contact the author.**

Script version: $ScriptVersion
"

####################################
## Self elevates to Administrator ##
####################################

Write-Host "Checking for administrative rights..." -ForegroundColor Yellow
	## Get the ID and security principal of the current user account.
$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent();
$myWindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($myWindowsID);
	## Get the security principal for the administrator role.
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator;

	## Check to see if we are currently running as an administrator.
if ($myWindowsPrincipal.IsInRole($adminRole))
{
		## We are running as an administrator, so change the title and background colour to indicate this.
	Write-Host "We are running as administrator, changing the title to indicate this." -ForegroundColor Green
	$Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + "(Elevated)";
}
else
{
	Write-Host "We are not running as administrator. Relaunching as administrator." -ForegroundColor Yellow
		## We are not running as admin, so relaunch as admin.
	$NewProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell";
		## Specify the current script path and name as a parameter with added scope and support for scripts with spaces in it's path.
	$NewProcess.Arguments = "& '" + $script:MyInvocation.MyCommand.Path + "'"
		## Indicate that the process should be elevated.
	$NewProcess.Verb = "runas";
		## Start the new process
	[System.Diagnostics.Process]::Start($newProcess);
		## Exit from the current, unelevated, process.
	Exit;
}

Write-Host "Continuing with setup..." -ForegroundColor Yellow

#############
## Logging ##
#############

if ($PSVersionTable.PSVersion.Major -ge 3)
{
	Write-Host "We are running Powershell version 3 or greater. Logging enabled." -ForegroundColor Green
	if ((Test-Path C:\Logs\) -eq $false)
	{
		$null = New-Item C:\Logs\ -ItemType Directory
	}
	Start-Transcript -Path "C:\Logs\$ScriptVersion.$(Get-Date -UFormat %Y%m%d).log"
}

#############
## Modules ##
#############

###############
## Variables ##
###############
Write-Host "Setting Variables..." -ForegroundColor Yellow
## 20200821.jmeyer.Added Try-Catch to the Domain Test.
try
{
	$DomainTest = (Test-ComputerSecureChannel)
}
catch [System.InvalidOperationException]
{
	$DomainTest = $null
}
$Domain = $env:USERDOMAIN
$Computer = $env:COMPUTERNAME
$LocalGroup = "Users"
$OSName = (Get-WmiObject Win32_OperatingSystem).Caption
$OlderOS = (($OSName -like '*Windows 7*') -or ($OSName -like '*Windows 8*') -or ($OSName -like "*Server 2012*"))
$NewerOS = (($OSName -like '*Windows 10*') -or ($OSName -like "*Server 2016*") -or ($OSName -like "*Server 2019*"))
$FailureLogTest = Test-Path C:\Logs\StripAdminFAILURE.txt
$FailureLogLocation = "C:\Logs\StripAdminFAILURE.txt"
$ExcludedAccounts = @("Administrator", "helionadmin", "helionkadmin")
if ($PExcludedAccounts -ne $null)
{
	$ExcludedAccounts += @($PExcludedAccounts)	
}
$ExcludedGroups = @("Domain Admins", "wadmin")
if ($PExcludedGroups -ne $null)
{
	$ExcludedGroups += @($PExcludedGroups)
}
## 20200814.jmeyer.Adjusted variables to differentiate between Local and Domain variables.
## 20200817.jmeyer.Added variables for Local Groups. Currently not implimented.
$LAdminGrpUsrListBefore = (Get-LocalGroupMember Administrators | Select-Object SID | Get-LocalUser -ErrorAction SilentlyContinue).Name
$LAdminGrpGrpListBefore = (Get-LocalGroupMember Administrators | Select-Object SID | Get-LocalGroup -ErrorAction SilentlyContinue).Name
$LUsrsGrpUsrListBefore = (Get-LocalGroupMember Users | Select-Object SID | Get-LocalUser -ErrorAction SilentlyContinue).Name
$LUsrsGrpGrpListBefore = (Get-LocalGroupMember Users | Select-Object SID | Get-LocalGroup -ErrorAction SilentlyContinue).Name
$LAdminGrpUsrChangeList = $LAdminGrpUsrListBefore | Where-Object { $_ -notin $ExcludedAccounts }
$LAdminGrpGrpChangeList = $LAdminGrpGrpListBefore | Where-Object { $_ -notin $ExcludedGroups }
## 20200814.jmeyer.Added Domain users and groups to the removal script.
if (($NewerOS -eq $true) -and ($DomainTest -eq $true))
{
	Write-Host "We are running on $OSName."
	Write-Host "Setting variables to adjust script for modern OS usage."
	$TEMPDAdminGrpUsrListBefore = (Get-LocalGroupMember Administrators | Where-Object { ($_.PrincipalSource -like "ActiveDirectory") -and ($_.ObjectClass -like "User") }).name
	$TEMPDAdminGrpGrpListBefore = (Get-LocalGroupMember Administrators | Where-Object { ($_.PrincipalSource -like "ActiveDirectory") -and ($_.ObjectClass -like "Group") }).name
	$TEMPDUsrsGrpUsrListBefore = (Get-LocalGroupMember Users | Where-Object { ($_.PrincipalSource -like "ActiveDirectory") -and ($_.ObjectClass -like "User") }).name
	$TEMPDUsrsGrpGrpListBefore = (Get-LocalGroupMember Users | Where-Object { ($_.PrincipalSource -like "ActiveDirectory") -and ($_.ObjectClass -like "Group") }).name
	Write-Host "Variables set for modern OS's. Continuing..."
}
elseif ($DomainTest -eq $true)
{
	Write-Host "We are running on $OSName."
	Write-Host "Setting variables to adjust script for older OS usage."
	$TEMPDAdminGrpUsrListBefore = (Get-LocalGroupMember Administrators | Where-Object { ($_.Name -like "$Domain\*") -and ($_.ObjectClass -like "User") }).name
	$TEMPDAdminGrpGrpListBefore = (Get-LocalGroupMember Administrators | Where-Object { ($_.Name -like "$Domain\*") -and ($_.ObjectClass -like "Group") }).name
	$TEMPDUsrsGrpUsrListBefore = (Get-LocalGroupMember Users | Where-Object { ($_.Name -like "$Domain\*") -and ($_.ObjectClass -like "User") }).name
	$TEMPDUsrsGrpGrpListBefore = (Get-LocalGroupMember Users | Where-Object { ($_.Name -like "$Domain\*") -and ($_.ObjectClass -like "Group") }).name
	Write-Host "Variables set for older OS's. Continuing..."
}

###############
## Functions ##
###############
Write-Host "Setting Functions..." -ForegroundColor Yellow

function RemoveDomainLocalAdminRights ()
{
	Write-Host "Setting up for domain account/group cleanup..." -ForegroundColor Yellow
	## 20200814.jmeyer.Added function for removing Domain Users and Groups from the Local Administrator group.	
	foreach ($User in $TEMPDAdminGrpUsrListBefore)
	{
		## Removing the "DOMAIN\" from the name of the account and placing them into another array for use later.
		$Temp1 = $User.Split("\")
		$Temp2 = $Temp1[1]
		$Temp3 = $DAdminGrpUsrListBefore += @($Temp2)
	}
	
	foreach ($User in $TEMPDAdminGrpGrpListBefore)
	{
		## Removing the "DOMAIN\" from the name of the group and placing them into another array for use later.
		$Temp1 = $User.Split("\")
		$Temp2 = $Temp1[1]
		$Temp3 = $DAdminGrpGrpListBefore += @($Temp2)
	}
	
	foreach ($User in $TEMPDUsrsGrpUsrListBefore)
	{
		## Removing the "DOMAIN\" from the name of the account and placing them into another array for use later.
		$Temp1 = $User.Split("\")
		$Temp2 = $Temp1[1]
		$Temp3 = $DUsrsGrpUsrListBefore += @($Temp2)
	}
	
	foreach ($User in $TEMPDUsrsGrpGrpListBefore)
	{
		## Removing the "DOMAIN\" from the name of the group and placing them into another array for use later.
		$Temp1 = $User.Split("\")
		$Temp2 = $Temp1[1]
		$Temp3 = $DUsrsGrpGrpListBefore += @($Temp2)
	}
	
	## Arrays for users/groups that will be moved.
	$DAdminGrpUsrChangeList = $DAdminGrpUsrListBefore | Where-Object { ($_ -notin $ExcludedAccounts) -and ($_ -notlike "*admin*") }
	$DAdminGrpGrpChangeList = $DAdminGrpGrpListBefore | Where-Object { ($_ -notin $ExcludedGroups) -and ($_ -notlike "*admin*") }
	
	Write-Host "Setup complete!" -ForegroundColor Green
	
	## 20200820.jmeyer.Only running domain user/group cleanup if it's needed. This is determined by the arrays listed on lines 255 and 256.
	if (($DAdminGrpUsrChangeList -ne $null) -or ($DAdminGrpGrpChangeList -ne $null))
	{
		## Installing RSAT AD Tools ONLY if Domain user changes need to take place.
		InstallRSATADTools

		Write-Host "Reporting on current group memberships."
		Write-Host "The following accounts and groups are currently Excluded from being moved if present:" -ForegroundColor Red
		Write-Host "Accounts:" -ForegroundColor Red
		$ExcludedAccounts
		Write-Host "Groups:" -ForegroundColor Red
		$ExcludedGroups
		Write-Host "The following Domain accounts and groups were found in the Administrators group:" -ForegroundColor Yellow
		Write-Host "Accounts:" -ForegroundColor Yellow
		$DAdminGrpUsrListBefore
		Write-Host "Groups:" -ForegroundColor Yellow
		$DAdminGrpGrpListBefore
		Write-Host "The following Domain accounts and groups were found in the Users group:" -ForegroundColor Yellow
		Write-Host "Accounts:" -ForegroundColor Yellow
		$DUsrsGrpUsrListBefore
		Write-Host "Groups:" -ForegroundColor Yellow
		$DUsrsGrpGrpListBefore
		
		if ($DAdminGrpUsrChangeList -ne $null)
		{
			Write-Warning "The following Domain accounts are going to be added to the Users group and removed from Administrators:"
			$DAdminGrpUsrChangeList
			Write-Warning "Moving users!"
			$DAdminGrpUsrChangesMade = $true
			foreach ($User in $DAdminGrpUsrChangeList)
			{
				if ($User -notin $DUsrsGrpUsrListBefore)
				{
					Write-Host "$User is not in the Users group." -ForegroundColor Yellow
					Write-Host "$User is being added to the Users group..." -ForegroundColor Yellow
					([ADSI]"WinNT://$Computer/$LocalGroup,group").psbase.Invoke("Add", ([ADSI]"WinNT://$Domain/$User").path)
					Write-Host "Removing $User from Administrators group..." -ForegroundColor Yellow
					Remove-LocalGroupMember -Group Administrators -Member $User
				}
				else
				{
					Write-Host "$User is already in the Users group." -ForegroundColor Green
					Write-Host "Removing $User from Administrators Group" -ForegroundColor Yellow
					Remove-LocalGroupMember -Group Administrators -Member $User
				}
			}
		}
		else
		{
			Write-Host "No domain accounts need to be moved." -ForegroundColor Green
			$DAdminGrpUsrChangesMade = $null
		}
		
		if ($DAdminGrpGrpChangeList -ne $null)
		{
			Write-Warning "The following Domain groups are going to be added to the Users group and removed from Administrators:"
			$DAdminGrpGrpChangeList
			Write-Warning "Moving groups!"
			$DAdminGrpGrpChangesMade = $true
			foreach ($Group in $DAdminGrpGrpChangeList)
			{
				if ($Group -notin $DUsrsGrpGrpListBefore)
				{
					Write-Host "$Group is not in the Users group." -ForegroundColor Yellow
					Write-Host "$Group is being added to the Users Group..." -ForegroundColor Yellow
					([ADSI]"WinNT://$Computer/$LocalGroup,group").psbase.Invoke("Add", ([ADSI]"WinNT://$Domain/$Group").path)
					Write-Host "Removing $Group from Administrators Group" -ForegroundColor Yellow
					Remove-LocalGroupMember -Group Administrators -Member $Group
				}
				else
				{
					Write-Host "$Group is already in the Users group." -ForegroundColor Green
					Write-Host "Removing $Group from Administrators Group" -ForegroundColor Yellow
					Remove-LocalGroupMember -Group Administrators -Member $Group
				}
			}
		}
		else
		{
			Write-Host "No domain groups need to be moved." -ForegroundColor Green
			$DAdminGrpGrpChangesMade = $null
		}
		
		if (($DAdminGrpUsrChangesMade -eq $true) -or ($DAdminGrpGrpChangesMade -eq $true))
		{
			## Reporting on changes that were made.
			Write-Host "Changes to domain accounts and/or groups were made." -ForegroundColor Green
			Write-Host "Generating report..." -ForegroundColor Yellow
			$TEMPDAdminGrpUsrListAfter = (Get-LocalGroupMember Administrators | Where-Object { ($_.PrincipalSource -like "ActiveDirectory") -and ($_.ObjectClass -like "User") }).name
			$TEMPDAdminGrpGrpListAfter = (Get-LocalGroupMember Administrators | Where-Object { ($_.PrincipalSource -like "ActiveDirectory") -and ($_.ObjectClass -like "Group") }).name
			$TEMPDUsrsGrpUsrListAfter = (Get-LocalGroupMember Users | Where-Object { ($_.PrincipalSource -like "ActiveDirectory") -and ($_.ObjectClass -like "User") }).name
			$TEMPDUsrsGrpGrpListAfter = (Get-LocalGroupMember Users | Where-Object { ($_.PrincipalSource -like "ActiveDirectory") -and ($_.ObjectClass -like "Group") }).name
			$DAdminGroupList = $DAdminGrpUsrListAfter | Where-Object { ($_ -notin $ExcludedAccounts) -and ($_ -notlike "*admin*") }
			$DAdminGroupList += $DAdminGrpGrpListAfter | Where-Object { ($_ -notin $ExcludedGroups) -and ($_ -notlike "*admin*") }
			
			foreach ($User in $TEMPDAdminGrpUsrListAfter)
			{
				## Removing the "DOMAIN\" from the name of the account and placing them into another array for use later.
				$Temp1 = $User.Split("\")
				$Temp2 = $Temp1[1]
				$Temp3 = $DAdminGrpUsrListAfter += @($Temp2)
			}
			
			foreach ($User in $TEMPDAdminGrpGrpListAfter)
			{
				## Removing the "DOMAIN\" from the name of the group and placing them into another array for use later.
				$Temp1 = $User.Split("\")
				$Temp2 = $Temp1[1]
				$Temp3 = $DAdminGrpGrpListAfter += @($Temp2)
			}
			
			foreach ($User in $TEMPDUsrsGrpUsrListAfter)
			{
				## Removing the "DOMAIN\" from the name of the account and placing them into another array for use later.
				$Temp1 = $User.Split("\")
				$Temp2 = $Temp1[1]
				$Temp3 = $DUsrsGrpUsrListAfter += @($Temp2)
			}
			
			foreach ($User in $TEMPDUsrsGrpGrpListAfter)
			{
				## Removing the "DOMAIN\" from the name of the group and placing them into another array for use later.
				$Temp1 = $User.Split("\")
				$Temp2 = $Temp1[1]
				$Temp3 = $DUsrsGrpGrpListAfter += @($Temp2)
			}
			
			Write-Host "Report generated!" -ForegroundColor Green
			
			if ($DAdminGroupList -ne $null)
			{
				Write-Warning "The following users and/or groups have NOT been moved!"
				$DAdminGroupList
				Write-Host "Creating failure log for Kaseya." -ForegroundColor Yellow
				if ($FailureLogTest -eq $true)
				{
					$FailureLogTime = (Get-Item $FailureLogLocation).LastWriteTime -gt (Get-Date).AddDays(-1)
					if ($FailureLogTime -eq $true)
					{
						Add-Content -Path $FailureLogLocation -Value $DAdminGroupList
					}
					else
					{
						$null = New-Item -Path "$FailureLogLocation" -ItemType "file" -Value $DAdminGroupList -Force
					}
				}
				else
				{
					$null = New-Item -Path "$FailureLogLocation" -ItemType "file" -Value $DAdminGroupList
				}
				
				$FailureLogTest = Test-Path C:\Logs\StripAdminFAILURE.txt
				if ($FailureLogTest -eq $true)
				{
					Write-Host "Report can be found at $FailureLogLocation" -ForegroundColor Green
				}
				else
				{
					Write-Host "Report was not generated. Please check Powershell log located at C:\Logs\$ScriptVersion.$(Get-Date -UFormat %Y%m%d).log"
				}
			}
			else
			{
				Write-Host "All changes have been successfully made" -ForegroundColor Green
				Write-Host "The following users were moved successfully:" -ForegroundColor Green
				$DAdminGrpUsrChangeList
				Write-Host "The following groups were moved successfully:" -ForegroundColor Green
				$DAdminGrpGrpChangeList
				Write-Host "The following accounts and groups are currently Excluded from being moved if present:" -ForegroundColor Red
				Write-Host "Accounts:" -ForegroundColor Red
				$ExcludedAccounts
				Write-Host "Groups:" -ForegroundColor Red
				$ExcludedGroups
				Write-Host "The following Domain accounts and groups were found in the Administrators group:" -ForegroundColor Green
				$DAdminGrpUsrListAfter
				Write-Host "Groups:" -ForegroundColor Green
				$DAdminGrpGrpListAfter
				Write-Host "The following Domain accounts and groups were found in the Users group:" -ForegroundColor Green
				$DUsrsGrpUsrListAfter
				Write-Host "Groups:" -ForegroundColor Green
				$DUsrsGrpGrpListAfter
			}
		}
		## Removing RSAT AD Tools.
		UninstallRSATADTools
	}
	else
	{
		Write-Host "No changes are needed to Domain users and/or groups." -ForegroundColor Green
	}
}

function InstallRSATADTools ()
{
	## 20200814.jmeyer.Added installation of RSAT AD Tools.
	if ((Get-WindowsCapability -Name Rsat.ActiveDirectory.* -Online).State -ne "Installed")
	{
		Write-Host "RSAT: Active Directory Domain Services and Lightweight Directory Services Tools are not installed." -ForegroundColor Yellow
		Write-Host "Installing RSAT: Active Directory Domain Services and Lightweight Directory Services Tools." -ForegroundColor Yellow
		Write-Host "This may take a few minutes..." -ForegroundColor Red
		Get-WindowsCapability -Name Rsat.ActiveDirectory.* -Online | Add-WindowsCapability -Online
		if ((Get-WindowsCapability -Name Rsat.ActiveDirectory.* -Online).State -eq "Installed")
		{
			Write-Host "RSAT: Active Directory Domain Services and Lightweight Directory Services Tools are installed." -ForegroundColor Green
			$RSATAD = "Installed"
		}
		else
		{
			Write-Host "RSAT: Active Directory Domain Services and Lightweight Directory Services Tools did not install." -ForegroundColor Red
			$RSATAD = $null
		}
	}
	else
	{
		Write-Host "RSAT: Active Directory Domain Services and Lightweight Directory Services Tools are already installed." -ForegroundColor Green
		$RSATAD = "Installed"
	}
}

function UninstallRSATADTools ()
{
	## 20200814.jmeyer.Added Removal of RSAT AD Tools for removal after script completes.
	if ((Get-WindowsCapability -Name Rsat.ActiveDirectory.* -Online).State -eq "Installed")
	{
		Write-Host "RSAT: Active Directory Domain Services and Lightweight Directory Services Tools are installed." -ForegroundColor Yellow
		Write-Host "Uninstalling RSAT: Active Directory Domain Services and Lightweight Directory Services Tools." -ForegroundColor Yellow
		Get-WindowsCapability -Name Rsat.ActiveDirectory.* -Online | Remove-WindowsCapability -Online
		if ((Get-WindowsCapability -Name Rsat.ActiveDirectory.* -Online).State -eq "Installed")
		{
			Write-Host "RSAT: Active Directory Domain Services and Lightweight Directory Services Tools are still installed." -ForegroundColor Red
			$RSATAD = "Installed"
		}
		else
		{
			Write-Host "RSAT: Active Directory Domain Services and Lightweight Directory Services Tools have been uninstalled." -ForegroundColor Green
			$RSATAD = $null
		}
	}
	else
	{
		Write-Host "RSAT: Active Directory Domain Services and Lightweight Directory Services Tools are not installed." -ForegroundColor Green
		$RSATAD = $null
	}
}

function RemoveLocalAdminRights ()
{
	## 20200820.jmeyer.Only running local user/group cleanup if it's needed. This is determined by the arrays on lines 189 and 190.
	if (($LAdminGrpUsrChangeList -ne $null) -or ($LAdminGrpGrpChangeList -ne $null))
	{
		Write-Host "Setting up for domain account/group cleanup..." -ForegroundColor Yellow
		Write-Host "The following accounts and groups are currently Excluded from being moved if present:" -ForegroundColor Red
		Write-Host "Accounts:" -ForegroundColor Red
		$ExcludedAccounts
		Write-Host "Groups:" -ForegroundColor Red
		$ExcludedGroups
		Write-Host "The following Local accounts and groups were found in the Administrators group:" -ForegroundColor Yellow
		$LAdminGrpUsrListBefore
		Write-Host "Groups:" -ForegroundColor Yellow
		$LUsrsGrpGrpListBefore
		Write-Host "The following Local accounts and groups were found in the Users group:" -ForegroundColor Yellow
		$LUsrsGrpUsrListBefore
		Write-Host "Groups:" -ForegroundColor Yellow
		$LAdminGrpGrpListBefore
		
		if ($LAdminGrpUsrChangeList -ne $null)
		{
			Write-Warning "The following Local accounts are going to be added to the Users group and removed from Administrators:"
			$LAdminGrpUsrChangeList
			Write-Warning "Moving users!"
			$LAdminGrpUsrChangesMade = $true
			foreach ($User in $LAdminGrpUsrChangeList)
			{
				if ($User -notin $LUsrsGrpUsrListBefore)
				{
					Write-Host "$User is not in the Users group." -ForegroundColor Yellow
					Write-Host "$User is being added to the Users Group..." -ForegroundColor Yellow
					Add-LocalGroupMember -Group Users -Member $User
					Write-Host "Removing $User from Administrators Group" -ForegroundColor Yellow
					Remove-LocalGroupMember -Group Administrators -Member $User
				}
				else
				{
					Write-Host "$User is already in the Users group." -ForegroundColor Green
					Write-Host "Removing $User from Administrators Group" -ForegroundColor Yellow
					Remove-LocalGroupMember -Group Administrators -Member $User
				}
			}
		}
		else
		{
			Write-Host "No local accounts need to be moved." -ForegroundColor Green
			$LAdminGrpUsrChangesMade = $null
		}
		
		if ($LAdminGrpUsrChangeList -ne $null)
		{
			Write-Warning "The following Local groups are going to be added to the Users group and removed from Administrators:"
			$LAdminGrpGrpChangeList
			Write-Warning "Moving users!"
			$LAdminGrpGrpChangesMade = $true
			foreach ($Group in $LAdminGrpGrpChangeList)
			{
				if ($Group -notin $LUsrsGrpGrpListBefore)
				{
					Write-Host "$Group is not in the Users group." -ForegroundColor Yellow
					Write-Host "$Group is being added to the Users Group..." -ForegroundColor Yellow
					Add-LocalGroupMember -Group Users -Member $Group
					Write-Host "Removing $Group from Administrators Group" -ForegroundColor Yellow
					Remove-LocalGroupMember -Group Administrators -Member $Group
				}
				else
				{
					Write-Host "$Group is already in the Users group." -ForegroundColor Green
					Write-Host "Removing $Group from Administrators Group" -ForegroundColor Yellow
					Remove-LocalGroupMember -Group Administrators -Member $Group
				}
			}
		}
		else
		{
			Write-Host "No local groups need to be moved." -ForegroundColor Green
			$LAdminGrpGrpChangesMade = $null
		}
		
		if (($LAdminGrpUsrChangesMade -eq $true) -or ($LAdminGrpGrpChangesMade -eq $true))
		{
			## Reporting on changes that were made.
			Write-Host "Changes to local accounts and/or groups were made." -ForegroundColor Green
			Write-Host "Gathering report..." -ForegroundColor Yellow
			$LAdminGrpUsrListAfter = (Get-LocalGroupMember Administrators | Select-Object SID | Get-LocalUser -ErrorAction SilentlyContinue).Name
			$LAdminGrpGrpListAfter = (Get-LocalGroupMember Administrators | Select-Object SID | Get-LocalGroup -ErrorAction SilentlyContinue).Name
			$LUsrsGrpUsrListAfter = (Get-LocalGroupMember Users | Select-Object SID | Get-LocalUser -ErrorAction SilentlyContinue).Name
			$LUsrsGrpGrpListAfter = (Get-LocalGroupMember Users | Select-Object SID | Get-LocalGroup -ErrorAction SilentlyContinue).Name
			$LAdminGroupList = $LAdminGrpUsrListAfter | Where-Object { ($_ -notin $ExcludedAccounts) }
			$LAdminGroupList += $LAdminGrpGrpListAfter | Where-Object { ($_ -notin $ExcludedGroups) }
			Write-Host "Report generated!" -ForegroundColor Green
			
			if ($LAdminGroupList -ne $null)
			{
				Write-Warning "The following users have NOT been moved!"
				$LAdminGroupList
				Write-Host "Creating failure log for Kaseya." -ForegroundColor Yellow
				if ($FailureLogTest -eq $true)
				{
					$FailureLogTime = (Get-Item $FailureLogLocation).LastWriteTime -gt (Get-Date).AddDays(-1)
					if ($FailureLogTime -eq $true)
					{
						Add-Content -Path $FailureLogLocation -Value $LAdminGroupList
					}
					else
					{
						$null = New-Item -Path "$FailureLogLocation" -ItemType "file" -Value $LAdminGroupList -Force
					}
				}
				else
				{
					$null = New-Item -Path "$FailureLogLocation" -ItemType "file" -Value $LAdminGroupList
				}
				
				$FailureLogTest = Test-Path C:\Logs\StripAdminFAILURE.txt
				if ($FailureLogTest -eq $true)
				{
					Write-Host "Report can be found at $FailureLogLocation" -ForegroundColor Green
				}
				else
				{
					Write-Host "Report was not generated. Please check Powershell log located at C:\Logs\$ScriptVersion.$(Get-Date -UFormat %Y%m%d).log"
				}
			}
			else
			{
				Write-Host "All changes have been successfully made" -ForegroundColor Green
				Write-Host "The following users were moved successfully:" -ForegroundColor Green
				$LAdminGrpUsrChangeList
				Write-Host "The following groups were moved successfully:" -ForegroundColor Green
				$LAdminGrpGrpChangeList
				Write-Host "The following accounts and groups are currently Excluded from being moved if present:" -ForegroundColor Red
				Write-Host "Accounts:" -ForegroundColor Red
				$ExcludedAccounts
				Write-Host "Groups:" -ForegroundColor Red
				$ExcludedGroups
				Write-Host "The following local accounts and groups were found in the Administrators group:" -ForegroundColor Green
				$LAdminGrpUsrListAfter
				Write-Host "Groups:" -ForegroundColor Green
				$LAdminGrpGrpListAfter
				Write-Host "The following local accounts and groups were found in the Users group:" -ForegroundColor Green
				$LUsrsGrpUsrListAfter
				Write-Host "Groups:" -ForegroundColor Green
				$LUsrsGrpGrpListAfter
			}
		}
	}
	else
	{
		Write-Host "No changes are needed to Local users and/or groups." -ForegroundColor Green
	}
}

function ScriptEnding ()
{
	## Post Creator information
	Write-Host "$INFO" -ForegroundColor Cyan
	Write-Host "Cleaning up..."
	$DebugPreference = 'SilentlyContinue'
	## Removing all script files for security reasons.
	Write-Warning "Removing script files for security purposes..."
	## Self destructs script.
	Remove-Item -LiteralPath $PSCommandPath -Force
	Write-Host "File deletion completed" -ForegroundColor Green
	
	## Stops Log.
	if ($PSVersionTable.PSVersion.Major -ge 3)
	{
		Write-Warning "Stopping log..."
		Stop-Transcript
	}
	exit
}

Write-Host "Setup complete!" -ForegroundColor Green

###################
## Prerequisites ##
###################

Write-Host "Checking Prerequisites..." -ForegroundColor Yellow
$ServerClass = (Get-WmiObject Win32_OperatingSystem).ProductType
if ($ServerClass -eq "2")
{
	Write-Warning "This script is not designed to run on a Domain Controller."
	## Removing all script files for security reasons.
	Write-Warning "Removing script files for security purposes..."
	## Self destructs script.
	Remove-Item -LiteralPath $PSCommandPath -Force
	Write-Host "File deletion completed" -ForegroundColor Green
	Write-Warning "Press any key to exit...";
	$x = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown");
	exit
}

## Script OS limitations
Write-Host "Checking OS version..." -ForegroundColor Yellow
if ((Get-WmiObject Win32_OperatingSystem).Caption -like '*server*')
{
	Write-Warning "This script is not designed to run on a Server OS."
	## Removing all script files for security reasons.
	Write-Warning "Removing script files for security purposes..."
	## Self destructs script.
	Remove-Item -LiteralPath $PSCommandPath -Force
	Write-Host "File deletion completed" -ForegroundColor Green
	Write-Warning "Press any key to exit...";
	$x = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown");
	exit
}
else
{
	Write-Host "OS Version verified. Continuing..." -ForegroundColor Green
}


##########################
## Start main code here ##
##########################

## 20200820.jmeyer.Adjusted functions due to if statement conditions.
Write-Host "Checking parameters..." -ForegroundColor Yellow
if ($Version -contains "All")
{
	if ($DomainTest -eq $true)
	{
		Write-Host "Running Local and Domain user and group cleanup..." -ForegroundColor Green
		RemoveLocalAdminRights
		RemoveDomainLocalAdminRights
	}
	else
	{
		Write-Host "We are not connected to a domain" -ForegroundColor Red
		Write-Host "Running local user and group cleanup..." -ForegroundColor Green
		RemoveLocalAdminRights
	}
}

if ($Version -contains "Local")
{
	Write-Host "Running local user and group cleanup..." -ForegroundColor Green
	RemoveLocalAdminRights
}

if ($Version -contains "Domain")
{
	if ($DomainTest -eq $true)
	{
		Write-Host "Running domain user and group cleanup..." -ForegroundColor Green
		RemoveDomainLocalAdminRights
	}
	else
	{
		Write-Host "We are not connected to a domain." -ForegroundColor Red
		Write-Host "Unable to run domain users/groups cleanup." -ForegroundColor Red
	}
}
#######################
#  Ending of script   #
#######################

ScriptEnding

###########################
# Do not write below here #
###########################