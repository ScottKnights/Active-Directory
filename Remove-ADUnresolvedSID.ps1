#Requires -Version 5
#Requires -Modules ActiveDirectory
<#
    .SYNOPSIS
	Report on and optionally remove unresolved SIDs on AD objects.

    .DESCRIPTION
	This script is based on a script by Ali Tajran: https://www.alitajran.com/remove-orphaned-sids/
	Ali's script works well, but I found that the indentation, short variable names and interesting parameter handling made it difficult to read.
	Added reporting and fixing of unresolved SID as the owner of AD objects.

	*** THIS SCRIPT MAKES CHANGES TO YOUR AD PERMISSIONS. USE AT YOUR OWN RISK ***

    .PARAMETER searchroot
	String. Validated. Specify the AD container to process. Can be set to:
		conf - Configuration Naming Context
		schema - Schema Naming Context
		domain - Current AD Domain (Default if neither searchroot or searchbase are specified).
		domaindns - Domain Dns Zones
		forestdns - Forest Dns Zones

    .PARAMETER searchbase
	String. Distinguished name of OU to process. If neither searchroot or searchbase are specfied, process the current AD Domain.

    .PARAMETER removepermission
	Switch. Remove unresolved SIDs if specified. Only report unresolved SIDs if not specified.

    .PARAMETER containeronly
	Switch. Only process containers if specified. Process all objects if not specified.

    .PARAMETER showpermissions
	Switch. Show permissions for reported object if specified.

    .PARAMETER showallobjects
	Switch. Show all objects if specified. If not specified, only show objects with unresolved SIDs in their ACL.

    .PARAMETER newowner
	String. Group name to set as owner of objects with unresolved SID as owner if fixowner is specified.
		Can be specified as domain\identity. If domain is omitted, the current domain will be prepended.
		Default is Domain Admins.

    .PARAMETER fixowner
	Switch. Set the owner of an object with an unresolved SID as owner to the newowner parameter (Default Domain Admins)

    .PARAMETER logfile
	String. Path to log file. Defaults to .\RemoveOrphanedSID-AD.txt.

    .INPUTS

    .OUTPUTS

    .NOTES
	Scott Knights.
	V 1.20220503.1
		Initial release
	V 1.20220503.2
		Added extra error trapping
	V 1.20200503.3
		Added reporting and fixing of unresolved SID as object owner

    .EXAMPLE
	Remove-ADUnresolvedSID.ps1
		Report all objects in the current domain that have unresolved SIDs in their ACL.

    .EXAMPLE
	Remove-ADUnresolvedSID.ps1 -searchbase "OU=corp,DC=org,DC=com" -containeronly -showpermissions
		Report all containers inside the OU "OU=corp,DC=org,DC=com".
		Show permissions for each container.

    .EXAMPLE
	Remove-ADUnresolvedSID.ps1 -searchbase "OU=corp,DC=com" -newowner "NT AUTHORITY\SYSTEM" -fixowner
		Report all objects inside the OU "OU=corp,DC=com".
		Set NT AUTHORITY\SYSTEM as the owner on any objects with an unresolved SID as owner

    .EXAMPLE
	Remove-ADUnresolvedSID.ps1 -searchroot domaindns -removepermission -showallobjects -logfile "c:\temp\mylogfile.log"
		Report on and remove unresolved SID on all objects in the domain DNS zones.
		Show all objects, including those without unresolved SIDs.
		Write transcript to C:\temp\mylogfile.log.
#>

# ============================================================================
#region Parameters
# ============================================================================
Param(
	[Parameter()]
	[String] $searchbase,

	[Parameter()]
	[switch] $removepermission,

	[Parameter()]
	[switch] $containeronly,

	[Parameter()]
	[switch] $showpermissions,

	[Parameter()]
	[switch] $showallobjects,

	[Parameter()]
	[switch] $fixowner,

	[Parameter()]
	[string] $newowner="Domain Admins",

	[Parameter()]
	[ValidateSet("conf","schema","domain","domaindns","forestdns")]
	[string] $searchroot,

	[Parameter()]
	[String] $logfile = ".\RemoveOrphanedSID-AD.txt"
)

#endregion Parameters

# ============================================================================
#region Functions
# ============================================================================
# Write a message in the specified colour
function write-message {
	param (
		[string]$message,
		[System.ConsoleColor]$colour
	)

	[System.ConsoleColor]$currentcolour=$Host.UI.RawUI.ForegroundColor
	$Host.UI.RawUI.ForegroundColor = $colour
	write-output $message
	$Host.UI.RawUI.ForegroundColor = $currentcolour
}

# Get permissions for the current object and find unresolved SIDs
function Get-Permission {
	param (
		[string]$objectname
	)

	# Get the AD object from the DN. Some DNs (such as conflicted objects or names with trailing spaces) will give an error
	try {
		[Microsoft.ActiveDirectory.Management.ADEntity]$object = get-item AD:$objectname -erroraction stop
	} catch {
		write-message "Error processing $objectname" -colour darkred
		return
	}

	# Get the object ACL and owner
	[System.Security.AccessControl.DirectoryObjectSecurity]$acl = get-ACL AD:$object
	[string]$owner=$acl.owner
	# Unresolved sids have O: as the start of the owner string, so strip it off
	if ($owner -like "O:*") {
		$owner=$owner.substring(2)
	}
	[string]$oldsid = $null

	# Show current object name if the showallobjects switch is true
	if ($showallobjects) {
		Write-output "Object: $objectname"
		# Show the current object permissions if the showpermissions switch is true
		if ($showpermissions) {
			write-output "Owner: $owner"
			write-output "Permissions:"
			write-output $acl.access | sort-object -property IdentityReference -unique | format-table -auto IdentityReference, IsInherited, AccessControlType, ActiveDirectoryRights
		}
	}

	# Test if the object owner is an unresolved SID
	if ($owner -like "$domainsid*") {
		Write-message "Orphaned SID $owner is the owner of $objectname" -colour Yellow
		if ($fixowner) {
			write-message "Setting $newowner as the owner of $objectname" -colour Red
			try {
				$acl.setowner($owneracct)
				Set-ACL -aclobject $acl -path AD:$object
			} catch {
				write-message "Failed to set $newowner as the owner of $objectname" -colour darkred
			}
		}
	}

	[string]$OldSID = $null

	# Enumerate each identity in the ACL
	foreach ($access in $acl.access) {
		[string]$identity = $access.identityReference.value
		# Current identity is an unresolved SID
		if ($identity -like "$domainsid*") {
			# Check if this identity has already been seen to prevent multiple reports on the same unresolved SID
			if ($oldSid -ne $identity) {
				Write-message "Orphaned SID $identity on $objectname" -colour Yellow
				$oldsid = $identity
			}
			# Remove the unresolved SIDs permissions if the removepermission switch is true
			if ($removepermission) {
				$acl.RemoveAccessRule($access)
				Set-ACL -aclobject $acl -path AD:$object
				write-message "Orphaned SID removed on $objectname" -colour Red
			}
		}
	}
}


Function Recurse-Container {
	param (
		[string]$parent
	)

	# Create array of subobjects to process. Only get containers if the containeronly switch is true, otherwise get all objects.
	try {
		If ($containeronly) {
			$ObjectList = get-childitem AD:$parent -force | where-object { ($_.ObjectClass -like "container") -or ($_.ObjectClass -like "OrganizationalUnit") }
		} else {
			$ObjectList = get-childitem AD:$parent -force
		}
	} catch {
		return
	}
	foreach ($object in $ObjectList) {
		[string]$objectDN = $object.Distinguishedname
		Get-Permission $objectDN
		recurse-container $objectDN
	}
}

#endregion Functions

# ============================================================================
#region Execute
# ============================================================================

[Microsoft.ActiveDirectory.Management.ADEntity]$Forest = Get-ADRootDSE
[string]$Domain = (Get-ADDomain).distinguishedname
[string]$ForestName = $Forest.rootDomainNamingContext
[string]$domainsid = (Get-ADDomain).domainsid
[string]$container=$domain

# Check if the newowner account specifies a domain. Prepend with domain if it doesn't
if (-not ($newowner -like "*\*")) {
	$newowner="$env:userdomain\$newowner"
}
# Create the new owner object
$owneracct=New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList $newowner

# Start transcript
Start-Transcript $logfile -Append -Force

if ($searchbase) {
	$container=$searchbase
} elseif ($searchroot) {
	$searchroot=$searchroot.tolower()
	if ($searchroot -eq "conf") {
		$container = $Forest.configurationNamingContext
	} elseif ($searchroot -eq "schema") {
		$container = $Forest.SchemaNamingContext
	} elseif ($searchroot -eq "domaindns") {
		$container = "DC=DomainDnsZones,$ForestName"
	} elseif ($searchroot -eq "forestdns") {
		$container = "DC=ForestDnsZones,$ForestName"
	}
}

Write-message "Analyzing the following object: $container" -colour Cyan

# Start
Get-Permission $container
Recurse-Container $container

Stop-Transcript

#endregion Execute
