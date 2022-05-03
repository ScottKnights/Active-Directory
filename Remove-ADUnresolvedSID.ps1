#Requires -Version 5
#Requires -Modules ActiveDirectory
<#
    .SYNOPSIS
	Report on and optionally remove unresolved SIDs on AD objects.

    .DESCRIPTION
	This is a rewrite of this script by Ali Tajran: https://www.alitajran.com/remove-orphaned-sids/
	Ali's script works, but the indentation, short variable names and interesting parameter handling make it difficult to read.

    .PARAMETER searchroot
	String. Validated. Specify the AD container to process. Can be set to:
		conf - Configuration Naming Context
		schema - Schema Naming Context
		domain - Current AD Domain (Default if neither searchroot or searchbase are specified).
		domaindns - Domain Dns Zones
		forestdns - Forest Dns Zones

    .PARAMETER searchbase
	String. Distinguished name of OU to process. If neither searchroot or searchbase is specfied, process the current AD Domain.

    .PARAMETER removepermission
	Switch. Removed unresolved SIDs if specified. Only report unresolved SIDs if not specified.

    .PARAMETER containeronly
	Switch. Only process containers if specified. Process all objects if not specified.

    .PARAMETER showpermissions
	Switch. Show permissions for reported object if specified.

    .PARAMETER showallobjects
	Switch. Show all objects if specified. If no specified, only show objects with unresolved SIDs in their ACL.

    .PARAMETER logfile
	String. Path to log file. Defaults to .\RemoveOrphanedSID-AD.txt.

    .INPUTS

    .OUTPUTS

    .NOTES
	Scott Knights.
	V 1.20220503.1
		Initial release

    .EXAMPLE
	Remove-ADUnresolvedSID.ps1
		Report all objects in the current domain that have unresolved SIDs in their ACL.

    .EXAMPLE
	Remove-ADUnresolvedSID.ps1 -searchbase "OU=corp,DC=org,DC=com" -containeronly -showpermissions
		Report all containers inside the OU "OU=corp,DC=org,DC=com". 
		Show permissions for each container.

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

	$currentcolour=$Host.UI.RawUI.ForegroundColor
	$Host.UI.RawUI.ForegroundColor = $colour
	write-output $message
	$Host.UI.RawUI.ForegroundColor = $currentcolour
}

# Get permissions for the current object and find unresolved SIDs
function Get-Permission {
	param (
		[string]$objectname
	)

	[Microsoft.ActiveDirectory.Management.ADEntity]$object = get-item AD:$objectname
 	[string]$objectDN = $object.distinguishedname
	[System.Security.AccessControl.DirectoryObjectSecurity]$acl = get-ACL AD:$object
	[string]$oldsid = $null

	# Show current object name if the showallobjects switch is true
	if ($showallobjects) {
		Write-output $objectDN
	}

	# Show the current object permissions if the showpermissions switch is true
	if ($showpermissions) {
		write-output $acl.access | sort-object -property IdentityReference -unique | format-table -auto IdentityReference, IsInherited, AccessControlType, ActiveDirectoryRights
	}

	[string]$OldSID = $null

	# Enumerate each identity in the ACL
	foreach ($access in $acl.access) {
		[string]$identity = $access.identityReference.value
		# Current identity is an unresolved SID
		if ($identity -like "$domainsid*") {
			# Check if this identity has already been seen to prevent multiple reports on the same unresolved SID
			if ($oldSid -ne $identity) {
				Write-message "Orphaned SID $identity on $objectDN" -colour Yellow
				$oldsid = $identity
			}
			# Remove the unresolved SIDs permissions if the removepermission switch is true
			if ($removepermission) {
				$acl.RemoveAccessRule($access)
				Set-ACL -aclobject $acl -path AD:$object
				write-message "Orphaned SID removed on $objectDN" -colour Red
			}
		}
	}
}


Function Recurse-Container {
	param (
		[string]$parent
	)

	# Create array of subobjects to process. Only get containers if the containeronly switch is true, otherwise get all objects.
	If ($containeronly) {
		$ObjectList = get-childitem AD:$parent -force | where-object { ($_.ObjectClass -like "container") -or ($_.ObjectClass -like "OrganizationalUnit") }
	} else {
		$ObjectList = get-childitem AD:$parent -force
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