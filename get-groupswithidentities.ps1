#Requires -Version 5
#Requires -Modules ActiveDirectory
<#
    .SYNOPSIS
	Find all groups in specified searchbase(s) that contain user or computer identities.
    .DESCRIPTION
	Find all groups in specified searchbase(s) that contain user or computer identities.
	Outputs the result to a CSV report.
	Searchbase(s) can be supplied as a comma seperated list or in a file.
	If no searchbase(s) are supplied, all AD groups will be reported on.
	Useful for testing IGDLA compliance. Check resource groups to see if they contain users/computers.

    .PARAMETER reportfile
	String. Output report file. Defaults to .\groupswithids.csv.
    .PARAMETER overwritereportfile
	Switch. Overwrite the report file if it already exists.
    .PARAMETER searchbases
	String array. Comma seperated list of searchbases to check.
    .PARAMETER searchbasefile
	String. Filename of file containing list of searchbases to check.

    .INPUTS

    .OUTPUTS

    .NOTES
	Scott Knights
	V 1.20220317.1

    .EXAMPLE
#>

# ============================================================================
#region Parameters
# ============================================================================
Param(
    [Parameter()]
    [String] $reportfile=".\groupswithids.csv",

    [Parameter()]
    [switch]$overwritereportfile,

    [Parameter()]
    [String[]] $searchbases,

    [Parameter()]
    [String] $searchbasefile
)
#endregion Parameters

# ============================================================================
#region Functions
# ============================================================================
# Return a list of all groups in a searchbase that contain user or computer objects
function get-groupwithid {
	Param(
		[Parameter(Position=0)]
		[String] $searchbase
	)

	try {
		$groups=get-adgroup -filter * -searchbase $searchbase
	} catch {
		"Invalid SearchBase $searchbase"
		return
	}
	foreach ($group in $groups) {
		write-output "Processing group $group.name"
		$groupdn=$group.distinguishedname
		$groupscope=$group.groupscope
		$identities=@(Get-ADGroupMember -Identity $group|where-object {$_.objectClass -eq "user" -or $_.objectClass -eq "computer"})
		if ($identities.count -gt 0) {
			foreach ($identity in $identities) {
				$Properties = [ordered]@{'Group DN'=$groupdn;'Group Scope'=$groupscope;'Identity'=$identity.name;'Identity Type'=$identity.objectclass}
				New-Object -TypeName PSObject -Property $Properties|Export-Csv -path $reportfile -NoTypeInformation -append
			}
		}
	}
}
#endregion functions

# ============================================================================
#region Execute
# ============================================================================
# Check if the report file already exists. Delete it if $overwritereportfile is selected.
if (test-path $reportfile) {
	if ($overwritereportfile) {
		remove-item -literalpath $reportfile -force
	} else {
		"The report file $reportfile already exists. Move or rename. Exiting."
		return
	}
}

[String[]]$sbs=@()
if ($searchbasefile) {
	if (test-path $searchbasefile) {
		$sbs=get-content $searchbasefile
	} else {
		write-output "The searchbase file is invalid. Exiting"
		return
	}
} elseif ($searchbases) {
	$sbs=$searchbases
} else {
	$sbs="dc="+$env:userdnsdomain.replace(".",",dc=")
}

foreach ($sb in $sbs) {
	get-groupwithid -searchbase $sb
}
#endregion Execute
