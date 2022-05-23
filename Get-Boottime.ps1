#Requires -Version 5
#Requires -Modules ActiveDirectory
<#
    .SYNOPSIS
	Get boot time and uptime for selected machines
    .DESCRIPTION
	Get boot time for uptime for selected machines. Can select servers only, workstations only, filter on specific names or all Windows machines.
	Write results to a CSV file.
    .PARAMETER reportfile
	String. Output report file. Defaults to .\uptimereport.csv.
    .PARAMETER overwritereportfile
	Switch. Overwrite the report file if it already exists.
    .PARAMETER servers
	Switch. Report on servers only
    .PARAMETER pcs
	Switch. report on PCs only
    .PARAMETER filter
	String. Filter to select specific machines
    .PARAMETER searchbase
	String. Root DN to search. Default is root of domain

    .INPUTS

    .OUTPUTS

    .NOTES
	Scott Knights
	V 1.20220517.1

    .EXAMPLE
	Get-Boottime -servers
	Report boot time and up time for all servers.
	Write report to default report location.

    .EXAMPLE
	Get-Boottime -pcs -reportfile "c:\temp\myreport.csv" -overwritereportfile
	Report boot time and up time for all PCs. Write report to c:\temp\myreport.csv.
	Overwrite the report file if it already exists.

    .EXAMPLE
	Get-Boottime -filter "*vdi*"
	Report boot time and up time for all machines with VDI on their name.
	Write report to default report location.
#>

# ============================================================================
#region Parameters
# ============================================================================
[CmdletBinding()]
Param(
    [Parameter()]
    [String] $reportfile=".\uptimereport.csv",

    [Parameter()]
    [switch]$overwritereportfile,

    [Parameter()]
    [switch]$servers,

    [Parameter()]
    [switch]$pcs,

    [Parameter()]
    [string]$filter,

    [Parameter()]
    [string]$searchbase=((Get-ADDomain).distinguishedname)

)
#endregion Parameters

# ============================================================================
#region Variables
# ============================================================================

# Declare and strongly type all variables

[string]$status=$null
[string]$comp=$null
[nullable[datetime]]$boottime=$null
[nullable[datetime]]$now=$null
[nullable[timespan]]$uptime=$null
[string]$upstring=$null
[int]$count=0

[array]$machines=$null
[int]$numcomp=$null

#endregion Variables

# ============================================================================
#region Execute
# ============================================================================
Set-StrictMode -Version 3.0
# Check if the report file already exists. Delete it if $overwritereportfile is selected.
if (test-path -literalpath $reportfile) {
	if ($overwritereportfile) {
		try {
			remove-item -literalpath $reportfile -force -erroraction stop
		} catch {
			write-output "Unable to delete existing report file. Exiting."
			return
		}
	} else {
		write-output "The report file $reportfile already exists. Move or rename. Exiting."
		return
	}
}

# Get selected machines or just get all machines with Windows OS.
if ($filter) {
	$machines=get-adcomputer -filter {name -like $filter} -searchbase $searchbase
} elseif ($servers) {
	$machines=get-adcomputer -filter {operatingsystem -like "*windows*" -and operatingsystem -like "*server*"} -searchbase $searchbase
} elseif ($pcs) {
	$machines=get-adcomputer -filter {operatingsystem -like "*windows*" -and operatingsystem -notlike "*server*"} -searchbase $searchbase
} else {
	$machines=get-adcomputer -filter {operatingsystem -like "*windows*"} -searchbase $searchbase
}
$numcomp=$machines.count

write-output "Processing $numcomp computers."

foreach ($machine in $machines) {
	$count ++
	$boottime=$uptime=$null
	$upstring=$null
	$comp=$machine.dnshostname
	write-output "$count $comp"
	if (Test-Connection -ComputerName $comp -Quiet -count 1) {
		try {
			$boot=(get-ciminstance -computername $comp -ClassName win32_operatingsystem -erroraction stop| select-object lastbootuptime)
			$status="Online"
			$boottime=$boot.lastbootuptime
			$now=get-date
			$uptime=(new-timespan -start $boottime -end $now)
			$upstring=($uptime.tostring("dd' days 'hh' hours 'mm' minutes 'ss' seconds'"))
		} catch {
			$status="WINRM Cannot Connect"
		}
	} else {
		$status="Offline"
	}
	$Properties = [ordered]@{'Computer'=$comp;'Status'=$status;'Boot Time'=$boottime;'Up Time'=$upstring}
	New-Object -TypeName PSObject -Property $Properties|Export-Csv -path $reportfile -NoTypeInformation -append
}

#endregion Execute
