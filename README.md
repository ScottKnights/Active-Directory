AD related stuff

Get-GroupsWithIdentities.ps1
Find all groups in supplied searchbase(s) that contain user or computer objects.  
Useful for checking IGDLA compliance. Check resource groups to ensure they don't contain users/computers.  
  
Remove-ADUnresolvedSID.ps1  
Find (and optionally remove) unresolved SIDs on AD objects.  
Rewrite of an Ali Tajran script from here: https://www.alitajran.com/remove-orphaned-sids/  
  
Get-Boottime.ps1  
Get the boot time and uptime for selected domain joined Windows machines.  
All, PCs only, servers only or filter on name.  

Get-LocalAdmins.ps1  
Get members of the local administrators group for selected domain joined Windows machines.  
All, PCs only, servers only or filter on name.  
