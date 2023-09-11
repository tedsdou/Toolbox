#Requires -Module NTFSSecurity

##Create a folder that will contain the script and all associated CSV files. All input/output will be in that folder.
$folderPaths = Import-Csv -Path "$PSScriptRoot\location.csv"
$users = Import-Csv -Path "$PSScriptRoot\users.csv" #User should be in format 'contoso\administrator'
$Action = 'List' #List will parse, change to Remove to remove users
$ExportPath = "$PSScriptRoot\User-$Action.csv"
 

foreach ($folderPath in $folderPaths.FolderPath) {
    Write-Verbose -Message "Currently working on $folderPath" -Verbose
    $subfolders = Get-ChildItem -Path $folderPath -Directory -Recurse 
    foreach ($subfolder in $subfolders) { 
        Write-Verbose -Message "Currently working on $subfolder" -Verbose       
        foreach ($user in $users.User) {
            Write-Verbose -Message "Currently working on $user" -Verbose
            $accessRule = Get-NTFSAccess -Path $subfolder.FullName -Account $user
            if ($accessRule) {
                Write-Verbose -Message "Found direct membership for $user on $subfolder" -Verbose
                switch ($Action) {
                    'List' {                     
                        [PSCustomObject]@{
                            'FolderPath'    = $folderPath
                            'SubfolderPath' = $subfolder.FullName
                            'FoundUser'     = $user
                            'AccessRights'  = $accessRule.AccessRights
                        } | Export-Csv -Path $ExportPath -NoTypeInformation -Append
                    }
                    'Remove' {
                        $accessrule | Remove-NTFSAccess
                        Write-Warning -Message "Removed permissions for users: $user from $($subfolder.FullName)"
                        [PSCustomObject]@{
                            'FolderPath'          = $folderPath
                            'SubfolderPath'       = $subfolder.FullName
                            'FoundUser'           = $user
                            'AccessRights'        = $accessRule.AccessRights
                            'AccessRightsRemoved' = 'TRUE'
                        } | Export-Csv -Path $ExportPath -NoTypeInformation -Append
                    }
                }
            }
        }
    }
}