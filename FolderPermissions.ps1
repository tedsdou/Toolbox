#Requires -Module NTFSSecurity

##Create a folder that will contain the script and all associated CSV files. All input/output will be in that folder.
$folderPaths = Import-Csv -Path "$PSScriptRoot\location.csv"
$users = Import-Csv -Path "$PSScriptRoot\users.csv" #User should be in format 'contoso\administrator'
$Action = 'List' #List will parse, change to Remove to remove users
$ExportPath = "$PSScriptRoot\User-$Action.csv"
 

foreach ($folderPath in $folderPaths.FolderPath) {
    $subfolders = Get-ChildItem -Path $folderPath -Directory -Recurse 
    foreach ($subfolder in $subfolders) {        
        foreach ($user in $users.User) {
            $accessRule = Get-NTFSAccess -Path $subfolder.FullName -Account $user
            if ($accessRule) {
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