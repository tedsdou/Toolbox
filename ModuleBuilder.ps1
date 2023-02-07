#Requires -Module Pester, Plaster
$Repository = 'C:\GitHubRepos' ##Adjust accordingly
$ModuleName = Read-Host -Prompt 'Enter the module name'
if (-not(Test-Path -Path "$Repository\$ModuleName")) {
    $Version = '0.0.1'
}
else {
    [Version]$Latest = Get-ChildItem -Path "$Repository\$ModuleName" -Directory | Sort-Object -Property Name -Descending | Select-Object -First 1 -ExpandProperty Name
    switch ($Latest) {
        {($Latest.Minor -eq 9) -and ($Latest.Build -eq 9)} { [string]$Version = [Version]::new($Latest.Major+1,0,0) ;Break }
        ($Latest.Build -eq 9) { [string]$Version = [Version]::new($Latest.Major,$Latest.Minor+1,0) ; Break }
        Default {[string]$Version = [Version]::new($Latest.Major,$Latest.Minor,$Latest.Build+1)}
    }
}

$param = @{
    'TemplatePath' = (Get-PlasterTemplate | Where-Object {$_.Author -eq "$Env:USERDOMAIN\$ENV:USERNAME"}).TemplatePath
    'DestinationPath' = "$Repository\$ModuleName\$Version"
    'ModuleName' = $ModuleName
    'Version' = $Version
    'Editor' = $Host.Name
}

Invoke-Plaster -NoLogo @param

<# #Once psm1 and functions are added
Import-Module -Name "$Repository\$ModuleName"
New-MarkdownHelp -AlphabeticParamsOrder -Module $ModuleName -OutputFolder "$Repository\$ModuleName\$Version\docs" -Force 
#Update as desired
Update-MarkdownHelp -Path "$Repository\$ModuleName\$Version\docs"
New-ExternalHelp -Path "$Repository\$ModuleName\$Version\docs" -OutputPath "$Repository\$ModuleName\$Version\en-us"
#>