#region Core cmdlets
Get-Command 
Get-Command -Name *dnsclient* 

Get-Help -Name Register-DnsClient

Get-Process -Name Lsass | Get-Member
#endregion

#Region Basic Function
[System.Net.Dns]::GetHostByAddress('192.168.1.10')

Get-Verb
#Use your snippets.  Ctrl+J in ISE / Ctrl+SpaceBar -or- start typing in VSCode

function Resolve-Reverse {
    param (
        $IP
    )
    [System.Net.Dns]::GetHostByAddress($IP)
}

Resolve-Reverse -IP '192.168.1.20'
#EndRegion

#Region Parameters
Function Get-MyProcess{
    Param(
        [string]$Name = 'lsass',
        $Computer
    )
    Get-Process -Name $Name -ComputerName $Computer
}

Get-MyProcess lsass MS
Get-MyProcess MS lsass
Get-MyProcess -Name lsass -Computer MS
Get-MyProcess -Computer MS -Name lsass 
Get-MyProcess MS
Get-MyProcess -Computer MS

#adding Help
Function Get-MyProcess{
    <#
    .SYNOPSIS
        Short description
    .DESCRIPTION
        Long description
    .EXAMPLE
        PS C:\> <example usage>
        Explanation of what the example does
    .NOTES
        General notes
    #>
    Param(
        [string]$Name = 'lsass',
        $Computer
    )
    Get-Process -Name $Name -ComputerName $Computer
}

#Adding a switch
Function Get-MyProcess{
    Param(
        [string]$Name = 'lsass',
        [switch]$FindOwner
    )
    If($FindOwner){
        Get-Process -IncludeUserName -InputObject (Get-Process -Name $Name)
    }
    Else{
        Get-Process -Name $Name
    }
}
Get-MyProcess -Name lsass
Get-MyProcess -Name lsass -FindOwner
#EndRegion

#Region CmdletBinding
#Region Common Parameters
Get-Help about_CommonParameters -ShowWindow
Function Get-MyProcess{
    [CmdletBinding()]
    Param(
        [string]$Name = 'lsass',
        [switch]$FindOwner
    )
    If($FindOwner){
        Write-Verbose -Message "Finding all information about $Name"
        Get-Process -IncludeUserName -InputObject (Get-Process -Name $Name)
    }
    Else{
        Get-Process -Name $Name
    }
}

Get-MyProcess -Name lsass -FindOwner -Verbose
#endregion

#region Risk Mitigation
#Adding in WhatIf and Confirm - Use your Snippets
Function Set-ADPass
{
[CmdletBinding(
    SupportsShouldProcess,
    ConfirmImpact = 'Low'
    )]
Param(  $user,
        $domain = 'contoso.local',
        $pass = 'Pa$$w0rd')
        
        $secPass = ConvertTo-SecureString -AsPlainText -Force -String $pass
        if ($PSCmdlet.ShouldProcess($user, "Setting password in $domain")) {
            Set-ADAccountPassword -Identity $user -NewPassword $secPass -Server $domain
        }
}

Set-ADPass -user 'DanPark1' -whatif
#endregion 

#endregion

#region Object
#region Select-Object
Get-Help -Name Select-Object -ShowWindow
Get-ChildItem -Path C:\scripts -File | Select-Object -First 5
Get-ChildItem -Path C:\scripts -File | Select-Object -Property FullName, length -First 5
#endregion

#region Sort-Object
Get-Help -Name Sort-Object -ShowWindow
Get-Process | Sort-Object -Property WorkingSet -Descending | Select-Object -First 10 -Property Name, WorkingSet, CPU
#endregion

#region Group-Object
Get-Help -Name Group-Object -ShowWindow
Get-Service | Group-Object -Property Status
#endregion

#region measure-object
Get-Help -Name Measure-Object -ShowWindow
Get-ChildItem -Path C:\Temp -Recurse | Measure-Object
Get-ChildItem -Path C:\Temp -Recurse | Measure-Object -Property Length -Sum

Get-Content -Path C:\Windows\lsasetup.log | Measure-Object
Get-Content -Path C:\Windows\lsasetup.log | Measure-Object -Word -Line -IgnoreWhiteSpace
#endregion

#region compare-object
#Example 1 - Process compare
Start-Process -FilePath notepad.exe
$ref = Get-Process

Stop-Process -Name notepad
$dif = Get-Process

Compare-Object -ReferenceObject $ref -DifferenceObject $dif -Property ProcessName

#Example 2 - Group membership compare
$ref = (Get-ADUser -Identity DanPark1 -Properties memberOf).memberOf
$dif = (Get-ADUser -Identity DanPark -Properties memberOf).memberOf

Compare-Object -ReferenceObject $ref -DifferenceObject $dif -IncludeEqual
#endregion 
#endregion

#region Format
#region Format-Table
Get-Process | Sort-Object -Property Name, WorkingSet | Select-Object -First 10 | Format-Table -AutoSize -Wrap
#endregion 

#region Format-List
Get-Process -Name lsass | Format-List
Get-Process -Name lsass | Format-List -Property Name, WorkingSet, CPU

Get-Process -Name lsass | Get-Member -MemberType Properties
Get-Process -Name lsass | Format-List -Property *
Get-Process -Name lsass | Select-Object -Property *
#endregion

#region Format-Wide
Get-Process | Format-Wide -Column 4
Get-Process | Format-Wide -AutoSize
#endregion
#endregion

#region Export
Get-Help -Name Export-Csv -ShowWindow
Get-Process | Select-Object -Property Name, StartTime | Export-Csv -Path C:\Temp\procs.csv
Invoke-Item -Path C:\Temp\procs.csv

Get-ChildItem -Path C:\Temp -File | Sort-Object -Property LastWriteTime -Descending |
    Format-Table -Property FullName, LastWriteTime, LastAccessTime, Length -AutoSize |
    Export-Csv -Path C:\Temp\files.csv
Invoke-Item -Path C:\Temp\files.csv

Get-ChildItem -Path C:\Temp -File | Sort-Object -Property LastWriteTime -Descending |
    Select-Object -Property FullName, LastWriteTime, LastAccessTime, Length |
    Export-Csv -Path C:\Temp\files.csv
Invoke-Item -Path C:\Temp\files.csv

Get-Process | Select-Object -First 15 -Property Name, WorkingSet, CPU | 
Export-Csv -Path C:\Temp\procs.csv
Import-Csv -Path C:\Temp\procs.csv | Sort-Object -Property WorkingSet -Descending
#Notice how the sort doesn't work as expected because WorkingSet is a string, not an int
#In those scenarios, XML is the better choice
Get-Process | Select-Object -First 15 -Property Name, WorkingSet, CPU | 
Export-Clixml -Path C:\Temp\procs.xml
Import-Clixml -Path C:\Temp\procs.xml | Sort-Object -Property WorkingSet -Descending
#endregion

#region Out verbs
Get-Process | Out-GridView
Get-Process | Out-GridView -PassThru | Stop-Process -WhatIf

Get-ADUser -Filter * | Out-GridView -PassThru | 
Export-Csv -Path C:\Temp\Managers.csv
Invoke-Item -Path C:\Temp\Managers.csv
#endregion

#region Optimization
#Built-In Arrays vs. ArrayList vs. HashTables

# Measure Speed of building array using Standard and .NET Method
Function Measure-ArraySpeed {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        $count,
        [Parameter(Mandatory)]
        [ValidateSet('Standard', 'ArrayList', 'HashTable')]
        $arrType
    )
    Switch ($arrType) {
        'Standard' {
            $arr = @()
            Measure-Command -Expression {
                for ($i = 1; $i -le $count; $i++) {
              
                    $arr += $i # Built In Way to add to array
                }
            } | Add-Member -Name 'ArrayType' -Value $_ -MemberType NoteProperty -PassThru `
            | Format-Table -Property Seconds, Milliseconds, ArrayType -AutoSize
        }

        'ArrayList' {
            $arr = New-Object System.Collections.ArrayList
            Measure-Command -Expression {
                for ($i = 1; $i -le $count; $i++) {
              
                    $arr.Add($i) # DotNet way to add to array = Much Faster
                } 
            } | Add-Member -Name 'ArrayType' -Value $_ -MemberType NoteProperty -PassThru `
            | Format-Table -Property Seconds, Milliseconds, ArrayType -AutoSize
        }

        'HashTable' {
            $arr = @{}
            Measure-Command -Expression {
                for ($i = 1; $i -le $count; $i++) {
              
                    $arr.Add($i, $i) # Hash Table - Still the fastest
                } 
            } | Add-Member -Name 'ArrayType' -Value $_ -MemberType NoteProperty -PassThru `
            | Format-Table -Property Seconds, Milliseconds, ArrayType -AutoSize
        }
    }

}

#endregion

#region cleanup

$file = Get-ChildItem -Path C:\Temp | Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-60) }
Remove-Item -Path $file
#endregion

#region What's new in 7
https://devblogs.microsoft.com/powershell/powershell-foreach-object-parallel-feature/

(Measure-Command { 1..5 | ForEach-Object { "Hello $_"; Start-Sleep 1 } }).Seconds

(Measure-Command { 1..5 | ForEach-Object -Parallel { "Hello $_"; Start-Sleep 1; } -ThrottleLimit 5 }).Seconds

#Good for processing alot of data that can work independently
Get-WinEvent -ListLog * -ErrorAction Ignore | Select-Object -First 10 -ExpandProperty LogName -OutVariable LogNames
Measure-Command { 
    $logs = $logNames | ForEach-Object -Parallel {
        Get-WinEvent -LogName $_ -MaxEvents 5000 -ErrorAction Ignore
    } -ThrottleLimit 10
}


Measure-Command {
    $logs = $logNames | ForEach-Object {
        Get-WinEvent -LogName $_ -MaxEvents 5000 -ErrorAction Ignore
    } 
}

#Avoid when executing trivial script blocks
(Measure-Command { 1..1000 | ForEach-Object -Parallel { "Hello: $_" } }).TotalMilliseconds
(Measure-Command { 1..1000 | ForEach-Object { "Hello: $_" } }).TotalMilliseconds

#Default throttleLimit is set to 5, can be set to one runspace per core
#for tasks that can run independantly of each other, this is good.

#ternary operator
https://docs.microsoft.com/en-us/powershell/scripting/whats-new/what-s-new-in-powershell-70?view=powershell-7
if (Test-Path 'C:\Foo') {
    'Path exists'
}
else {
    'Path not found'
}
# <condition> ? <if-true> : <if-false>
(Test-Path 'C:\Foo') ? 'Path exists' : 'Path not found'

<# && (AND) and || (OR)
The && operator executes the right-hand pipeline, if the left-hand pipeline succeeded. 
Conversely, the || operator executes the right-hand pipeline if the left-hand pipeline failed.
#>
#First command fails, causing second not to be executed
Write-Error 'Bad' && Write-Output 'Second'
Write-Host 'First' && Write-Host 'Second'
Write-Output 'First' && Write-Error 'Bad'

#One or both should be true
Write-Output 'First' || Write-Output 'Second'
Write-Error 'Bad' || Write-Output 'Second'

#Null-coalescing, assignment, and conditional operators
$myVar = $null
$myVar ?? 'This is null'

$myVar ??= 'I fixed it'

$myVar ?? 'This is null'

#Highlight match in select-string
'This is some text' | Select-String -Pattern 'some'

#Concise Error View
Get-Process -Name foo 
$errorView
#endregion
Test-Connection localhost

Get-Error