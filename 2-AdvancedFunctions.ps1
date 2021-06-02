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

#region HelpURI
Function Get-Something 
{
<#
        .LINK
            http://www.contoso.local
    #>
    
    [CmdletBinding(
        HelpURI='http://www.bing.com'
    )]
    Param (
        [parameter(ValueFromPipeLine=$True)]
        $Data
    )
    Begin{}
    Process{Write-Output $Data}
    End{}
}

Get-Help Get-Something -Online

#endregion

#region SupportsPaging
Function Get-Something {
  
    [CmdletBinding(SupportsPaging = $True)]
    Param ( $Data )
    Begin{}
    Process{}
    End {
        If($Data.count -gt 0) {
            If($PSCmdlet.PagingParameters.Skip -ge $Data.count) {
                Write-Verbose "No results satisfy the Skip parameters"
            } Elseif($PSCmdlet.PagingParameters.First -eq 0) {
                Write-Verbose "No results satisfy the First parameters"
            } Else {
            $First = $PSCmdlet.PagingParameters.Skip
            Write-Verbose ("First: {0}" -f $First)
            $Last = $First + 
                [Math]::Min($PSCmdlet.PagingParameters.First, $Data.Count - $PSCmdlet.PagingParameters.Skip) - 1    
            }
            If ($Last -le 0) {
                $Data = $Null
            } Else {
                $Data = $Data[$First..$last]
                Write-Output $Data            
            }
            Write-Verbose ("Last: {0}" -f $Last)
        }
        If ($PSCmdlet.PagingParameters.IncludeTotalCount){
            [double]$Accuracy = 1.0
            $PSCmdlet.PagingParameters.NewTotalCount($Data.count, $Accuracy)
        }
    }
}

Get-Something -Data (Get-ChildItem C:\Windows\System32) -IncludeTotalCount 

Get-Something -Data (Get-ChildItem C:\Windows\System32) -First 10

Get-Something -Data (Get-ChildItem C:\Windows\System32) -Skip 3180

Get-Something -Data (Get-ChildItem C:\Windows\System32) -First 10 -Skip 3350 -IncludeTotalCount

#endregion

#region PositionalBinding
Function Get-MyProcess{
    [CmdletBinding()]
    Param(
        [string]$Name = 'lsass',
        $Computer
    )
    Get-Process -Name $Name -ComputerName $Computer
}

Get-MyProcess lsass MS
Get-MyProcess MS lsass
#endregion

#EndRegion

#Region Begin/Process/End
Get-Help -Name Test-WSMan -Parameter ComputerName
'MS','DC' | Test-WSMan
Function Get-MyProcessInfo{
    
    Begin{
        Write-Host -Object "Begin Block: Setting process count to 0" -ForegroundColor Green
        $Counter = 0
    }
    Process{
        Write-Host -Object "Process Block: Currently counting $_" -ForegroundColor Cyan
        $Counter++
    }
    End{
        Write-Host -Object "End Block: There were $Counter processes" -ForegroundColor Yellow
    }
}
(Get-Process).Name | Get-MyProcessInfo

#EndRegion