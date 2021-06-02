#Region Three Core Cmdlets
Get-Command
Get-Command -Name *process*

Get-Help -Name Stop-Process -ShowWindow

Get-Process -Name Lsass | Get-Member -MemberType Properties
(Get-Process -Name Lsass).CPU

Get-Date | Get-Member -MemberType Methods
(Get-Date).AddDays(-60)
$date = Get-Date
$date.Year

$Query = Get-CimInstance -ClassName CIM_OperatingSystem
$Query | Get-Member
$Query.Caption
#EndRegion

Get-Process | Where-Object { $_.ProcessName -match 'svc' } | ForEach-Object { Write-Host -ForegroundColor Cyan -Object $_.ProcessName }

$arr = Get-Process
$arr[0].processname

$Arr = @()
$arr += 123
$arr += 456
#Region Script Basics
Get-ExecutionPolicy -List
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned

#Sign scripts
code C:\scripts\helloWorld.ps1
$cert = Get-ChildItem -Path Cert:\ -CodeSigningCert -Recurse
Set-AuthenticodeSignature -FilePath C:\scripts\helloWorld.ps1 -Certificate $cert

#Modules
$env:PSModulePath -split ';' | ForEach-Object { Invoke-Item $_ -ErrorAction Ignore }
#requires -Module ActiveDirectory
#-OR-
If (-Not(Get-Module -Name Az -ListAvailable)) { Install-Module -Name Az }

#Building Help : Use comment-help snippet 
<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.EXAMPLE
    PS C:\> <example usage>
    Explanation of what the example does
.INPUTS
    Inputs (if any)
.OUTPUTS
    Output (if any)
.NOTES
    General notes
#>
#EndRegion

#Region FlowControl - Use your snippets
$a = 0
while ($a -lt 10) {
    Write-Warning -Message $a
    $a++
}

for ($i = 0; $i -lt 100; $i += 5) {
    Write-Warning "Server-$i"
}

$service = Get-Service
foreach ($s in $service) {
    "Name: $($s.Name) | Status: $($s.Status)"
}

if (Get-ADUser -Filter { Name -eq 'DanPark' }) {
    'Found DanPark'
}
elseif (Get-ADUser -Filter { Name -eq 'DanPark1' }) {
    'Found DanPark1'
}
Else {
    'Did not find either'
}

switch ((Get-ADUser -Filter { Name -like 'DanPark*' }).Name) {
    'DanPark' { "Found $_"; Continue }
    'DanPark1' { "Found $_" ; Continue}
    Default { "Not Found $_" }
}

$User = (Get-ADUser -Filter { Name -like 'Office*' }).Name
foreach ($u in $User) {
    If ($u -match '11|13') {
        Write-Warning -Message "Skipping $u"
        Continue
    }
    "Processing $u"
}
#EndRegion

#Region Function Basics
Get-Process -Name lsass

function Get-MyProcess {
    param (
        $Name
    )
    Get-Process -Name $Name
}
#EndRegion

#Region RegEx
Get-Help about_Regular_Expressions -ShowWindow
'Find PowerShell in this string' -match 'PowerShell'
$Matches

$Matches = $null
'Find PowerShell in this string' -match 'P\w+l'

'192.168.23.34' -split '.'
'192.168.23.34' -split '\.'
ipconfig.exe /all | Select-String -Pattern 'ipv4'
#EndRegion
#region 