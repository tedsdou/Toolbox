#Source file to create
$NewConfiguration = @{
    '$schema' = 'https://aka.ms/PowerShell/Crescendo/Schemas/2021-11'
    Commands = @()
}

$parameters = @{
    Verb = 'Invoke'
    Noun = 'W32Time'
    OriginalName = 'C:\Windows\System32\w32tm.exe'
}

$NewConfiguration.Commands += New-CrescendoCommand @parameters
$NewConfiguration | ConvertTo-Json -Depth 3 | Out-File 'C:\Temp\W32Time.json'
#open up json and add pertinent information
code 'C:\Temp\W32Time.json'
#Once edited, export it out and it generates the module.
Export-CrescendoModule -ConfigurationFile 'C:\Temp\W32Time.json' -ModuleName W32Time.psm1