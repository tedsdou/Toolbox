function Test-NameConnectivity {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [String[]]$Name,
        
        [String]$Domain = $env:UserDomain
    )
        
    process {
        foreach ($N in $Name) {
            if (Test-NetConnection -ComputerName $N -ErrorAction SilentlyContinue) {
                [PSCustomObject]@{
                    'Name' = $N
                }
            }
            elseif (Test-NetConnection -ComputerName "$N.$Domain" -ErrorAction SilentlyContinue) {
                [PSCustomObject]@{
                    'Name' = "$N.$Domain"
                }
            }
            else {
                [PSCustomObject]@{
                    'Name' = 'Unable to connect'
                }
            }
        }   
    }
}