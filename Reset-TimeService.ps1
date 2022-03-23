function Reset-TimeService {
    [CmdletBinding()]
    param ()
    $ErrorActionPreference = 'Stop'
    try {
        $null = Stop-Service -Name W32Time -Force 
        $null = w32tm.exe /unregister
        $null = w32tm.exe /register
        $null = Start-Service -Name W32Time -Force
        Write-Output -InputObject 'Reset Time Service Complete'
    }
    catch {
        $_.Exception.Message
    }
}