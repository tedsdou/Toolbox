function Expand-Drive {
    <#
    .Synopsis
    Expand hard drive to utilize all available space.
    .DESCRIPTION
    After increasing the volume size in the VM shell, use this command to expand the drive in Windows.
    .EXAMPLE
    'ms','foo','win10' | Expand-Drive -DriveLetter 'C'
    This sends three machines through the pipeline to run on the C drive
    .EXAMPLE
    Expand-Drive -Computer 'WIN10', 'MS' -DriveLetter 'X'
    This example will expand the X drive on WIN10 and MS.
    #>
    [CmdletBinding()]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline
        )]
        [string[]]$ComputerName,

        # Param2 help description
        [Parameter(Mandatory = $true,
            Position = 1)]
        [String]$DriveLetter
    )

    Process {
        foreach ($Computer in $ComputerName) {
            Write-Verbose -Message "SCANNING Drive: $($DriveLetter.ToUpper()) - Server: $($Computer.ToUpper())"
            #Creating a CIM session is a low-level form of PowerShell Remoting
            try {
                $Cim = New-CimSession -ComputerName $Computer -ErrorAction Stop
            }
            catch {
                Write-Warning -Message "Unable to connect to $Computer`n`rERROR: $($_.Exception.Message)"
                Continue
            }
            
            try {
                $OrigSize = Get-Volume -DriveLetter $DriveLetter -CimSession $Cim -ErrorAction Stop
                $MaxSize = Get-PartitionSupportedSize -DriveLetter $DriveLetter -CimSession $Cim -ErrorAction Stop
    
                if ($MaxSize.SizeMax -gt ($OrigSize.Size + 1mb)) {
                    Write-Verbose -Message "RESIZING Drive: $($DriveLetter.ToUpper()) - Server: $($Computer.ToUpper())"
                    Resize-Partition -DriveLetter $DriveLetter -Size $MaxSize.SizeMax -CimSession $Cim -ErrorAction Stop
                }
    
                $NewSize = Get-Volume -DriveLetter $DriveLetter -CimSession $Cim -ErrorAction Stop
                [PSCustomObject]@{
                    'Server'       = $Computer.ToUpper()
                    'DriveLetter'  = $DriveLetter.ToUpper()
                    'OriginalSize' = ('{0:n0}GB' -f ($OrigSize.Size / 1gb))
                    'NewSize'      = ('{0:n0}GB' -f ($NewSize.Size / 1gb))
                    'FreeSpace'    = ('{0:n0}GB' -f ($NewSize.SizeRemaining / 1gb))
                }
                $null = Remove-CimSession -CimSession $Cim  
            }
            catch {
                $($_.Exception.Message)
            }           
        }
    } 
}