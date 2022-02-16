Function Get-PublicIP {
    [CmdletBinding()]
    Param()
    $pattern = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    $null = (Invoke-WebRequest -Uri 'https://www.bing.com/search?q=IP+Address' | Select-Object -Property content) -match $pattern 
    If ($Matches) { Write-Output $Matches.values  }
}
function Request-JITAccess {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $SubscriptionId ,
        [Parameter(Mandatory)]
        $ResourceGroupName,
        [Parameter(Mandatory)]
        $VMName,
        [Parameter(Mandatory)]
        $IPv4Address,
        [ValidateSet('22', '5985', '5986', '3389')]
        $Port = 3389,
        [ValidateRange(1, 3)]
        $AccessTime = 3
    )
    
    begin {
        $VM = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName
        if (-Not $VM) {
            Throw "VM $VMName not found in resource group $ResourceGroupName"
        }
    }
    
    process {
        $JitPolicyVm1 = (@{
                id    = $VM.Id
                ports = (@{
                        number                     = $Port;
                        endTimeUtc                 = ('{0:u}' -f (Get-Date).AddHours($AccessTime).ToUniversalTime() -replace ' ', 'T');
                        allowedSourceAddressPrefix = @($IPv4Address)
                    })
            })
    
        $JitPolicyArr = @($JitPolicyVm1)
        try {
            Start-AzJitNetworkAccessPolicy -ResourceId "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Security/locations/$($VM.Location)/jitNetworkAccessPolicies/default" -VirtualMachine $JitPolicyArr -ErrorAction Stop
        }
        catch {
            $_.Exception.Message
        }
    }
}

Request-JITAccess -SubscriptionId (Get-AzContext).Subscription.Id -ResourceGroupName fedex -VMName ms2022 -IPv4Address (Get-PublicIP) -Port 3389