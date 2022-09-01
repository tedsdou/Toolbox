[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Download = 'https://go.microsoft.com/fwlink/?linkid=2108834&Channel=Stable&language=en'
$InstallPath = 'C:\Temp\MicrosoftEdgeSetup.exe'
Invoke-WebRequest -Uri $Download -OutFile $InstallPath
$null = Start-Process -FilePath $InstallPath -ArgumentList '/silent /install' -PassThru
while (Get-Process -Name 'MicrosoftEdgeSetup' -ErrorAction Ignore) {
    Write-Warning -Message 'Waiting for Edge to update'
    Start-Sleep -Seconds 45
}

Write-Host -ForegroundColor Cyan -Object 'Edge Update Complete' -BackgroundColor Black

