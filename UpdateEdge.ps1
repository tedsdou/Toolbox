[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Download = 'https://go.microsoft.com/fwlink/?linkid=2108834&Channel=Stable&language=en'
$InstallPath = 'C:\Temp\MicrosoftEdgeSetup.exe'
Invoke-WebRequest -Uri $Download -OutFile $InstallPath
$null = Start-Process -FilePath $InstallPath -ArgumentList '/silent /install' -PassThru
while (Get-Process -Name 'MicrosoftEdgeSetup') {
    Write-Warning -Message 'Waiting for Edge to update'
    Start-Sleep -Seconds 45
}
$IELink = 'C:\Users\student\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Internet Explorer.lnk'
$EdgeLink = 'C:\Users\student\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk'

Copy-Item -Path $IELink -Destination $EdgeLink
Remove-Item -Path $IELink -Force

$shell = New-Object -COM WScript.Shell
$shortcut = $shell.CreateShortcut($EdgeLink)  ## Open the lnk
$shortcut.TargetPath = '"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -profile-directory=Default'
$shortcut.Description = 'Browse the Web'  ## This is the "Comment" field
$shortcut.Save()  ## Save

Write-Host -ForegroundColor Green -Object 'Edge Update Complete'