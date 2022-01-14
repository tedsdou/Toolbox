$Download = 'https://go.microsoft.com/fwlink/?linkid=2108834&Channel=Stable&language=en'
$InstallPath = 'C:\Temp\MicrosoftEdgeSetup.exe'
Invoke-WebRequest -Uri $Download -OutFile $InstallPath
$StartInstall = Start-Process -FilePath $InstallPath -ArgumentList '/silent /install'
while ($StartInstall) {
    Write-Warning -Message 'Waiting for Edge to update'
    Start-Sleep -Seconds 5
}

Copy-Item -Path $IELink -Destination $EdgeLink
$shell = New-Object -COM WScript.Shell
$shortcut = $shell.CreateShortcut($destination)  ## Open the lnk
$shortcut.TargetPath = '"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -profile-directory=Default'
$shortcut.Description = 'Browse the Web'  ## This is the "Comment" field
$shortcut.Save()  ## Save

$IELink = 'C:\Users\student\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Internet Explorer.lnk'
$EdgeLink = 'C:\Users\student\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk'
Remove-Item -Path $IELink -Force

Write-Host -ForegroundColor Green -Object 'Edge Update Complete'