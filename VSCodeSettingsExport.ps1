#On source machine
$ExportPath = 'C:\Temp\VSCodeSettings'
if (-Not(Test-Path -Path $ExportPath)) {
    $null = New-Item -ItemType Directory -Path $ExportPath
}
if (-Not(Test-Path -Path "$ExportPath\extensions")) {
    $null = New-Item -ItemType Directory -Path "$ExportPath\extensions"
}
$files = "$env:APPDATA\Code\User\keybindings.json","$env:APPDATA\Code\User\settings.json"
Copy-Item -Path $files -Destination $ExportPath
Copy-item -Path "$ENV:USERPROFILE\.vscode\extensions\*" -Destination "$ExportPath\extensions"
Compress-Archive -Path $ExportPath -DestinationPath "$ExportPath.zip"

#On target machine
Expand-Archive -Path "$ExportPath.zip" -DestinationPath $ExportPath
Copy-Item -Destination "$ENV:USERPROFILE\.vscode\extensions\*" -Path "$ExportPath\extensions" -Force
Copy-Item -Destination $files -Path $ExportPath -Force
