# Moves the skills and settings into the project's .claude folder.
# Run from the Group Project folder:  powershell -ExecutionPolicy Bypass -File .\claude-setup\install.ps1
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Src  = Join-Path $Root "claude-setup"
$Dst  = Join-Path $Root ".claude"
New-Item -ItemType Directory -Force -Path (Join-Path $Dst "skills") | Out-Null
Copy-Item -Recurse -Force (Join-Path $Src "skills\*") (Join-Path $Dst "skills")
$NewSettings = Join-Path $Src "settings.json"
$CurSettings = Join-Path $Dst "settings.json"
if ((Test-Path $CurSettings) -and ((Get-FileHash $CurSettings).Hash -ne (Get-FileHash $NewSettings).Hash)) {
    $Backup = "$CurSettings.bak-$(Get-Date -Format yyyyMMdd-HHmmss)"
    Copy-Item $CurSettings $Backup
    Write-Host "Existing settings.json backed up to $Backup" -ForegroundColor Yellow
}
Copy-Item -Force $NewSettings $CurSettings
Get-ChildItem -Recurse $Dst | Select-Object FullName
Write-Host "Done. You can delete the claude-setup folder." -ForegroundColor Green
