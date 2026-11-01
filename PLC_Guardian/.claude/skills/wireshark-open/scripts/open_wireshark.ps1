# Starts the Wireshark GUI detached so the calling terminal (and Claude) isn't blocked.
# Called by open.sh; can also be run directly:
#   powershell -NoProfile -ExecutionPolicy Bypass -File open_wireshark.ps1 -Exe "C:\Program Files\Wireshark\Wireshark.exe" -File "C:\...\x.pcapng" [-Filter "mbtcp"] [-Frame 42]
param(
  [Parameter(Mandatory = $true)][string]$Exe,
  [Parameter(Mandatory = $true)][string]$File,
  [string]$Filter = "",
  [string]$Frame = ""
)
function Quote([string]$s) { '"' + ($s -replace '"', '\"') + '"' }
$argList = @('-r', (Quote $File))
if ($Filter) { $argList += @('-Y', (Quote $Filter)) }
if ($Frame)  { $argList += @('-g', $Frame) }
Start-Process -FilePath $Exe -ArgumentList $argList
