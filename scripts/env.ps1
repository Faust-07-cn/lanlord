# Dot-source this to put the auto-resolved toolchain on PATH for the current session.
#   . .\scripts\env.ps1
$root = Split-Path -Parent $PSScriptRoot
$isAscii = $true
foreach ($ch in $root.ToCharArray()) { if ([int]$ch -gt 127) { $isAscii = $false; break } }
if ($isAscii) { $tools = Join-Path $root 'tools' }
else { $tools = [System.IO.Path]::GetFullPath((Join-Path $root '..\lanlord-tools')) }
$env:PATH = "$tools\mingw64\bin;$tools\cmake\bin;$env:PATH"
if (Get-Command gcc -ErrorAction SilentlyContinue) {
    Write-Output ("Toolchain on PATH: gcc " + (gcc -dumpversion))
} else {
    Write-Output ('工具链未就绪: ' + $tools + '  先运行 scripts\bootstrap.ps1')
}
