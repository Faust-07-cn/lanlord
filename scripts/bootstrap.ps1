# One-time toolchain bootstrap (no admin). Downloads portable CMake + MinGW-w64.
# Location: <project>\tools if the project path is ASCII, else sibling ..\lanlord-tools.
#   pwsh -File .\scripts\bootstrap.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$isAscii = $true
foreach ($ch in $root.ToCharArray()) { if ([int]$ch -gt 127) { $isAscii = $false; break } }
if ($isAscii) { $tools = Join-Path $root 'tools' }
else { $tools = [System.IO.Path]::GetFullPath((Join-Path $root '..\lanlord-tools')) }
$dl = Join-Path $tools '_dl'
New-Item -ItemType Directory -Force -Path $dl | Out-Null

$cmakeUrl = 'https://github.com/Kitware/CMake/releases/download/v4.4.4/cmake-4.4.4-windows-x86_64.zip'
$gccUrl   = 'https://github.com/brechtsanders/winlibs_mingw/releases/download/16.2.0posix-23.1.3-14.0.0-ucrt-r3/winlibs-x86_64-posix-seh-gcc-16.2.0-mingw-w64ucrt-14.0.0-r3.zip'

if (-not (Test-Path "$tools\mingw64\bin\gcc.exe")) {
    Write-Host '下载 GCC (winlibs MinGW-w64) ...'
    curl.exe -L --fail --retry 3 -o "$dl\gcc.zip" $gccUrl
    tar.exe -xf "$dl\gcc.zip" -C "$tools"
}
if (-not (Test-Path "$tools\cmake\bin\cmake.exe")) {
    Write-Host '下载 CMake ...'
    curl.exe -L --fail --retry 3 -o "$dl\cmake.zip" $cmakeUrl
    tar.exe -xf "$dl\cmake.zip" -C "$tools"
    $v = Get-ChildItem "$tools" -Directory -Filter 'cmake-*' | Select-Object -First 1
    if ($v -and -not (Test-Path "$tools\cmake")) { Rename-Item $v.FullName (Join-Path $tools 'cmake') }
}
Write-Host ("工具链就绪: " + $tools + "  运行 .\build.ps1 构建")
