# One-time toolchain bootstrap (no admin). Downloads portable CMake + MinGW-w64.
#   pwsh -File .\scripts\bootstrap.ps1
$ErrorActionPreference = 'Stop'
$tc = 'E:\Chengdu_DB_soft\toolchain'
$dl = "$tc\_dl"
New-Item -ItemType Directory -Force -Path $dl | Out-Null

$cmakeUrl = 'https://github.com/Kitware/CMake/releases/download/v4.4.4/cmake-4.4.4-windows-x86_64.zip'
$gccUrl   = 'https://github.com/brechtsanders/winlibs_mingw/releases/download/16.2.0posix-23.1.3-14.0.0-ucrt-r3/winlibs-x86_64-posix-seh-gcc-16.2.0-mingw-w64ucrt-14.0.0-r3.zip'

if (-not (Test-Path "$tc\mingw64\bin\gcc.exe")) {
    Write-Host "下载 GCC (winlibs MinGW-w64) ..."
    curl.exe -L --fail --retry 3 -o "$dl\gcc.zip" $gccUrl
    tar.exe -xf "$dl\gcc.zip" -C "$tc"
}
if (-not (Test-Path "$tc\cmake-4.4.4-windows-x86_64\bin\cmake.exe")) {
    Write-Host "下载 CMake ..."
    curl.exe -L --fail --retry 3 -o "$dl\cmake.zip" $cmakeUrl
    tar.exe -xf "$dl\cmake.zip" -C "$tc"
}
Write-Host "完成。请运行: . .\scripts\env.ps1"
