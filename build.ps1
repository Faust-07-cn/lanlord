# Direct-build script (fast iteration; no cmake/ninja needed).
# Toolchain: portable MinGW-w64 on E:\Chengdu_DB_soft\toolchain\mingw64
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$gcc  = 'E:\Chengdu_DB_soft\toolchain\mingw64\bin\gcc.exe'

if (-not (Test-Path $gcc)) {
    Write-Error "未找到编译器: $gcc（先运行 scripts/bootstrap.ps1）"
    exit 1
}

# MinGW ld corrupts non-ASCII output paths under the GBK ACP, so build to an ASCII-only dir.
$outDir = 'E:\Chengdu_DB_soft\build'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$inc = @("$root\src", "$root\third_party\cJSON")
$inc += Get-ChildItem -Path "$root\src" -Recurse -Directory | ForEach-Object { $_.FullName }
$src = @()
$src += Get-ChildItem -Path "$root\src" -Recurse -Filter *.c | ForEach-Object { $_.FullName }
$src += "$root\third_party\cJSON\cJSON.c"

$libs = @('-lws2_32','-liphlpapi','-lcrypt32','-lwinhttp','-ladvapi32','-luser32','-lshell32','-lbcrypt','-lm')

$args = @('-std=c11','-O0','-g','-Wall','-Wextra')
foreach ($i in $inc) { $args += "-I$i" }
$args += $src
$args += @('-o', (Join-Path $outDir 'lanmgr.exe'))
$args += $libs

Write-Output ("compiling " + $src.Count + " source files -> " + (Join-Path $outDir 'lanmgr.exe'))
& $gcc @args
if ($LASTEXITCODE -ne 0) { Write-Error "BUILD FAILED (exit $LASTEXITCODE)"; exit 1 }
Write-Output "BUILD OK"
