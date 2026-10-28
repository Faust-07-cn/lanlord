# Build lanlord.exe. Self-contained: toolchain auto-detected + auto-bootstrapped.
#   pwsh -File .\build.ps1                  # build
#   pwsh -File .\build.ps1 -BuildDir D:\out # override output dir
param([string]$BuildDir = '')
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

# --- ASCII tools location (MinGW ld cannot handle non-ASCII paths) ---
$isAscii = $true
foreach ($ch in $root.ToCharArray()) { if ([int]$ch -gt 127) { $isAscii = $false; break } }
if ($isAscii) { $toolsRoot = Join-Path $root 'tools' }
else { $toolsRoot = [System.IO.Path]::GetFullPath((Join-Path $root '..\lanlord-tools')) }

function Resolve-Gcc {
    $local = Join-Path $toolsRoot 'mingw64\bin\gcc.exe'
    if (Test-Path $local) { return $local }
    $g = Get-Command gcc -ErrorAction SilentlyContinue
    if ($g) { return $g.Source }
    return $null
}
$gcc = Resolve-Gcc
if (-not $gcc) {
    Write-Host "编译器未找到，自动引导下载工具链到 $toolsRoot ..." -ForegroundColor Yellow
    & (Join-Path $root 'scripts\bootstrap.ps1')
    $gcc = Resolve-Gcc
    if (-not $gcc) { throw '工具链引导失败，请手动运行 scripts\bootstrap.ps1' }
}

if ($BuildDir) { $outDir = $BuildDir }
elseif ($isAscii) { $outDir = Join-Path $root 'build' }
else { $outDir = [System.IO.Path]::GetFullPath((Join-Path $root '..\build')) }
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
$out = Join-Path $outDir 'lanmgr.exe'
$args += @('-o', $out)
$args += $libs

Write-Output ("compiling " + $src.Count + " source files -> " + $out)
Write-Output ("  gcc = " + $gcc)
& $gcc @args
if ($LASTEXITCODE -ne 0) { Write-Error "BUILD FAILED (exit $LASTEXITCODE)"; exit 1 }
Write-Output "BUILD OK"
