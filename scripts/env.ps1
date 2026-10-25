# Dot-source this to put the portable toolchain on PATH for the current session.
#   . .\scripts\env.ps1
$tc = 'E:\Chengdu_DB_soft\toolchain'
$env:PATH = "$tc\mingw64\bin;$tc\cmake-4.4.4-windows-x86_64\bin;$env:PATH"
Write-Output "Toolchain on PATH: gcc $(gcc -dumpversion)"
