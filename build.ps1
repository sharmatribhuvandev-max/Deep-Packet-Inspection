# Builds Deep Packet Inspection and its tests with g++ (MSYS2 / MinGW-w64) on Windows.
# Usage:  .\build.ps1          build only
#         .\build.ps1 -Test    build, then run the unit tests

param([switch]$Test)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
New-Item -ItemType Directory -Force build | Out-Null

# -static bundles the C++ runtime into the .exe, so it runs on any Windows PC
# without MSYS2's DLLs (and never picks up a different, incompatible copy).
$flags = @('-std=c++17', '-O2', '-Wall', '-Wextra', '-pedantic', '-pthread', '-static', '-I', 'include')
$core = Get-ChildItem src -Filter *.cpp | Where-Object Name -ne 'main.cpp' | ForEach-Object FullName

Write-Host 'Building build\dpi.exe ...'
g++ @flags -o build/dpi.exe @core src/main.cpp
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host 'Building build\dpi_tests.exe ...'
g++ @flags -o build/dpi_tests.exe @core tests/test_main.cpp
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($Test) { .\build\dpi_tests.exe; exit $LASTEXITCODE }
Write-Host 'Done.'
