param(
    [string]$BuildDirectory = "build-final",
    [string]$OutputDirectory = "release",
    [string]$MingwBin = ""
)

$ErrorActionPreference = "Stop"
$buildPath = (Resolve-Path $BuildDirectory).Path
$outputPath = [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $OutputDirectory))
$executable = Join-Path $buildPath "sentinel.exe"
$testExecutable = Join-Path $buildPath "sentinel_tests.exe"
$resolvedMingwBin = $MingwBin
if ([string]::IsNullOrWhiteSpace($resolvedMingwBin)) {
    $windeployqtCommand = Get-Command windeployqt.exe -ErrorAction SilentlyContinue
    if ($null -ne $windeployqtCommand) {
        $resolvedMingwBin = Split-Path $windeployqtCommand.Source -Parent
    }
}
if ([string]::IsNullOrWhiteSpace($resolvedMingwBin)) {
    throw "MingwBin was not provided and windeployqt.exe was not found on PATH. Pass -MingwBin <Qt/MinGW bin directory>."
}
$resolvedMingwBin = (Resolve-Path $resolvedMingwBin).Path
$windeployqt = Join-Path $resolvedMingwBin "windeployqt.exe"

if (-not (Test-Path $executable)) { throw "Executable not found: $executable" }
if (-not (Test-Path $windeployqt)) { throw "Qt deployment tool not found: $windeployqt" }

New-Item -ItemType Directory -Force -Path $outputPath | Out-Null
Copy-Item $executable (Join-Path $outputPath "sentinel.exe") -Force
if (Test-Path $testExecutable) {
    Copy-Item $testExecutable (Join-Path $outputPath "sentinel_tests.exe") -Force
}
& $windeployqt --release --compiler-runtime --no-translations --dir $outputPath (Join-Path $outputPath "sentinel.exe")
if ($LASTEXITCODE -ne 0) { throw "windeployqt failed with exit code $LASTEXITCODE" }

$runtimeDlls = @(
    "libgcc_s_seh-1.dll", "libstdc++-6.dll", "libwinpthread-1.dll",
    "libsqlite3-0.dll", "libicudt78.dll", "libicuin78.dll", "libicuio78.dll",
    "libicutest78.dll", "libicutu78.dll", "libicuuc78.dll",
    "libb2-1.dll", "libdouble-conversion.dll", "libpcre2-16-0.dll",
    "zlib1.dll", "libzstd.dll", "libfreetype-6.dll", "libharfbuzz-0.dll",
    "libmd4c.dll", "libpng16-16.dll", "libbrotlidec.dll", "libbrotlicommon.dll",
    "libbz2-1.dll", "libglib-2.0-0.dll", "libgraphite2.dll", "libintl-8.dll",
    "libjpeg-8.dll", "libgio-2.0-0.dll", "libgobject-2.0-0.dll", "libiconv-2.dll",
    "libpcre2-8-0.dll", "libgmodule-2.0-0.dll", "libffi-8.dll"
)
foreach ($dll in $runtimeDlls) {
    $source = Join-Path $resolvedMingwBin $dll
    if (-not (Test-Path $source)) { throw "Required runtime DLL not found: $source" }
    Copy-Item $source (Join-Path $outputPath $dll) -Force
}
Write-Output "Deployment complete: $outputPath"
