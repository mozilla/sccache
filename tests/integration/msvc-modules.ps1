param(
    [Parameter(Mandatory = $true)][string]$Sccache,
    [Parameter(Mandatory = $true)][string]$WorkDir,
    [switch]$ExpectUncached,
    [switch]$Mapped
)

$ErrorActionPreference = 'Stop'
$Sccache = (Resolve-Path -LiteralPath $Sccache).Path
if (Test-Path -LiteralPath $WorkDir) { throw 'WorkDir must not already exist' }
$null = New-Item -ItemType Directory -Path $WorkDir
$WorkDir = (Resolve-Path -LiteralPath $WorkDir).Path
$cl = (Get-Command cl.exe -ErrorAction Stop).Source
$revision = '40626af88bd7df9a5fb80be7b25ac85b122d6c21' # fmt 11.2.0
$savedEnv = @{}
Get-ChildItem Env: | Where-Object Name -Like 'SCCACHE_*' | ForEach-Object {
    $savedEnv[$_.Name] = $_.Value
    Remove-Item -LiteralPath "Env:$($_.Name)"
}
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$listener.Start()
$env:SCCACHE_SERVER_PORT = [string]$listener.LocalEndpoint.Port
$listener.Stop()
$env:SCCACHE_DIR = Join-Path $WorkDir 'cache'
$env:SCCACHE_CACHED_CONF = Join-Path $WorkDir 'cached-config'
$results = [System.Collections.Generic.List[object]]::new()
$artifactHashes = @{}

function Invoke-Checked([string]$Exe, [string[]]$Arguments) {
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Exe failed ($LASTEXITCODE): $Arguments" }
}

function Start-Server {
    Invoke-Checked $Sccache @('--start-server')
    $connection = [System.Net.Sockets.TcpClient]::new()
    try { $connection.Connect('127.0.0.1', [int]$env:SCCACHE_SERVER_PORT) }
    finally { $connection.Dispose() }
}

$producerArgs = @('/nologo', '/c', '/std:c++20', '/EHsc', '/MD', '/Z7', '/utf-8',
    '/interface', 'fmt\src\fmt.cc', '/Ifmt\include', '/ifcOutput', 'fmt.ifc',
    '/Fofmt.obj', '/sourceDependencies', 'fmt.json')
$consumerArgs = @('/nologo', '/c', '/std:c++20', '/EHsc', '/MD', '/Z7', '/utf-8',
    'consumer.cpp', '/reference', 'fmt=fmt.ifc', '/Foconsumer.obj',
    '/sourceDependencies', 'consumer.json')
$fmtProducerArgs = $producerArgs
$fmtConsumerArgs = $consumerArgs
$artifacts = @('fmt.ifc', 'fmt.obj', 'consumer.obj')
$linkObjects = @('fmt.obj', 'consumer.obj')
$expectedOutput = 'The answer is 42'

function Build-Phase([string]$Name, [bool]$Hit, [int]$ExpectedHits = -1) {
    if ($ExpectedHits -lt 0) { $ExpectedHits = 2 * [int]$Hit }
    Invoke-Checked $Sccache @('--zero-stats')
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    Invoke-Checked $Sccache (@($cl) + $producerArgs)
    Invoke-Checked $Sccache (@($cl) + $consumerArgs)
    $clock.Stop()
    $statsText = & $Sccache --show-stats --stats-format=json
    if ($LASTEXITCODE -ne 0) { throw 'Unable to read cache statistics' }
    $stats = ($statsText | ConvertFrom-Json).stats
    $hits = [int]$stats.cache_hits.counts.'C/C++'
    $misses = [int]$stats.cache_misses.counts.'C/C++'
    $uncached = [int]$stats.requests_not_cacheable
    if ($ExpectUncached) {
        if ($hits -ne 0 -or $misses -ne 0 -or $uncached -ne 2) {
            throw "Baseline unexpectedly cached $Name`: hits=$hits misses=$misses uncached=$uncached"
        }
    } elseif ($hits -ne $ExpectedHits -or $misses -ne (2 - $ExpectedHits) -or $uncached -ne 0) {
        throw "Unexpected $Name statistics: hits=$hits misses=$misses uncached=$uncached"
    }
    $exe = "consumer-$Name.exe"
    Invoke-Checked $cl (@('/nologo') + $linkObjects + @("/Fe$exe"))
    $actual = & (Join-Path (Get-Location).Path $exe)
    if ($LASTEXITCODE -ne 0 -or $actual -ne $expectedOutput) {
        throw "Unexpected consumer result: $actual"
    }
    $hashes = @{}
    foreach ($artifact in $artifacts) {
        $hashes[$artifact] = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash
        if ($Hit -and !$ExpectUncached -and $hashes[$artifact] -ne $artifactHashes[$artifact]) {
            throw "Cache did not restore the genuine $artifact"
        }
        $artifactHashes[$artifact] = $hashes[$artifact]
    }
    $results.Add([pscustomobject]@{
        Phase = $Name; Hits = $hits; Misses = $misses; Uncached = $uncached
        Milliseconds = $clock.ElapsedMilliseconds; SHA256 = $hashes
    })
}

Push-Location $WorkDir
try {
    Invoke-Checked git @('clone', '--depth', '1', '--branch', '11.2.0', 'https://github.com/fmtlib/fmt.git', 'fmt')
    $actualRevision = & git -C fmt rev-parse HEAD
    if ($LASTEXITCODE -ne 0 -or $actualRevision -ne $revision) { throw 'Unexpected fmt revision' }
    # This file is our consumer, not a copy of third-party source.
    Set-Content -LiteralPath consumer.cpp -Encoding ascii -Value @'
#include <string>
import fmt;
int main() {
    auto text = fmt::format("The answer is {}", 42);
    fmt::print("{}\n", text);
    return text == "The answer is 42" ? 0 : 1;
}
'@
    Start-Server
    Build-Phase 'cold' $false
    foreach ($artifact in $artifacts) { Remove-Item -LiteralPath $artifact }
    Remove-Item -LiteralPath fmt.json, consumer.json
    Build-Phase 'warm-restored' $true
    Invoke-Checked $Sccache @('--stop-server')
    Start-Server
    foreach ($artifact in $artifacts) { Remove-Item -LiteralPath $artifact }
    Build-Phase 'fresh-server' $true
    Invoke-Checked $Sccache @('--stop-server')
    $env:SCCACHE_DIR = Join-Path $WorkDir 'fresh-cache'
    Start-Server
    Build-Phase 'fresh-cache' $false
    $producerArgs += '/DFMT_OS=0'
    Build-Phase 'changed-module-flags' $false
    Set-Content -LiteralPath unit.h -Encoding ascii -Value 'inline int unit_value() { return 23; }'
    Set-Content -LiteralPath unit.cpp -Encoding ascii -Value @'
#include <cstdio>
import "unit.h";
int main() {
    std::printf("Header value: %d\n", unit_value());
    return unit_value() == 23 ? 0 : 1;
}
'@
    $producerArgs = @('/nologo', '/c', '/std:c++20', '/EHsc', '/MD', '/Z7',
        '/exportHeader', '/headerName:quote', 'unit.h', '/ifcOutput', 'unit.ifc', '/Founit.obj')
    $consumerArgs = @('/nologo', '/c', '/std:c++20', '/EHsc', '/MD', '/Z7',
        'unit.cpp', '/headerUnit:quote', 'unit.h=unit.ifc', '/Founit-consumer.obj')
    $artifacts = @('unit.ifc', 'unit.obj', 'unit-consumer.obj')
    $linkObjects = @('unit.obj', 'unit-consumer.obj')
    $expectedOutput = 'Header value: 23'
    Build-Phase 'header-unit-cold' $false
    foreach ($artifact in $artifacts) { Remove-Item -LiteralPath $artifact }
    Build-Phase 'header-unit-restored' $true
    Invoke-Checked $Sccache @('--stop-server')
    Start-Server
    foreach ($artifact in $artifacts) { Remove-Item -LiteralPath $artifact }
    Build-Phase 'header-unit-fresh-server' $true
    if ($Mapped) {
        if ($ExpectUncached) { throw 'Mapped mode requires the module-enabled executable.' }
        Invoke-Checked $Sccache @('--stop-server')
        $a = Join-Path $WorkDir 'mapped-producer'
        $b = Join-Path $WorkDir 'mapped receiver with a longer path'
        $null = New-Item -ItemType Directory -Path (Join-Path $a 'fmt')
        foreach ($name in @('src', 'include', 'LICENSE')) {
            Copy-Item -LiteralPath (Join-Path $WorkDir "fmt\$name") -Destination (Join-Path $a 'fmt') -Recurse
        }
        Copy-Item -LiteralPath consumer.cpp -Destination $a
        Set-Content -LiteralPath (Join-Path $a 'unit.h') -Encoding ascii -Value @'
#pragma once
#include <source_location>
inline int unit_count = 0;
inline int unit_initialized = [] { ++unit_count; return 23; }();
inline int unit_value() { return unit_initialized; }
inline const char* unit_file() { return __FILE__; }
inline const char* unit_location() { return std::source_location::current().file_name(); }
'@
        Set-Content -LiteralPath (Join-Path $a 'unit.cpp') -Encoding ascii -Value @'
#include <cstdio>
#include <cstring>
import "unit.h";
int main() {
    std::printf("Header value: %d\n", unit_value());
    return unit_value() == 23 && unit_count == 1
        && std::strcmp(unit_file(), R"(X:\logical-source\unit.h)") == 0
        && std::strcmp(unit_location(), R"(X:\logical-source\unit.h)") == 0 ? 0 : 1;
}
'@
        Copy-Item -LiteralPath $a -Destination $b -Recurse
        $env:SCCACHE_DIR = Join-Path $WorkDir 'mapped-cache'
        $env:SCCACHE_BASEDIRS = "$a;$b"
        $mappedCases = @(
            @{ Name = 'fmt'; Producer = $fmtProducerArgs; Consumer = $fmtConsumerArgs
                Files = @('fmt.ifc', 'fmt.obj', 'consumer.obj'); Objects = @('fmt.obj', 'consumer.obj')
                Output = 'The answer is 42' },
            @{ Name = 'header'; Producer = @('/nologo', '/c', '/std:c++20', '/EHsc', '/MD', '/Z7',
                    '/exportHeader', '/headerName:quote', 'unit.h', '/ifcOutput', 'unit.ifc', '/Founit.obj')
                Consumer = @('/nologo', '/c', '/std:c++20', '/EHsc', '/MD', '/Z7',
                    'unit.cpp', '/headerUnit:quote', 'unit.h=unit.ifc', '/Founit-consumer.obj')
                Files = @('unit.ifc', 'unit.obj', 'unit-consumer.obj'); Objects = @('unit.obj', 'unit-consumer.obj')
                Output = 'Header value: 23' }
        )
        Start-Server
        foreach ($root in @($a, $b)) {
            Push-Location $root
            try {
                foreach ($case in $mappedCases) {
                    $flags = @('/FC', '/experimental:deterministic', "/pathmap:$root\=X:\logical-source\")
                    $producerArgs = $case.Producer + $flags
                    $consumerArgs = $case.Consumer + $flags
                    $artifacts = $case.Files
                    $linkObjects = $case.Objects
                    $expectedOutput = $case.Output
                    Build-Phase "mapped-$($case.Name)-$([int]($root -eq $b))" ($root -eq $b)
                }
            } finally { Pop-Location }
            if ($root -eq $a) {
                Rename-Item -LiteralPath $a -NewName 'mapped-producer-offline'
                Invoke-Checked $Sccache @('--stop-server')
                Start-Server
            }
        }
        Push-Location $b
        try {
            foreach ($case in $mappedCases) {
                $flags = @('/FC', '/experimental:deterministic', "/pathmap:$b\=X:\logical-source\")
                $producerArgs = $case.Producer + $flags
                $consumerArgs = $case.Consumer + $flags + @('/DFRESH_MAPPED_CONSUMER=1')
                $artifacts = $case.Files
                $linkObjects = $case.Objects
                $expectedOutput = $case.Output
                Build-Phase "mapped-$($case.Name)-fresh-consumer" $false 1
            }
        } finally { Pop-Location }
    }
    [pscustomobject]@{
        Compiler = (Get-Item -LiteralPath $cl).VersionInfo.FileVersion
        FmtRevision = $revision; Baseline = [bool]$ExpectUncached; Mapped = [bool]$Mapped
        Results = $results
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath results.json -Encoding ascii
    $results | Select-Object Phase, Hits, Misses, Uncached, Milliseconds | Format-Table
} finally {
    & $Sccache --stop-server | Out-Null
    Pop-Location
    Get-ChildItem Env: | Where-Object Name -Like 'SCCACHE_*' | ForEach-Object {
        Remove-Item -LiteralPath "Env:$($_.Name)"
    }
    foreach ($name in $savedEnv.Keys) { Set-Item -LiteralPath "Env:$name" -Value $savedEnv[$name] }
}
