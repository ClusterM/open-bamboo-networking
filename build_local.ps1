param(
    [string]$Action = "configure"
)
$ErrorActionPreference = "Stop"

$vsCMake = "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin"
$vsNinja = "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja"
if ($env:PATH -notlike "*$vsCMake*") {
    $env:PATH = "$vsCMake;$vsNinja;$env:PATH"
}
$env:VCPKG_ROOT = "L:\vcpkg"
$buildDir = "L:\bambu_build"
$staging = "L:\bambu_install"

if ($Action -eq "configure") {
    if (-not (Test-Path $buildDir)) { New-Item -ItemType Directory -Path $buildDir | Out-Null }
    if (-not (Test-Path $staging))  { New-Item -ItemType Directory -Path $staging | Out-Null }
    .\configure.ps1 `
        -ClientType bambu_studio `
        -WithVersion "02.08.01.99" `
        -BuildDir $buildDir `
        -Prefix $staging `
        -Architecture x64 `
        -VcpkgRoot "L:\vcpkg" `
        -VcpkgTriplet "x64-windows-static-md" `
        -PatchConf:$false `
        -RegisterDShowFilter:$false `
        -EnableTests:$false
}
elseif ($Action -eq "build") {
    cmake --build $buildDir --config Release --parallel
}
elseif ($Action -eq "install") {
    cmake --install $buildDir --config Release
}
elseif ($Action -eq "deploy") {
    cmake --build $buildDir --config Release --parallel
    $srcDir = "$buildDir\Release"
    $bambuSrc = "$srcDir\BambuSource.dll"
    $bambuNet = "$srcDir\bambu_networking.dll"

    if (-not (Test-Path $bambuSrc) -or -not (Test-Path $bambuNet)) {
        throw "Built DLLs not found in $srcDir"
    }

    $targets = @(
        "D:\Documentos\Programming projects\orcaslicer-bbl-cloud-patches\orcaslicer-patched\resources\plugins",
        "D:\Documentos\Programming projects\orcaslicer-bbl-cloud-patches\oss\OrcaSlicer_Windows_V2.5.0-dev_x64_portable(2)\resources\plugins",
        "D:\Documentos\Programming projects\orcaslicer-bbl-cloud-patches\oss\OrcaSlicer_Windows_V2.5.0-dev_x64_portable(2)",
        (Join-Path $env:APPDATA "OrcaSlicer\plugins")
    )

    foreach ($t in $targets) {
        if (-not (Test-Path $t)) {
            New-Item -ItemType Directory -Path $t -Force | Out-Null
        }
        Copy-Item -Path $bambuSrc -Destination $t -Force
        Copy-Item -Path $bambuNet -Destination $t -Force
        Write-Host "Deployed to $t"
    }

    # Register BambuSource.dll from portable plugins directory
    $mainDll = "D:\Documentos\Programming projects\orcaslicer-bbl-cloud-patches\oss\OrcaSlicer_Windows_V2.5.0-dev_x64_portable(2)\resources\plugins\BambuSource.dll"
    $proc = Start-Process "regsvr32.exe" -ArgumentList "/s `"$mainDll`"" -PassThru -Wait
    Write-Host "regsvr32 exit code: $($proc.ExitCode)"
}

