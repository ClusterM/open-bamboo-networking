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
