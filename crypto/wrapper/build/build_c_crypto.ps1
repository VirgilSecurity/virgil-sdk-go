param(
    [string]$branch="master",
    [string]$sufix=""
)

function New-TemporaryDirectory {
    $parent = [System.IO.Path]::GetTempPath()
    [string] $name = [System.Guid]::NewGuid()
    Join-Path $parent $name
}

$scriptFolder=$PSScriptRoot
$os=$(go env GOOS)
$arch=$(go env GOARCH)
$tmpDir=New-TemporaryDirectory
$prebuildFolder="$($os)_$($arch)$($sufix)"

$result=$(git clone -b $branch https://github.com/VirgilSecurity/virgil-crypto-c.git $tmpDir | Out-Host;$?) -and
        $(New-Item -ItemType "directory" -Path (Join-Path $tmpDir build)) -and
        $(Push-Location (Join-Path $tmpDir build) -ev err | Out-Host;!$err) -and
        $(cmake.exe `
            -G "MinGW Makefiles" `
            -DVIRGIL_WRAP_GO=OFF `
            -DVIRGIL_LIB_PYTHIA=OFF `
            -DVIRGIL_SDK_PYTHIA=OFF `
            -DVIRGIL_LIB_RATCHET=OFF `
            -DVIRGIL_INSTALL_HDRS=ON `
            -DVIRGIL_INSTALL_LIBS=ON `
            -DVIRGIL_INSTALL_CMAKE=OFF `
            -DVIRGIL_INSTALL_DEPS_HDRS=ON `
            -DVIRGIL_INSTALL_DEPS_LIBS=ON `
            -DVIRGIL_INSTALL_DEPS_CMAKE=OFF `
            -DENABLE_TESTING=OFF `
            -DVIRGIL_C_TESTING=OFF `
            -DCMAKE_BUILD_TYPE=Release `
            -DVIRGIL_POST_QUANTUM=ON `
            -DED25519_REF10=ON `
            -DED25519_AMD64_RADIX_64_24K=OFF `
            -DCMAKE_INSTALL_PREFIX="..\wrappers\go\pkg\$($os)_$($arch)" .. | Out-Host;$?
        ) -and
        $(mingw32-make -j5  | Out-Host;$?) -and $(mingw32-make -j5 install  | Out-Host;$?) -and
        $(Push-Location (Join-Path $tmpDir \wrappers\go) -ev err | Out-Host;!$err) -and
        $(go test ./... | Out-Host;$?)

<#
Pop-Location
Pop-Location
#>

if ($result) 
{ 
    <# Remove-Item -Path (Join-Path $scriptFolder "..\pkg\$prebuildFolder\*") -Recurse -Force #>
    ForEach ($dir in ("include", "lib"))
    {
       New-Item -ItemType "directory" -Path (Join-Path $scriptFolder "..\pkg\$prebuildFolder\$dir")
       Copy-Item -Recurse -Path (Join-Path $tmpDir "wrappers\go\pkg\$($os)_$($arch)\$dir\*") -Destination (Join-Path $scriptFolder "..\pkg\$prebuildFolder\$dir")
    }
}

<#
Remove-Item -Recurse has unexpected behaviour.

See thread https://www.vistax64.com/threads/help-output-what-do-they-mean-by-this.25349

The Recurse parameter in this cmdlet does not work properly.
Because the Recurse parameter in this cmdlet is faulty,
the command uses the Get-Childitem cmdlet to get the desire d files,
and it uses the pipeline operator to pass them to the Remove-Item cmdlet.

Example:
Get-ChildItem $tmpDir -Recurse | Remove-Item -Force -Recurse; Remove-Item $tmpDir -Force -Recurse
#>

Get-ChildItem $tmpDir -Recurse | Remove-Item -Force -Recurse; Remove-Item $tmpDir -Force -Recurse

