$distro = if ($env:STRIX_WSL_DISTRO) { $env:STRIX_WSL_DISTRO } else { "Ubuntu" }
$forwardedArgs = @($args)
$wslHome = (& wsl.exe -d $distro -- bash -lc 'printf %s "$HOME"').Trim()
if (-not $wslHome) {
    Write-Error "Could not resolve the home directory in WSL distribution '$distro'."
    exit 1
}

$entryPoint = "$wslHome/.local/bin/strix"
& wsl.exe -d $distro -- $entryPoint @forwardedArgs
exit $LASTEXITCODE
