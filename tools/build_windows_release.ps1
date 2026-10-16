param(
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$manifestPath = Join-Path $PSScriptRoot "release_firmwares.txt"
$distPath = Join-Path $repoRoot "dist"
$workPath = Join-Path $repoRoot "build\pyinstaller"

Push-Location $repoRoot
try {
    $firmwareNames = @(
        Get-Content -LiteralPath $manifestPath |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -and -not $_.StartsWith("#") }
    )
    if ($firmwareNames.Count -eq 0) {
        throw "The release firmware manifest is empty: $manifestPath"
    }
    if (($firmwareNames | Sort-Object -Unique).Count -ne $firmwareNames.Count) {
        throw "The release firmware manifest contains duplicate names."
    }

    $dataArgs = @()
    foreach ($name in $firmwareNames) {
        # PyInstaller resolves collected data relative to the generated .spec
        # file, which lives under build/.  Use an absolute source so --specpath
        # cannot silently redirect this to build/pyinstaller/firmwares.
        $source = Join-Path $repoRoot (Join-Path "firmwares" $name)
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "Release firmware does not exist: $source"
        }
        $dataArgs += "--add-data=$source;firmwares"
    }

    $arguments = @(
        "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--console",
        "--name", "BekenSimulator",
        "--paths", $repoRoot,
        "--distpath", $distPath,
        "--workpath", $workPath,
        "--specpath", $workPath,
        "--collect-all", "unicorn",
        "--hidden-import", "Crypto.Cipher.AES"
    )
    $arguments += $dataArgs
    $arguments += "tools\sim_ui.py"

    & $Python @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller failed with exit code $LASTEXITCODE"
    }

    $exePath = Join-Path $distPath "BekenSimulator.exe"
    if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) {
        throw "PyInstaller reported success but did not create $exePath"
    }
    Write-Host "Built $exePath"
}
finally {
    Pop-Location
}
