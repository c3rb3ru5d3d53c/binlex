$ErrorActionPreference = "Stop"

$version = ""
try {
    $pkgid = cargo pkgid -p binlex 2>$null
} catch {
    $pkgid = ""
}

if ($pkgid) {
    $version = if ($pkgid -match '@') { $pkgid -replace '^.*@', '' } else { $pkgid -replace '^.*#', '' }
}

if (-not $version -or $version -eq $pkgid) {
    $match = Select-String -Path "Cargo.toml" -Pattern '^version = "(.+)"$' | Select-Object -First 1
    if ($match) {
        $version = $match.Matches[0].Groups[1].Value
    }
}

if (-not $version) {
    throw "failed to resolve BINLEX_VERSION"
}

Write-Output $version
