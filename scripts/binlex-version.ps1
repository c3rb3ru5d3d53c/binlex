$ErrorActionPreference = "Stop"

$pkgid = cargo pkgid -p binlex
$version = if ($pkgid -match '@') { $pkgid -replace '^.*@', '' } else { $pkgid -replace '^.*#', '' }
Write-Output $version
