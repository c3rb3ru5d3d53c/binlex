#!/usr/bin/env bash
set -euo pipefail

pkgid="$(cargo pkgid -p binlex)"
version="${pkgid##*@}"
if [[ "${version}" == "${pkgid}" ]]; then
    version="${pkgid##*#}"
fi
printf '%s\n' "${version}"
