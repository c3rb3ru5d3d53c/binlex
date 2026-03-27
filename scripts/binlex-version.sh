#!/usr/bin/env bash
set -euo pipefail

version=""
pkgid="$(cargo pkgid -p binlex 2>/dev/null || true)"
if [[ -n "${pkgid}" ]]; then
    version="${pkgid##*@}"
    if [[ "${version}" == "${pkgid}" ]]; then
        version="${pkgid##*#}"
    fi
fi

if [[ -z "${version}" || "${version}" == "${pkgid}" ]]; then
    version="$(
        sed -nE 's/^version = "(.*)"/\1/p' Cargo.toml | head -n1
    )"
fi

if [[ -z "${version}" ]]; then
    printf 'failed to resolve BINLEX_VERSION\n' >&2
    exit 1
fi

printf '%s\n' "${version}"
