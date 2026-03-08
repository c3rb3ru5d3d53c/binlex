#!/usr/bin/env bash
set -euo pipefail

LIBVEX_REPO="https://github.com/pwnslinger/libvex-rs.git"
LIBVEX_BRANCH="feat/libvex-macos-sonoma-support"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DEPS_DIR="${PROJECT_DIR}/deps"
LIBVEX_DIR="${DEPS_DIR}/libvex-rs"
VALGRIND_VEX_DIR="${LIBVEX_DIR}/libvex-sys/valgrind/VEX"

print_env() {
    local vex_dir_win
    vex_dir_win="$(cygpath -w "${VALGRIND_VEX_DIR}")"
    if [ -n "${GITHUB_ENV:-}" ]; then
        echo "VEX_SRC=${vex_dir_win}"
        echo "VEX_LIBS=${vex_dir_win}"
    else
        echo "export VEX_SRC=\"${vex_dir_win}\""
        echo "export VEX_LIBS=\"${vex_dir_win}\""
    fi
}

check_prerequisites() {
    local missing=()
    for cmd in git make gcc ar cygpath; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [ ${#missing[@]} -ne 0 ]; then
        echo "ERROR: missing required tools: ${missing[*]}" >&2
        exit 1
    fi
}

clone_libvex() {
    if [ -d "${LIBVEX_DIR}" ]; then
        echo "[setup-vex-windows] libvex-rs already cloned at ${LIBVEX_DIR}"
        return
    fi
    echo "[setup-vex-windows] Cloning libvex-rs..."
    mkdir -p "${DEPS_DIR}"
    git clone --depth 1 --branch "${LIBVEX_BRANCH}" "${LIBVEX_REPO}" "${LIBVEX_DIR}"
}

build_vex() {
    local target_lib="${VALGRIND_VEX_DIR}/libvex-amd64-windows.a"
    if [ -f "${target_lib}" ]; then
        echo "[setup-vex-windows] VEX library already built at ${target_lib}"
        return
    fi

    echo "[setup-vex-windows] Building VEX static library..."
    cd "${VALGRIND_VEX_DIR}"
    make -f Makefile-gcc clean
    make -f Makefile-gcc -j"$(nproc 2>/dev/null || echo 2)" libvex.a
    cp libvex.a libvex-amd64-windows.a

    echo "[setup-vex-windows] VEX build complete"
    ls -la libvex*.a
}

usage() {
    echo "Usage: $0 [--env|--check|--clean]"
    echo ""
    echo "  (no args)  Clone/build libvex and print env exports"
    echo "  --env      Print env exports only"
    echo "  --check    Check if Windows VEX static library exists"
    echo "  --clean    Remove the deps/libvex-rs directory"
}

case "${1:-}" in
    --env)
        print_env
        ;;
    --check)
        if [ -f "${VALGRIND_VEX_DIR}/libvex-amd64-windows.a" ]; then
            echo "[setup-vex-windows] VEX is built and ready"
            exit 0
        else
            echo "[setup-vex-windows] VEX is not built" >&2
            exit 1
        fi
        ;;
    --clean)
        echo "[setup-vex-windows] Removing ${LIBVEX_DIR}..."
        rm -rf "${LIBVEX_DIR}"
        echo "[setup-vex-windows] Clean complete"
        ;;
    --help|-h)
        usage
        ;;
    *)
        check_prerequisites
        clone_libvex
        build_vex
        echo ""
        echo "[setup-vex-windows] Done. Set these environment variables:"
        echo ""
        print_env
        ;;
esac
