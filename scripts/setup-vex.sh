#!/usr/bin/env bash
set -euo pipefail

VALGRIND_REPO="https://github.com/LouisBrunner/valgrind-macos.git"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DEPS_DIR="${PROJECT_DIR}/deps"
VALGRIND_DIR="${DEPS_DIR}/valgrind-macos"
VEX_DIR="${VALGRIND_DIR}/VEX"

print_env() {
    if [ -n "${GITHUB_ENV:-}" ]; then
        echo "VEX_SRC=${VALGRIND_DIR}"
        echo "VEX_HEADERS=${VEX_DIR}:${VALGRIND_DIR}"
        echo "VEX_LIBS=${VEX_DIR}"
    else
        echo "export VEX_SRC=${VALGRIND_DIR}"
        echo "export VEX_HEADERS=${VEX_DIR}:${VALGRIND_DIR}"
        echo "export VEX_LIBS=${VEX_DIR}"
    fi
}

check_prerequisites() {
    local missing=()
    for cmd in git automake autoconf make; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [ ${#missing[@]} -ne 0 ]; then
        echo "ERROR: missing required tools: ${missing[*]}" >&2
        if [[ "$(uname)" == "Darwin" ]]; then
            echo "  Install with: brew install ${missing[*]}" >&2
        fi
        exit 1
    fi
}

clone_valgrind() {
    if [ -d "$VALGRIND_DIR" ]; then
        echo "[setup-vex] valgrind-macos already cloned at ${VALGRIND_DIR}"
        return
    fi
    echo "[setup-vex] Cloning valgrind-macos..."
    mkdir -p "$DEPS_DIR"
    git clone --depth 1 "$VALGRIND_REPO" "$VALGRIND_DIR"
}

build_vex() {
    if [ -f "${VEX_DIR}/libvex-"*"-darwin.a" ] 2>/dev/null || \
       [ -f "${VEX_DIR}/libvex-"*"-linux.a" ] 2>/dev/null; then
        echo "[setup-vex] VEX library already built"
        return
    fi

    echo "[setup-vex] Running autogen.sh..."
    cd "$VALGRIND_DIR"
    ./autogen.sh

    echo "[setup-vex] Running configure..."
    CONFIGURE_FLAGS=""
    if [[ "$(uname -m)" == "arm64" || "$(uname -m)" == "aarch64" ]]; then
        CONFIGURE_FLAGS="--enable-only64bit"
        export I_ACKNOWLEDGE_THIS_MIGHT_CRASH_OR_DAMAGE_MY_COMPUTER=yes
    fi
    ./configure $CONFIGURE_FLAGS

    echo "[setup-vex] Building VEX..."
    cd "$VEX_DIR"
    make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)"

    echo "[setup-vex] VEX build complete"
    ls -la "${VEX_DIR}"/libvex*.a
}

usage() {
    echo "Usage: $0 [--env|--check|--clean]"
    echo ""
    echo "  (no args)  Clone, build, and print env exports"
    echo "  --env      Print env exports only (assumes already built)"
    echo "  --check    Check if VEX is built, exit 0 if yes"
    echo "  --clean    Remove the deps/valgrind-macos directory"
}

case "${1:-}" in
    --env)
        print_env
        ;;
    --check)
        if ls "${VEX_DIR}"/libvex*.a &>/dev/null 2>&1; then
            echo "[setup-vex] VEX is built and ready"
            exit 0
        else
            echo "[setup-vex] VEX is not built" >&2
            exit 1
        fi
        ;;
    --clean)
        echo "[setup-vex] Removing ${VALGRIND_DIR}..."
        rm -rf "$VALGRIND_DIR"
        echo "[setup-vex] Clean complete"
        ;;
    --help|-h)
        usage
        ;;
    *)
        check_prerequisites
        clone_valgrind
        build_vex
        echo ""
        echo "[setup-vex] Done. Set these environment variables:"
        echo ""
        print_env
        ;;
esac
