#!/bin/sh
# Install the UMC command-line client and daemon from the GitHub source tree.
set -eu

repository=${UMC_REPOSITORY:-https://github.com/vrlda/umc.git}
ref=${UMC_REF:-main}

if ! command -v git >/dev/null 2>&1; then
    echo "umc installer: git is required" >&2
    exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "umc installer: Rust and Cargo are required" >&2
    echo "install Rust from https://rustup.rs/ and run this command again" >&2
    exit 1
fi

temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/umc-install.XXXXXX")
cleanup() {
    rm -rf "$temporary_root"
}
trap cleanup EXIT INT TERM

echo "Downloading UMC (${ref})..."
git clone --depth 1 --branch "$ref" "$repository" "$temporary_root/source"

echo "Installing umc..."
cargo install --locked --path "$temporary_root/source/bins/umc" --bin umc

echo "Installing umcd..."
cargo install --locked --path "$temporary_root/source/bins/umcd" --bin umcd

cargo_bin=${CARGO_HOME:-"$HOME/.cargo"}/bin
echo "Installed umc and umcd to $cargo_bin"
case ":${PATH}:" in
    *":${cargo_bin}:"*) ;;
    *)
        echo "Add $cargo_bin to PATH if the commands are not found:"
        echo "  export PATH=\"$cargo_bin:\$PATH\""
        ;;
esac

