#!/usr/bin/env bash
set -eu

usage() {
    echo "usage: $0 MANIFEST PUBLIC_KEY SIGNATURE" >&2
    exit 2
}

[ "$#" -eq 3 ] || usage
manifest=$1
public_key=$2
signature=$3

command -v openssl >/dev/null 2>&1 || {
    echo "openssl is required" >&2
    exit 1
}
[ -f "$manifest" ] || { echo "manifest not found: $manifest" >&2; exit 1; }
[ -f "$public_key" ] || { echo "public key not found: $public_key" >&2; exit 1; }
[ -f "$signature" ] || { echo "signature not found: $signature" >&2; exit 1; }

# The command exits non-zero for a bad signature; callers should treat that
# as a release verification failure.
openssl pkeyutl -verify -rawin -pubin -inkey "$public_key" -in "$manifest" -sigfile "$signature"
