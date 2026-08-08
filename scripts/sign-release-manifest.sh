#!/usr/bin/env bash
set -eu

usage() {
    echo "usage: $0 MANIFEST PRIVATE_KEY OUTPUT_SIGNATURE" >&2
    exit 2
}

[ "$#" -eq 3 ] || usage
manifest=$1
private_key=$2
signature=$3

command -v openssl >/dev/null 2>&1 || {
    echo "openssl is required" >&2
    exit 1
}
[ -f "$manifest" ] || { echo "manifest not found: $manifest" >&2; exit 1; }
[ -f "$private_key" ] || { echo "private key not found: $private_key" >&2; exit 1; }

# Ed25519 signs the exact manifest bytes; -rawin prevents OpenSSL from
# applying a digest that is not part of the release-manifest contract.
openssl pkeyutl -sign -rawin -inkey "$private_key" -in "$manifest" -out "$signature"
