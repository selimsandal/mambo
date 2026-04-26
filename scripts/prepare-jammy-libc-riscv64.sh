#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
ARTIFACT_ROOT=${ARTIFACT_ROOT:-"$REPO_ROOT/.demo-artifacts"}
TARGET_DIR=${TARGET_DIR:-"$ARTIFACT_ROOT/jammy-libc-riscv64"}
CACHE_DIR=${CACHE_DIR:-"$ARTIFACT_ROOT/package-cache/jammy-riscv64"}
BASE_URL=${BASE_URL:-"http://ports.ubuntu.com/ubuntu-ports"}

fetch_to_file() {
  local url=$1
  local output=$2

  if command -v wget >/dev/null 2>&1; then
    wget -q -O "$output" "$url"
  elif command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$output" "$url"
  else
    echo "Either wget or curl is required." >&2
    exit 1
  fi
}

resolve_libc_filename() {
  local suite
  local index
  local filename

  for suite in jammy-updates jammy-security jammy; do
    index=$(mktemp)
    fetch_to_file \
      "$BASE_URL/dists/$suite/main/binary-riscv64/Packages.gz" \
      "$index"

    filename=$(
      gzip -dc "$index" | awk '
        $1 == "Package:" {
          in_pkg = ($2 == "libc6")
        }
        in_pkg && $1 == "Filename:" {
          print $2
          exit
        }
      '
    )
    rm -f "$index"

    if [[ -n "$filename" ]]; then
      printf '%s\n' "$filename"
      return 0
    fi
  done

  return 1
}

if [[ $(uname -m) != "riscv64" ]]; then
  echo "This helper is intended for a native riscv64 host." >&2
  exit 1
fi

for cmd in dpkg-deb gzip awk mktemp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "$cmd is required but was not found in PATH." >&2
    exit 1
  fi
done

if [[ -x "$TARGET_DIR/lib/ld-linux-riscv64-lp64d.so.1" ]] &&
   [[ -f "$TARGET_DIR/lib/riscv64-linux-gnu/libc.so.6" ]]; then
  printf '%s\n' "$TARGET_DIR"
  exit 0
fi

mkdir -p "$CACHE_DIR"

filename=$(resolve_libc_filename)
if [[ -z "$filename" ]]; then
  echo "Failed to locate libc6 in Ubuntu jammy package indexes." >&2
  exit 1
fi

deb_path="$CACHE_DIR/${filename##*/}"
if [[ ! -f "$deb_path" ]]; then
  echo "Downloading $filename" >&2
  fetch_to_file "$BASE_URL/$filename" "$deb_path"
fi

rm -rf "$TARGET_DIR"
mkdir -p "$TARGET_DIR"
dpkg-deb -x "$deb_path" "$TARGET_DIR"

if [[ ! -x "$TARGET_DIR/lib/ld-linux-riscv64-lp64d.so.1" ]]; then
  echo "Extracted jammy loader is missing." >&2
  exit 1
fi
if [[ ! -f "$TARGET_DIR/lib/riscv64-linux-gnu/libc.so.6" ]]; then
  echo "Extracted jammy libc is missing." >&2
  exit 1
fi

printf '%s\n' "$TARGET_DIR"
