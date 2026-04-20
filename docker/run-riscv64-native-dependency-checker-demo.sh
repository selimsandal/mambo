#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
IMAGE_NAME=${IMAGE_NAME:-mambo-riscv64-native-demo}
ARTIFACT_DIR=${ARTIFACT_DIR:-"$REPO_ROOT/.demo-artifacts/riscv_dependency_checker"}
DEMO_SOURCE=${DEMO_SOURCE:-examples/riscv_dependency_checker_demo.c}

if [[ $(uname -m) != "riscv64" ]]; then
  echo "This workflow is intended for a native riscv64 host." >&2
  echo "Refusing to run on $(uname -m); use a real RISC-V machine instead of x86/ARM host-guest emulation." >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required but was not found in PATH." >&2
  exit 1
fi

mkdir -p "$ARTIFACT_DIR"

docker build -f "$SCRIPT_DIR/Dockerfile.riscv64-native" -t "$IMAGE_NAME" "$REPO_ROOT"

docker run --rm \
  -v "$REPO_ROOT:/workspace/mambo" \
  -v "$ARTIFACT_DIR:/artifacts" \
  -e DEMO_SOURCE="$DEMO_SOURCE" \
  -w /workspace/mambo \
  "$IMAGE_NAME" \
  bash -lc '
    set -euo pipefail
    echo "container uname -m: $(uname -m)"
    make dependency_checker
    case "$DEMO_SOURCE" in
      *.c)
        gcc -O2 -fno-inline -o /tmp/riscv_dependency_checker_demo \
          "/workspace/mambo/$DEMO_SOURCE"
        ;;
      *.S)
        gcc -O2 -o /tmp/riscv_dependency_checker_demo \
          "/workspace/mambo/$DEMO_SOURCE"
        ;;
      *)
        echo "Unsupported demo source: $DEMO_SOURCE" >&2
        exit 1
        ;;
    esac
    rm -f /artifacts/stats.txt /artifacts/chains.txt /artifacts/hotspots.txt
    cd /artifacts
    /workspace/mambo/mambo_dependency_checker /tmp/riscv_dependency_checker_demo
    printf "\nGenerated reports in /artifacts:\n"
    ls -1 /artifacts
    printf "\n== stats.txt ==\n"
    sed -n "1,120p" /artifacts/stats.txt
    printf "\n== chains.txt ==\n"
    sed -n "1,120p" /artifacts/chains.txt
    printf "\n== hotspots.txt ==\n"
    sed -n "1,160p" /artifacts/hotspots.txt
  '

printf "\nHost artifact directory: %s\n" "$ARTIFACT_DIR"
