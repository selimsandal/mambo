#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
SPEC_ROOT=${SPEC_ROOT:-"$HOME/Downloads/cpu2017"}
SOURCE_CONFIG_NAME=${SOURCE_CONFIG_NAME:-"Local-gcc-linux-riscv64-spacemit-k3.cfg"}
GENERATED_CONFIG_NAME=${GENERATED_CONFIG_NAME:-"Local-gcc-linux-riscv64-mambo-rv64gc.cfg"}
SPEC_LABEL=${SPEC_LABEL:-"mambo-rv64gc-gcc15"}
BENCHMARK=${BENCHMARK:-"505.mcf_r"}
MAMBO_TIMEOUT=${MAMBO_TIMEOUT:-600}
VERIFY_NATIVE=${VERIFY_NATIVE:-1}
ARTIFACT_DIR=${ARTIFACT_DIR:-"$REPO_ROOT/.demo-artifacts/spec2017_505_mcf_r"}
MAMBO_BINARY=${MAMBO_BINARY:-"$REPO_ROOT/mambo_dependency_checker"}

ensure_native_riscv64() {
  if [[ $(uname -m) != "riscv64" ]]; then
    echo "This workflow is intended for a native riscv64 host." >&2
    exit 1
  fi
}

ensure_prereqs() {
  local cmd

  for cmd in make timeout cmp sed; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "$cmd is required but was not found in PATH." >&2
      exit 1
    fi
  done

  if [[ ! -d "$SPEC_ROOT" ]]; then
    echo "SPEC_ROOT does not exist: $SPEC_ROOT" >&2
    exit 1
  fi
  if [[ ! -f "$SPEC_ROOT/shrc" ]]; then
    echo "SPEC shrc was not found under $SPEC_ROOT" >&2
    exit 1
  fi
  if [[ ! -f "$SPEC_ROOT/config/$SOURCE_CONFIG_NAME" ]]; then
    echo "Source SPEC config was not found: $SPEC_ROOT/config/$SOURCE_CONFIG_NAME" >&2
    exit 1
  fi
}

write_generated_config() {
  local source_config=$SPEC_ROOT/config/$SOURCE_CONFIG_NAME
  local target_config=$SPEC_ROOT/config/$GENERATED_CONFIG_NAME
  local tmp_config

  tmp_config=$(mktemp)
  sed \
    -e 's/^%   define label .*/%   define label "'"$SPEC_LABEL"'"/' \
    -e 's|^   RISCV_TARGET .*|   RISCV_TARGET           = -march=rv64gc -mabi=lp64d|' \
    "$source_config" > "$tmp_config"

  mv "$tmp_config" "$target_config"
}

build_dependency_checker() {
  (
    cd "$REPO_ROOT"
    make dependency_checker
  )
}

prepare_spec_tree() {
  (
    cd "$SPEC_ROOT"
    # shellcheck disable=SC1091
    source shrc
    runcpu --config="$GENERATED_CONFIG_NAME" \
      --tune=base \
      --size=test \
      --action=build \
      --noreportable \
      "$BENCHMARK"
    runcpu --config="$GENERATED_CONFIG_NAME" \
      --define rate_copies=1 \
      --tune=base \
      --size=test \
      --action=setup \
      --noreportable \
      "$BENCHMARK"
  )
}

locate_run_dir() {
  find "$SPEC_ROOT/benchspec/CPU/$BENCHMARK/run" \
    -maxdepth 1 \
    -type d \
    -name "run_base_test_${SPEC_LABEL}.*" \
    -printf '%T@ %p\n' | sort -n | tail -n 1 | cut -d' ' -f2-
}

run_with_loader() {
  local loader_dir=$1
  local run_dir=$2
  local exe_name=$3
  local output_tag=$4

  rm -f \
    "$run_dir/inp.out.$output_tag" \
    "$run_dir/inp.err.$output_tag" \
    "$run_dir/mcf.out.$output_tag" \
    "$run_dir/mcf.out"

  (
    cd "$run_dir"
    "$loader_dir/lib/ld-linux-riscv64-lp64d.so.1" \
      --library-path "$loader_dir/lib/riscv64-linux-gnu" \
      "./$exe_name" inp.in \
      > "inp.out.$output_tag" \
      2> "inp.err.$output_tag"
    mv mcf.out "mcf.out.$output_tag"
  )
}

run_with_mambo() {
  local loader_dir=$1
  local run_dir=$2
  local exe_name=$3

  rm -f \
    "$run_dir/stats.txt" \
    "$run_dir/chains.txt" \
    "$run_dir/hotspots.txt" \
    "$run_dir/inp.out.mambo" \
    "$run_dir/inp.err.mambo" \
    "$run_dir/mcf.out"

  (
    cd "$run_dir"
    timeout "${MAMBO_TIMEOUT}s" \
      "$MAMBO_BINARY" \
      "$loader_dir/lib/ld-linux-riscv64-lp64d.so.1" \
      --library-path "$loader_dir/lib/riscv64-linux-gnu" \
      "./$exe_name" inp.in \
      > inp.out.mambo \
      2> inp.err.mambo
  )

  if [[ ! -f "$run_dir/mcf.out" ]]; then
    echo "MAMBO run completed without producing mcf.out" >&2
    exit 1
  fi

  mv "$run_dir/mcf.out" "$run_dir/mcf.out.mambo"
}

verify_output_pair() {
  local run_dir=$1
  local output_tag=$2
  local expected_base=$SPEC_ROOT/benchspec/CPU/$BENCHMARK/data/test/output

  cmp -s "$run_dir/inp.out.$output_tag" "$expected_base/inp.out"
  cmp -s "$run_dir/mcf.out.$output_tag" "$expected_base/mcf.out"
}

copy_artifacts() {
  local run_dir=$1

  mkdir -p "$ARTIFACT_DIR"
  cp -f \
    "$run_dir/inp.out.mambo" \
    "$run_dir/inp.err.mambo" \
    "$run_dir/mcf.out.mambo" \
    "$run_dir/stats.txt" \
    "$run_dir/chains.txt" \
    "$run_dir/hotspots.txt" \
    "$ARTIFACT_DIR/"

  if [[ "$VERIFY_NATIVE" != "0" ]]; then
    cp -f \
      "$run_dir/inp.out.native" \
      "$run_dir/inp.err.native" \
      "$run_dir/mcf.out.native" \
      "$ARTIFACT_DIR/"
  fi
}

print_summary() {
  local run_dir=$1

  printf '\nRun directory: %s\n' "$run_dir"
  printf 'Artifact directory: %s\n' "$ARTIFACT_DIR"
  printf '\n== stats.txt ==\n'
  sed -n '1,120p' "$run_dir/stats.txt"
  printf '\n== chains.txt ==\n'
  sed -n '1,120p' "$run_dir/chains.txt"
  printf '\n== hotspots.txt ==\n'
  sed -n '1,160p' "$run_dir/hotspots.txt"
}

main() {
  local jammy_libc_dir
  local run_dir
  local exe_name

  ensure_native_riscv64
  ensure_prereqs
  mkdir -p "$ARTIFACT_DIR"

  jammy_libc_dir=$("$SCRIPT_DIR/prepare-jammy-libc-riscv64.sh")
  write_generated_config
  build_dependency_checker
  prepare_spec_tree

  run_dir=$(locate_run_dir)
  if [[ -z "$run_dir" ]]; then
    echo "Failed to locate the prepared SPEC run directory." >&2
    exit 1
  fi

  exe_name="mcf_r_base.${SPEC_LABEL}"
  if [[ ! -x "$run_dir/$exe_name" ]]; then
    echo "Prepared benchmark binary was not found: $run_dir/$exe_name" >&2
    exit 1
  fi

  if [[ "$VERIFY_NATIVE" != "0" ]]; then
    run_with_loader "$jammy_libc_dir" "$run_dir" "$exe_name" native
    verify_output_pair "$run_dir" native
  fi

  run_with_mambo "$jammy_libc_dir" "$run_dir" "$exe_name"
  verify_output_pair "$run_dir" mambo
  copy_artifacts "$run_dir"
  print_summary "$run_dir"
}

main "$@"
