#!/usr/bin/env bash
set -euo pipefail

: "${AXVEN_SOURCE_SHA:?}"
: "${SOURCE_DATE_EPOCH:?}"
: "${MANYLINUX_IMAGE:?}"
: "${RUST_URL:?}"
: "${RUST_SHA256:?}"
: "${RUST_ARCHIVE_NAME:?}"
: "${RUST_ARCHIVE_ROOT:?}"
: "${TOOLCHAIN_NAME:?}"

test "$(git rev-parse HEAD)" = "$AXVEN_SOURCE_SHA"
test "$SOURCE_DATE_EPOCH" -ge 315532800

workspace="$PWD"
archive="/tmp/$RUST_ARCHIVE_NAME"
extract_root=/tmp/axven-rust025-extracted
install_parent=/tmp/axven-rust025-installed
toolchain="$install_parent/$TOOLCHAIN_NAME"
toolchain_manifest=/tmp/axven-rust025-toolchain.json
consumer=/tmp/axven-rust025-consumer
rebuild_source="$consumer/rebuild-source"
bundle=/tmp/axven-rust025-dependencies
vendor_dir=/tmp/axven-rust025-vendor
cargo_home=/tmp/axven-rust025-cargo-home
tools=/tmp/axven-rust025-tools
output="$consumer/rebuilt-wheel"

docker pull "$MANYLINUX_IMAGE"
resolved="$(docker image inspect "$MANYLINUX_IMAGE" --format '{{index .RepoDigests 0}}')"
test "$resolved" = "$MANYLINUX_IMAGE"

rm -f "$archive"
curl --proto "=https" --tlsv1.2 --fail --location --silent --show-error "$RUST_URL" --output "$archive"
test -s "$archive"
test ! -L "$archive"
test "$(sha256sum "$archive" | awk '{print $1}')" = "$RUST_SHA256"
python rust_024_upstream_rust_distribution.py verify-archive "$archive"

rm -rf "$extract_root" "$install_parent"
python rust_024_upstream_rust_distribution.py extract "$archive" "$extract_root"
dist_root="$extract_root/$RUST_ARCHIVE_ROOT"
test -f "$dist_root/install.sh"
test ! -L "$dist_root/install.sh"
mkdir -p "$install_parent"

docker run --rm --network none \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -v "$dist_root:/dist:ro" \
  -v "$install_parent:/install" \
  -w /dist \
  "$MANYLINUX_IMAGE" \
  /bin/bash -lc '
    set -euo pipefail
    test -f ./install.sh
    test ! -L ./install.sh
    ./install.sh --prefix=/install/1.98.0-x86_64-unknown-linux-gnu --disable-ldconfig
  '

test -d "$toolchain"
test ! -L "$toolchain"
test "$("$toolchain/bin/rustc" --version)" = "rustc 1.98.0 (88d9e12ae 2026-08-18)"
test "$("$toolchain/bin/cargo" --version)" = "cargo 1.98.0 (797e8a9bc 2026-08-05)"
test -d "$toolchain/lib/rustlib/x86_64-unknown-linux-gnu"

rm -f "$toolchain_manifest"
env -i HOME=/tmp PATH="$PATH" PYTHONUTF8=1 PYTHONIOENCODING=utf-8 PYTHONDONTWRITEBYTECODE=1 \
  python rust_023_rust_toolchain_closure.py collect "$toolchain" "$toolchain_manifest"
env -i HOME=/tmp PATH="$PATH" PYTHONUTF8=1 PYTHONIOENCODING=utf-8 PYTHONDONTWRITEBYTECODE=1 \
  python rust_023_rust_toolchain_closure.py verify "$toolchain" "$toolchain_manifest"

cargo metadata --locked --manifest-path native/axven_native/Cargo.toml --format-version 1 >/tmp/rust025-host-metadata.json
registry_src="$HOME/.cargo/registry/src"
test -d "$registry_src"
mapfile -t roots < <(find "$registry_src" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort)
test "${#roots[@]}" -eq 1
case "${roots[0]}" in
  index.crates.io-*) ;;
  *) exit 1 ;;
esac
registry_source_dir="${roots[0]}"

for candidate in a b; do
  target=".rust025-target-$candidate"
  candidate_tools=".rust025-tools-$candidate"
  wheelhouse="wheelhouse-repro-$candidate"
  rm -rf "$target" "$candidate_tools" "$wheelhouse"
  mkdir -p "$candidate_tools" "$wheelhouse"
  docker run --rm \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp \
    -e CARGO_HOME=/cargo \
    -e PYO3_PYTHON=/opt/python/cp313-cp313/bin/python \
    -e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    -e CARGO_INCREMENTAL=0 \
    -e PYTHONHASHSEED=0 \
    -e TZ=UTC \
    -e LC_ALL=C.UTF-8 \
    -e REGISTRY_SOURCE_DIR="$registry_source_dir" \
    -e RUSTFLAGS="--remap-path-prefix=/cargo/registry/src/$registry_source_dir=/axven/vendor" \
    -e CARGO_TARGET_DIR="/work/$target" \
    -e CANDIDATE_TOOLS="/work/$candidate_tools" \
    -e CANDIDATE_WHEELHOUSE="/work/$wheelhouse" \
    -e PATH=/rust-toolchain/bin:/opt/python/cp313-cp313/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    -v "$workspace:/work" \
    -v "$HOME/.cargo:/cargo" \
    -v "$toolchain:/rust-toolchain:ro" \
    -w /work \
    "$MANYLINUX_IMAGE" \
    /bin/bash -lc '
      set -euo pipefail
      test "$RUSTFLAGS" = "--remap-path-prefix=/cargo/registry/src/$REGISTRY_SOURCE_DIR=/axven/vendor"
      test "$(rustc --version)" = "rustc 1.98.0 (88d9e12ae 2026-08-18)"
      test "$(cargo --version)" = "cargo 1.98.0 (797e8a9bc 2026-08-05)"
      python -c "import platform; assert platform.python_version() == \"3.13.13\", platform.python_version()"
      python -m pip install --no-deps --only-binary=:all: --require-hashes --target "$CANDIDATE_TOOLS" -r /work/requirements-native-build.lock
      export PYTHONPATH="$CANDIDATE_TOOLS"
      export PATH="$CANDIDATE_TOOLS/bin:$PATH"
      test "$(maturin --version)" = "maturin 1.15.0"
      maturin build --release --locked --compatibility manylinux_2_28 \
        --manifest-path /work/native/axven_native/Cargo.toml \
        --interpreter /opt/python/cp313-cp313/bin/python \
        --out "$CANDIDATE_WHEELHOUSE"
      auditwheel show "$CANDIDATE_WHEELHOUSE"/*.whl
    '
  if [[ "$candidate" = a ]]; then sleep 2; fi
done

python rust_013_reproducible_wheel_spec.py wheelhouse-repro-a wheelhouse-repro-b "$SOURCE_DATE_EPOCH"
for candidate in a b; do
  rm -rf wheelhouse-portable
  mkdir wheelhouse-portable
  cp -- "wheelhouse-repro-$candidate"/*.whl wheelhouse-portable/
  python rust_009_portable_linux_wheel_spec.py
done

rm -f reproducible-provenance.json reproducible-attestation.json
python rust_014_reproducible_attestation.py generate reproducible-provenance.json
python rust_014_reproducible_attestation.py seal reproducible-provenance.json reproducible-attestation.json
python rust_014_reproducible_attestation.py verify reproducible-provenance.json reproducible-attestation.json
python rust_014_reproducible_attestation.py selftest reproducible-provenance.json reproducible-attestation.json
python rust_014_reproducible_attestation.py verify reproducible-provenance.json reproducible-attestation.json

rm -rf "$consumer"
mkdir -p \
  "$consumer/build-a" \
  "$consumer/build-b" \
  "$consumer/source-inputs" \
  "$consumer/git-objects/trees" \
  "$output" \
  "$rebuild_source/native/axven_native/src"
cp rust_015_offline_repro_consumer_verify.py "$consumer/"
cp rust_016_offline_build_input_verify.py "$consumer/"
cp rust_017_offline_git_tree_verify.py "$consumer/"
cp rust_018_detached_rebuild_verify.py "$consumer/"
cp wheelhouse-repro-a/*.whl "$consumer/build-a/"
cp wheelhouse-repro-b/*.whl "$consumer/build-b/"
cp reproducible-provenance.json "$consumer/"
cp reproducible-attestation.json "$consumer/"

inputs=(
  "native/axven_native/Cargo.toml"
  "native/axven_native/Cargo.lock"
  "native/axven_native/src/lib.rs"
  "requirements-native-build.lock"
  "requirements-ci-runtime-posix.lock"
  "rust_009_portable_linux_wheel_spec.py"
  "rust_013_reproducible_wheel_spec.py"
  "rust_013_reproducible_build_policy_spec.py"
  "rust_014_reproducible_attestation.py"
  "rust_014_reproducible_attestation_policy_spec.py"
  ".github/workflows/native-reproducible-build.yml"
)
for relative in "${inputs[@]}"; do
  mkdir -p "$consumer/source-inputs/$(dirname "$relative")"
  cp -- "$relative" "$consumer/source-inputs/$relative"
done

cp "$consumer/source-inputs/native/axven_native/Cargo.toml" "$rebuild_source/native/axven_native/Cargo.toml"
cp "$consumer/source-inputs/native/axven_native/Cargo.lock" "$rebuild_source/native/axven_native/Cargo.lock"
cp "$consumer/source-inputs/native/axven_native/src/lib.rs" "$rebuild_source/native/axven_native/src/lib.rs"
cp native/axven_native/pyproject.toml "$rebuild_source/native/axven_native/pyproject.toml"
cp native/axven_native/rust-toolchain.toml "$rebuild_source/native/axven_native/rust-toolchain.toml"

git cat-file commit "$AXVEN_SOURCE_SHA" >"$consumer/git-objects/commit.object"
test "$(git hash-object -t commit --stdin <"$consumer/git-objects/commit.object")" = "$AXVEN_SOURCE_SHA"
root_tree="$(git rev-parse "$AXVEN_SOURCE_SHA^{tree}")"
tree_paths=("" ".github" ".github/workflows" "native" "native/axven_native" "native/axven_native/src")
for tree_path in "${tree_paths[@]}"; do
  if [[ -z "$tree_path" ]]; then
    oid="$root_tree"
  else
    oid="$(git rev-parse "$AXVEN_SOURCE_SHA:$tree_path")"
  fi
  git cat-file tree "$oid" >"$consumer/git-objects/trees/$oid.tree"
  test "$(git hash-object -t tree --stdin <"$consumer/git-objects/trees/$oid.tree")" = "$oid"
done

test ! -e "$consumer/.git"
test ! -e "$rebuild_source/.git"
test "$(find "$consumer/source-inputs" -type f | wc -l)" -eq 11
test "$(find "$consumer/git-objects" -type f | wc -l)" -eq 7
test "$(find "$rebuild_source" -type f | wc -l)" -eq 5
test "$(find "$consumer" -type l | wc -l)" -eq 0

(
  cd "$consumer"
  wheel_a="$(find build-a -maxdepth 1 -type f -name '*.whl' -print)"
  wheel_b="$(find build-b -maxdepth 1 -type f -name '*.whl' -print)"
  env -i HOME=/tmp PATH="$PATH" PYTHONUTF8=1 PYTHONIOENCODING=utf-8 PYTHONDONTWRITEBYTECODE=1 \
    python rust_018_detached_rebuild_verify.py sourcecheck \
      "$wheel_a" "$wheel_b" reproducible-provenance.json reproducible-attestation.json \
      source-inputs git-objects rebuild-source
)

cargo fetch --locked --manifest-path "$rebuild_source/native/axven_native/Cargo.toml"
rm -rf "$bundle"
mkdir -p "$bundle/cargo-crates" "$bundle/python-wheels"
python rust_019_offline_dependency_closure.py collect-crates \
  "$rebuild_source/native/axven_native/Cargo.lock" "$HOME/.cargo" "$bundle/cargo-crates"
python -m pip download \
  --no-deps \
  --only-binary=:all: \
  --require-hashes \
  -r "$consumer/source-inputs/requirements-native-build.lock" \
  --dest "$bundle/python-wheels"
test "$(find "$bundle/python-wheels" -maxdepth 1 -type f -name '*.whl' | wc -l)" -eq 1
test "$(find "$bundle" -type l | wc -l)" -eq 0

env -i HOME=/tmp PATH="$PATH" PYTHONUTF8=1 PYTHONIOENCODING=utf-8 PYTHONDONTWRITEBYTECODE=1 \
  python rust_019_offline_dependency_closure.py verify \
    "$rebuild_source/native/axven_native/Cargo.lock" \
    "$consumer/source-inputs/requirements-native-build.lock" \
    "$bundle/cargo-crates" "$bundle/python-wheels"
env -i HOME=/tmp PATH="$PATH" PYTHONUTF8=1 PYTHONIOENCODING=utf-8 PYTHONDONTWRITEBYTECODE=1 \
  python rust_019_offline_dependency_closure.py selftest \
    "$rebuild_source/native/axven_native/Cargo.lock" \
    "$consumer/source-inputs/requirements-native-build.lock" \
    "$bundle/cargo-crates" "$bundle/python-wheels"

rm -rf "$vendor_dir"
env -i HOME=/tmp PATH="$PATH" PYTHONUTF8=1 PYTHONIOENCODING=utf-8 PYTHONDONTWRITEBYTECODE=1 \
  python rust_020_verified_vendor.py build \
    "$rebuild_source/native/axven_native/Cargo.lock" "$bundle/cargo-crates" "$vendor_dir"
env -i HOME=/tmp PATH="$PATH" PYTHONUTF8=1 PYTHONIOENCODING=utf-8 PYTHONDONTWRITEBYTECODE=1 \
  python rust_020_verified_vendor.py verify \
    "$rebuild_source/native/axven_native/Cargo.lock" "$vendor_dir"
env -i HOME=/tmp PATH="$PATH" PYTHONUTF8=1 PYTHONIOENCODING=utf-8 PYTHONDONTWRITEBYTECODE=1 \
  python rust_020_verified_vendor.py selftest \
    "$rebuild_source/native/axven_native/Cargo.lock" "$vendor_dir"
test "$(find "$vendor_dir" -type l | wc -l)" -eq 0

rm -rf "$cargo_home" "$tools" "$output"
mkdir -p "$cargo_home" "$tools" "$output"
python rust_020_verified_vendor.py write-config "$cargo_home"
test ! -e "$cargo_home/registry"
test ! -e "$cargo_home/git"

docker run --rm --network none \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -e CARGO_HOME=/cargo-home \
  -e PYO3_PYTHON=/opt/python/cp313-cp313/bin/python \
  -e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  -e CARGO_INCREMENTAL=0 \
  -e CARGO_NET_OFFLINE=true \
  -e PYTHONHASHSEED=0 \
  -e TZ=UTC \
  -e LC_ALL=C.UTF-8 \
  -e PIP_NO_CACHE_DIR=1 \
  -e RUSTFLAGS=--remap-path-prefix=/vendor=/axven/vendor \
  -e CARGO_TARGET_DIR=/tmp/axven-rust025-target \
  -e PATH=/rust-toolchain/bin:/opt/python/cp313-cp313/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  -v "$rebuild_source/native/axven_native:/work/native/axven_native:ro" \
  -v "$vendor_dir:/vendor:ro" \
  -v "$bundle/python-wheels:/python-wheels:ro" \
  -v "$cargo_home:/cargo-home" \
  -v "$tools:/tools" \
  -v "$output:/out" \
  -v "$toolchain:/rust-toolchain:ro" \
  -w /work/native/axven_native \
  "$MANYLINUX_IMAGE" \
  /bin/bash -lc '
    set -euo pipefail
    test ! -e /work/.git
    test ! -e /work/native/axven_native/.git
    test "$(find /work/native/axven_native -type f | wc -l)" -eq 5
    if env | grep -q "^GITHUB_"; then exit 1; fi
    test "$CARGO_NET_OFFLINE" = "true"
    test "$RUSTFLAGS" = "--remap-path-prefix=/vendor=/axven/vendor"
    test ! -e /cargo-home/registry
    test ! -e /cargo-home/git
    test "$(rustc --version)" = "rustc 1.98.0 (88d9e12ae 2026-08-18)"
    test "$(cargo --version)" = "cargo 1.98.0 (797e8a9bc 2026-08-05)"
    python -c "import platform; assert platform.python_version() == \"3.13.13\", platform.python_version()"
    python -m pip install --no-index --no-deps --no-cache-dir --target /tools /python-wheels/*.whl
    export PYTHONPATH=/tools
    export PATH=/tools/bin:$PATH
    test "$(maturin --version)" = "maturin 1.15.0"
    maturin build --release --locked --compatibility manylinux_2_28 \
      --manifest-path /work/native/axven_native/Cargo.toml \
      --interpreter /opt/python/cp313-cp313/bin/python \
      --out /out
    auditwheel show /out/*.whl
    test ! -e /cargo-home/registry/index
    test ! -e /cargo-home/registry/cache
    test ! -e /cargo-home/registry/src
    test ! -e /cargo-home/git
  '

test "$(find "$output" -maxdepth 1 -type f -name '*.whl' | wc -l)" -eq 1
test ! -e "$cargo_home/registry/index"
test ! -e "$cargo_home/registry/cache"
test ! -e "$cargo_home/registry/src"
test ! -e "$cargo_home/git"

(
  cd "$consumer"
  wheel_a="$(find build-a -maxdepth 1 -type f -name '*.whl' -print)"
  wheel_b="$(find build-b -maxdepth 1 -type f -name '*.whl' -print)"
  rebuilt="$(find rebuilt-wheel -maxdepth 1 -type f -name '*.whl' -print)"
  env -i HOME=/tmp PATH="$PATH" PYTHONUTF8=1 PYTHONIOENCODING=utf-8 PYTHONDONTWRITEBYTECODE=1 \
    python rust_018_detached_rebuild_verify.py verify \
      "$wheel_a" "$wheel_b" reproducible-provenance.json reproducible-attestation.json \
      source-inputs git-objects rebuild-source "$rebuilt"
  env -i HOME=/tmp PATH="$PATH" PYTHONUTF8=1 PYTHONIOENCODING=utf-8 PYTHONDONTWRITEBYTECODE=1 \
    python rust_018_detached_rebuild_verify.py selftest \
      "$wheel_a" "$wheel_b" reproducible-provenance.json reproducible-attestation.json \
      source-inputs git-objects rebuild-source "$rebuilt"
)

python rust_021_verified_dependency_rebuild_spec.py verify wheelhouse-repro-a "$output"
python rust_021_verified_dependency_rebuild_spec.py selftest wheelhouse-repro-a "$output"
python rust_013_reproducible_wheel_spec.py wheelhouse-repro-a "$output" "$SOURCE_DATE_EPOCH"
rm -rf wheelhouse-portable
mkdir wheelhouse-portable
cp -- "$output"/*.whl wheelhouse-portable/
python rust_009_portable_linux_wheel_spec.py

env -i HOME=/tmp PATH="$PATH" PYTHONUTF8=1 PYTHONIOENCODING=utf-8 PYTHONDONTWRITEBYTECODE=1 \
  python rust_019_offline_dependency_closure.py verify \
    "$rebuild_source/native/axven_native/Cargo.lock" \
    "$consumer/source-inputs/requirements-native-build.lock" \
    "$bundle/cargo-crates" "$bundle/python-wheels"
env -i HOME=/tmp PATH="$PATH" PYTHONUTF8=1 PYTHONIOENCODING=utf-8 PYTHONDONTWRITEBYTECODE=1 \
  python rust_020_verified_vendor.py verify \
    "$rebuild_source/native/axven_native/Cargo.lock" "$vendor_dir"
python rust_024_upstream_rust_distribution.py verify-archive "$archive"
env -i HOME=/tmp PATH="$PATH" PYTHONUTF8=1 PYTHONIOENCODING=utf-8 PYTHONDONTWRITEBYTECODE=1 \
  python rust_023_rust_toolchain_closure.py verify "$toolchain" "$toolchain_manifest"

echo "RUST-025 upstream-authenticated fully detached native rebuild: GREEN"
