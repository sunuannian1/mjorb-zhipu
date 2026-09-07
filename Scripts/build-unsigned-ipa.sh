#!/usr/bin/env bash
set -euo pipefail

configuration="${SEAL_IPA_CONFIGURATION:-Release}"
derived_data="$PWD/build/DerivedData"
product="$derived_data/Build/Products/${configuration}-iphoneos/Seal.app"
package_root="$PWD/build/package"
archive="$PWD/build/Seal.ipa"

if [[ "${SEAL_SKIP_XCODEGEN:-0}" != "1" ]]; then
  if ! command -v xcodegen >/dev/null 2>&1; then
    echo "error: xcodegen is required to regenerate Seal.xcodeproj from project.yml" >&2
    exit 1
  fi
  xcodegen generate
fi

rm -rf "$package_root" "$archive" "$archive.sha256"

xcodebuild clean build \
  -project Seal.xcodeproj \
  -scheme Seal \
  -configuration "$configuration" \
  -sdk iphoneos \
  -destination 'generic/platform=iOS' \
  -derivedDataPath "$derived_data" \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGN_IDENTITY='' \
  CURRENT_PROJECT_VERSION="${GITHUB_RUN_NUMBER:-${SEAL_BUILD_NUMBER:-1}}"

test -d "$product"
mkdir -p "$package_root/Payload"
ditto "$product" "$package_root/Payload/Seal.app"

# Copy Anisette ADI libraries into app bundle.
# Xcode treats .so as Mach-O binaries and skips them in resources;
# without these, local anisette generation falls back to remote servers
# (machineID drift -> Apple ID session invalidation).
anisette_src="$PWD/Seal/Resources/Anisette"
anisette_dst="$package_root/Payload/Seal.app/Anisette"
if [ -d "$anisette_src" ]; then
  mkdir -p "$anisette_dst"
  cp "$anisette_src"/libCoreADI.so "$anisette_dst/" 2>/dev/null || true
  cp "$anisette_src"/libstoreservicescore.so "$anisette_dst/" 2>/dev/null || true
  echo "Copied Anisette libraries:"
  ls -la "$anisette_dst/"
else
  echo "WARNING: $anisette_src not found, Anisette libraries will be missing" >&2
fi

(cd "$package_root" && /usr/bin/zip -qry "$archive" Payload)
shasum -a 256 "$archive" > "$archive.sha256"
