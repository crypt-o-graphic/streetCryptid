#!/usr/bin/env bash
# Only EdDSA-signed universal apps reach the update feed, and nothing without an update key.
# MACOS_SIGNING=developer-id (the default) signs with Developer ID and notarizes. adhoc is the
# interim mode for before the project has a Developer ID: Sparkle accepts an update whose archive
# carries the app's EdDSA signature whatever its code signature, so updates stay authenticated, but
# Gatekeeper asks the user to approve the first launch by hand. It is never a silent fallback.
set -euo pipefail
root="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$root"
version="${1:?version}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 2
signing="${MACOS_SIGNING:-developer-id}"
case "$signing" in
  developer-id)
    : "${MACOS_SIGN_IDENTITY:?Developer ID Application identity required}"
    : "${MACOS_NOTARY_PROFILE:?notarytool keychain profile required}"
    ;;
  adhoc) ;;
  *) echo "MACOS_SIGNING must be developer-id or adhoc" >&2; exit 2 ;;
esac
: "${MACOS_SPARKLE_PUBLIC_KEY:?Sparkle public key required}"
: "${MACOS_SPARKLE_PRIVATE_KEY_FILE:?Sparkle private key file required}"
app="$root/repeater/macos/artifacts/universal/streetCryptid Repeater.app"
out="$root/repeater/macos/artifacts/release-$version"
mkdir -p "$out"

APP="$app" VERSION="$version" python3 - <<'PY'
import os, plistlib
with open(os.path.join(os.environ["APP"], "Contents/Info.plist"), "rb") as file:
    info = plistlib.load(file)
assert info["CFBundleVersion"] == os.environ["VERSION"], "Wrong app version"
assert info["SUPublicEDKey"] == os.environ["MACOS_SPARKLE_PUBLIC_KEY"], "Wrong update key"
PY
sparkle="$app/Contents/Frameworks/Sparkle.framework/Versions/B"
if [[ "$signing" == adhoc ]]; then
  sign() { codesign --force --sign - "$1"; }
else
  sign() { codesign --force --timestamp --options runtime --sign "$MACOS_SIGN_IDENTITY" "$1"; }
fi
# Sign from the leaves inward, never --deep for distribution.
sign "$sparkle/Autoupdate"
sign "$sparkle/Updater.app"
for service in "$sparkle"/XPCServices/*.xpc; do sign "$service"; done
sign "$app/Contents/Frameworks/Sparkle.framework"
sign "$app/Contents/Resources/streetcryptid-repeater-host"
sign "$app"
codesign --verify --deep --strict "$app"
for binary in "$app/Contents/MacOS/StreetCryptidRepeater" "$app/Contents/Resources/streetcryptid-repeater-host"; do
  lipo "$binary" -verify_arch arm64 x86_64
done
if [[ "$signing" == developer-id ]]; then
  ditto -c -k --keepParent "$app" "$out/notarization.zip"
  notary_args=(--keychain-profile "$MACOS_NOTARY_PROFILE")
  if [[ -n "${MACOS_SIGN_KEYCHAIN:-}" ]]; then
    notary_args+=(--keychain "$MACOS_SIGN_KEYCHAIN")
  fi
  xcrun notarytool submit "$out/notarization.zip" "${notary_args[@]}" --wait --timeout 30m
  xcrun stapler staple "$app"
  xcrun stapler validate "$app"
  spctl --assess --type execute "$app"
  rm "$out/notarization.zip"
fi

archive="streetcryptid-repeater-${version}-universal-macos.zip"
ditto -c -k --keepParent "$app" "$out/$archive"
tools="$root/repeater/macos/.build/artifacts/sparkle/Sparkle/bin"
"$tools/generate_appcast" --ed-key-file "$MACOS_SPARKLE_PRIVATE_KEY_FILE" \
  --download-url-prefix "https://github.com/unrealJune/streetCryptid/releases/download/macos-v${version}/" \
  "$out"
# Full corresponding source: includes every workspace manifest and all shared build inputs.
git archive --format=tar.gz --prefix="streetcryptid-repeater-$version-source/" \
  --output="$out/streetcryptid-repeater-$version-source.tar.gz" HEAD
(cd "$out" && shasum -a 256 "$archive" "streetcryptid-repeater-$version-source.tar.gz" > SHA256SUMS)
printf 'Release assets: %s\n' "$out"
