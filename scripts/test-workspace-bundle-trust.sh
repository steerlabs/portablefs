#!/usr/bin/env bash
# Mutate task-owned copies; no registration, installation or identity lookup.
set -euo pipefail
app="$1"
mode="${2:---unsigned}"
[[ "$mode" == --unsigned || "$mode" == --signed ]] || exit 2
cli="$app/Contents/Helpers/portablefs"
"$cli" lifecycle verify-workspace-bundle --app "$app"
work="$(mktemp -d /tmp/portablefs-bundle-trust.XXXXXX)"
trap 'rm -rf "$work"' EXIT
for fault in image manifest service; do
  mkdir "$work/$fault"
  cp -cR "$app" "$work/$fault/PortableFS.app"
  altered="$work/$fault/PortableFS.app"
  case "$fault" in
    image) printf corrupt >"$altered/Contents/Resources/LinuxWorkspace/kernel" ;;
    manifest) printf ' ' >>"$altered/Contents/Resources/LinuxWorkspace/manifest.json" ;;
    service) /usr/libexec/PlistBuddy -c 'Set :CFBundleIdentifier org.example.substituted' "$altered/Contents/Library/LaunchAgents/PortableFSWorkspaceService.app/Contents/Info.plist" ;;
  esac
  if "$cli" lifecycle verify-workspace-bundle --app "$altered" >"$work/$fault.log" 2>&1; then
    echo "accepted substituted $fault" >&2; exit 1
  fi
  if [[ "$mode" == --signed ]]; then
    if "$cli" lifecycle verify-macos-bundle --app "$altered" >"$work/$fault-signed.log" 2>&1; then
      echo "signed publication accepted substituted $fault" >&2; exit 1
    fi
  fi
  echo "PASS: workspace bundle $fault substitution refused"
  rm -rf "$work/$fault"
done
