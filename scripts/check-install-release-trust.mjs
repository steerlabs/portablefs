#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const installer = await readFile(path.join(root, "scripts/install.sh"), "utf8");
const packager = await readFile(
  path.join(root, "scripts/package-macos-app.sh"),
  "utf8"
);
const helperEmbedder = await readFile(
  path.join(root, "swift/PortableFSApp/Scripts/embed-portablefs-tools.sh"),
  "utf8"
);
const helperEntitlements = await readFile(
  path.join(root, "swift/PortableFSApp/Config/PortableFSHelpers.entitlements"),
  "utf8"
);
const appGroupBuildInputs = await Promise.all(
  [
    "swift/PortableFSApp/App/Info.plist",
    "swift/PortableFSApp/App/PortableFSApp.entitlements",
    "swift/PortableFSApp/PortableFSExt/Info.plist",
    "swift/PortableFSApp/PortableFSExt/PortableFSExt.entitlements",
    "swift/PortableFSKitDev/PortableFSKitDev/Info.plist",
    "swift/PortableFSKitDev/PortableFSKitDev/PortableFSKitDev.entitlements",
    "swift/PortableFSKitDev/PortableFSDev/Info.plist",
    "swift/PortableFSKitDev/PortableFSDev/PortableFSDev.entitlements",
    "swift/PortableFSKitMacOS27Dev/PortableFSKitMacOS27Dev/Info.plist",
    "swift/PortableFSKitMacOS27Dev/PortableFSKitMacOS27Dev/PortableFSKitMacOS27Dev.entitlements",
    "swift/PortableFSKitMacOS27Dev/PortableFSDev/Info.plist",
    "swift/PortableFSKitMacOS27Dev/PortableFSDev/PortableFSDev.entitlements",
  ].map(async (relativePath) => ({
    relativePath,
    contents: await readFile(path.join(root, relativePath), "utf8"),
  }))
);
const appGroupBuildConfigs = await Promise.all(
  [
    "swift/PortableFSApp/Config/Development.xcconfig",
    "swift/PortableFSKitDev/Config/Development.xcconfig",
    "swift/PortableFSKitMacOS27Dev/Config/Development.xcconfig",
  ].map(async (relativePath) => ({
    relativePath,
    contents: await readFile(path.join(root, relativePath), "utf8"),
  }))
);
const developmentProjects = await Promise.all(
  [
    "swift/PortableFSKitDev/PortableFSKitDev.xcodeproj/project.pbxproj",
    "swift/PortableFSKitMacOS27Dev/PortableFSKitMacOS27Dev.xcodeproj/project.pbxproj",
  ].map(async (relativePath) => ({
    relativePath,
    contents: await readFile(path.join(root, relativePath), "utf8"),
  }))
);
const qualificationPhaseProjects = await Promise.all(
  [
    {
      relativePath: "swift/PortableFSApp/PortableFSApp.xcodeproj/project.pbxproj",
      phaseValue: "PORTABLEFS_NATIVE_QUALIFICATION= ",
    },
    {
      relativePath: "swift/PortableFSKitDev/PortableFSKitDev.xcodeproj/project.pbxproj",
      phaseValue: "PORTABLEFS_NATIVE_QUALIFICATION= ",
    },
    {
      relativePath: "swift/PortableFSKitMacOS27Dev/PortableFSKitMacOS27Dev.xcodeproj/project.pbxproj",
      phaseValue: "PORTABLEFS_NATIVE_QUALIFICATION=sdk27-live-qualification-only ",
    },
  ].map(async ({ relativePath, phaseValue }) => ({
    relativePath,
    phaseValue,
    contents: await readFile(path.join(root, relativePath), "utf8"),
  }))
);
const cliFSKit = await readFile(
  path.join(root, "vcs/cmd/portablefs/internal/cli/fskitmount.go"),
  "utf8"
);
const cliMacOSInstaller = await readFile(
  path.join(root, "vcs/cmd/portablefs/internal/cli/installmacos_darwin.go"),
  "utf8"
);
const cliCommands = await readFile(
  path.join(root, "vcs/cmd/portablefs/internal/cli/cli.go"),
  "utf8"
);
const macOS27QualificationCommand = await readFile(
  path.join(
    root,
    "vcs/cmd/portablefs/internal/cli/installmacos_qualification_darwin.go"
  ),
  "utf8"
);
const macOS27QualificationLayout = await readFile(
  path.join(
    root,
    "vcs/cmd/portablefs/internal/cli/installmacos_qualification_layout_darwin.go"
  ),
  "utf8"
);
const disabledQualificationLayout = await readFile(
  path.join(
    root,
    "vcs/cmd/portablefs/internal/cli/installmacos_qualification_layout_disabled.go"
  ),
  "utf8"
);
const darwinNativeBridge = await readFile(
  path.join(root, "vcs/internal/darwinnative/bridge_darwin.m"),
  "utf8"
);
const appHostLauncher = await readFile(
  path.join(root, "vcs/internal/apphost/launch_darwin.go"),
  "utf8"
);
const hostControlProtocol = await readFile(
  path.join(root, "vcs/internal/hostctl/protocol.go"),
  "utf8"
);
const hostControlClient = await readFile(
  path.join(root, "vcs/internal/hostctl/client_darwin.go"),
  "utf8"
);
const hostProcessWitness = await readFile(
  path.join(root, "vcs/internal/hostctl/process_witness_darwin.go"),
  "utf8"
);
const hostProcessWitnessNative = await readFile(
  path.join(root, "vcs/internal/hostctl/process_witness_darwin.c"),
  "utf8"
);
const serviceUpdateServer = await readFile(
  path.join(
    root,
    "swift/PortableFSKit/Sources/PortableFSAppCore/ServiceUpdateServer.swift"
  ),
  "utf8"
);
const appGroupResolver = await readFile(
  path.join(root, "vcs/internal/appgroupcontainer/container_darwin.go"),
  "utf8"
);
const daemonControl = await readFile(
  path.join(root, "vcs/internal/portablefsd/control.go"),
  "utf8"
);
const workflow = await readFile(path.join(root, ".github/workflows/release.yml"), "utf8");
const ciWorkflow = await readFile(path.join(root, ".github/workflows/ci.yml"), "utf8");
const xcodeSwiftGate = await readFile(path.join(root, "scripts/test-swift-xcode.sh"), "utf8");
const xcodeEvidenceVerifier = await readFile(
  path.join(root, "scripts/verify_xcode_tests.py"),
  "utf8"
);
const xcodeEvidenceTests = await readFile(
  path.join(root, "scripts/test_verify_xcode_tests.py"),
  "utf8"
);
const goreleaser = await readFile(path.join(root, ".goreleaser.yaml"), "utf8");
const qualificationSource = await readFile(
  path.join(
    root,
    "swift/PortableFSKitMacOS27Dev/IOQualification/QualificationApp.swift"
  ),
  "utf8"
);
const qualificationInfo = await readFile(
  path.join(root, "swift/PortableFSKitMacOS27Dev/IOQualification/Info.plist"),
  "utf8"
);
const qualificationProject = await readFile(
  path.join(
    root,
    "swift/PortableFSKitMacOS27Dev/PortableFSKitMacOS27Dev.xcodeproj/project.pbxproj"
  ),
  "utf8"
);
const qualificationScheme = await readFile(
  path.join(
    root,
    "swift/PortableFSKitMacOS27Dev/PortableFSKitMacOS27Dev.xcodeproj/xcshareddata/xcschemes/PortableFSKitMacOS27IOQualification.xcscheme"
  ),
  "utf8"
);
const macOS27HostScheme = await readFile(
  path.join(
    root,
    "swift/PortableFSKitMacOS27Dev/PortableFSKitMacOS27Dev.xcodeproj/xcshareddata/xcschemes/PortableFSKitMacOS27Dev.xcscheme"
  ),
  "utf8"
);
const productionProject = await readFile(
  path.join(root, "swift/PortableFSApp/PortableFSApp.xcodeproj/project.pbxproj"),
  "utf8"
);
const macOS26DevelopmentProject = await readFile(
  path.join(root, "swift/PortableFSKitDev/PortableFSKitDev.xcodeproj/project.pbxproj"),
  "utf8"
);
const macOS26DevelopmentHost = await readFile(
  path.join(root, "swift/PortableFSKitDev/PortableFSKitDev/HostApp.swift"),
  "utf8"
);
const macOS27DevelopmentHost = await readFile(
  path.join(
    root,
    "swift/PortableFSKitMacOS27Dev/PortableFSKitMacOS27Dev/HostApp.swift"
  ),
  "utf8"
);

const failures = [];
const requireText = (source, text, label) => {
  if (!source.includes(text)) failures.push(`missing ${label}`);
};

const qualificationName = "PortableFSKitMacOS27IOQualification";
const qualificationBundleID = "dev.portablefs.oss.KitDev.IOQualification";
for (const contract of [
  "NSNetworkVolumesUsageDescription",
  "qualification-only app to verify data I/O",
]) {
  requireText(qualificationInfo, contract, `qualification Info.plist ${contract}`);
}
for (const contract of [
  "case basic",
  'case dataRefresh = "data-refresh"',
  "namespace and attribute cross-client qualification is intentionally unsupported",
  'expectedFileSystemType = "pfs"',
  'expectedSourcePrefix = "dev.portablefs.oss://"',
  "same open file descriptor did not observe the expected refreshed data",
  "kernel mount identity changed during qualification",
]) {
  requireText(qualificationSource, contract, `qualification boundary ${contract}`);
}
for (const forbidden of [
  "com.apple.security.application-groups",
  "CODE_SIGN_ENTITLEMENTS",
  "portablefsd",
  "bind-root",
  "namespace-refresh",
  "attribute-refresh",
]) {
  if (qualificationSource.includes(forbidden) || qualificationInfo.includes(forbidden)) {
    failures.push(`qualification app gained forbidden product surface ${forbidden}`);
  }
}
for (const contract of [
  "updateSession.HostProcessWitness()",
  "hostWitness.RequireCurrentExecutable(expectedHostExecutable)",
  "const darwinProcessNameLimit = len(unix.ExternProc{}.P_comm) - 1",
  "p_comm is only a conservative rejection filter",
]) {
  requireText(cliMacOSInstaller, contract, `prepared host process witness ${contract}`);
}
for (const contract of [
  "type ProcessWitness struct",
  "PIDVersion",
  "RequireCurrentExecutable",
  "captureSocketPeerProcessWitness",
]) {
  requireText(hostProcessWitness, contract, `Darwin audit-token witness ${contract}`);
}
for (const contract of [
  "LOCAL_PEERTOKEN",
  "audit_token_to_pidversion",
  "audit_token_to_euid",
  "proc_pidpath_audittoken",
]) {
  requireText(hostProcessWitnessNative, contract, `native process witness ${contract}`);
}
for (const contract of [
  `name = ${qualificationName};`,
  `productName = ${qualificationName};`,
  `PRODUCT_BUNDLE_IDENTIFIER = ${qualificationBundleID};`,
  "IOQualification/Info.plist",
]) {
  requireText(qualificationProject, contract, `isolated qualification target ${contract}`);
}
const qualificationSkips = qualificationProject.match(/SKIP_INSTALL = YES;/g) ?? [];
if (qualificationSkips.length !== 4) {
  failures.push("macOS 27 project must mark the extension and qualification app non-installable in both configurations");
}
for (const configID of [
  "100000000000000000000771",
  "100000000000000000000772",
]) {
  const start = qualificationProject.indexOf(`\t\t${configID} /*`);
  const end = qualificationProject.indexOf("\n\t\t};", start);
  const config = start >= 0 && end > start
    ? qualificationProject.slice(start, end)
    : "";
  if (!config || config.includes("CODE_SIGN_ENTITLEMENTS") || config.includes("MARKETING_VERSION")) {
    failures.push(`qualification configuration ${configID} gained entitlements or the shipping release version`);
  }
}
for (const contract of [
  `BlueprintName = "${qualificationName}"`,
  'buildImplicitDependencies = "NO"',
  'buildForArchiving = "NO"',
  'buildForTesting = "NO"',
  'buildForProfiling = "NO"',
]) {
  requireText(qualificationScheme, contract, `qualification-only scheme ${contract}`);
}
if (macOS27HostScheme.includes(qualificationName)) {
  failures.push("macOS 27 development host scheme embeds or builds the qualification app");
}
for (const [label, contents] of [
  ["installer", installer],
  ["packager", packager],
  ["release workflow", workflow],
  ["CI workflow", ciWorkflow],
  ["GoReleaser", goreleaser],
  ["shipping Xcode project", productionProject],
  ["macOS 26 development project", macOS26DevelopmentProject],
]) {
  if (contents.includes(qualificationName) || contents.includes(qualificationBundleID)) {
    failures.push(`${label} references the qualification-only application`);
  }
}

requireText(installer, "gh_version=2.93.0", "pinned GitHub CLI version");
requireText(
  packager,
  "PORTABLEFS_RELEASE=1 requires an explicit exact PORTABLEFS_GO",
  "release build exact Go requirement"
);
requireText(
  workflow,
  'export PORTABLEFS_GO="$(realpath "$(command -v go)")"',
  "release workflow exact Go compiler input"
);
requireText(
  installer,
  "amd64) gh_sha256=02d1290eba130e0b896f3709ffff22e1c75a51475ddb70476a85abc6b5807af0",
  "GitHub CLI amd64 digest"
);
requireText(
  installer,
  "arm64) gh_sha256=c55feb33684abba57e9909737340d5b39282257c0363e1edde6785ac4a413be7",
  "GitHub CLI arm64 digest"
);
for (const flag of [
  "--hostname github.com",
  '--repo "$REPO"',
  '--signer-workflow "$REPO/.github/workflows/release.yml"',
  '--source-ref "refs/tags/$tag"',
  "--deny-self-hosted-runners",
  '--bundle "$tmp/$attestation_bundle"',
]) {
  requireText(installer, flag, `attestation policy ${flag}`);
}

const canonicalStart = installer.indexOf('if [ "$REPO" = "steerlabs/portablefs" ]; then');
const canonicalEnd = installer.indexOf("\nelse", canonicalStart);
const canonicalPolicy =
  canonicalStart >= 0 && canonicalEnd > canonicalStart
    ? installer.slice(canonicalStart, canonicalEnd)
    : "";
for (const identity of [
  "EXPECTED_TEAM_ID=B47U2LLKHW",
  "EXPECTED_BUNDLE_ID=dev.portablefs.PortableFSApp",
  "EXPECTED_APP_GROUP=B47U2LLKHW.pfsoss",
  "EXPECTED_FS_TYPE=pfs",
  "EXPECTED_RESOURCE_SCHEME=dev.portablefs.oss",
]) {
  requireText(canonicalPolicy, identity, `canonical identity ${identity}`);
}
if (/PORTABLEFS_EXPECTED_/.test(canonicalPolicy)) {
  failures.push("canonical Apple identities remain environment-overridable");
}

const attestationIndex = installer.indexOf('"$tmp/gh" attestation verify');
const extractionIndex = installer.indexOf('tar -xzf "$tmp/$archive"');
if (attestationIndex < 0 || extractionIndex < 0 || attestationIndex >= extractionIndex) {
  failures.push("PortableFS archive extraction can happen before provenance verification");
}
for (const archiveContract of [
  "id: portablefs-client",
  "ids: [portablefs, portablefsd]",
  'name_template: "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"',
  "id: portablefs-server",
  'name_template: "{{ .ProjectName }}-server_{{ .Version }}_{{ .Os }}_{{ .Arch }}"',
  "replace_existing_draft: false",
  "use_existing_draft: false",
  "replace_existing_artifacts: false",
]) {
  requireText(goreleaser, archiveContract, `GoReleaser release contract ${archiveContract}`);
}
for (const exactMemberCheck of [
  'printf \'%s\\n\' "$BINARY" "$DAEMON"',
  "does not contain exactly the PortableFS CLI/daemon pair",
  "contains a link, special entry, or duplicate binary",
]) {
  requireText(installer, exactMemberCheck, `exact installer archive membership check ${exactMemberCheck}`);
}
for (const strictReleaseInput of [
  "curl -fsSL --retry 3 -o /dev/null -w '%{url_effective}'",
  'tag_prefix="https://github.com/$REPO/releases/tag/"',
  "'^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$'",
]) {
  requireText(installer, strictReleaseInput, `strict release input ${strictReleaseInput}`);
}
for (const macArchiveBoundary of [
  'zipinfo -1 "$tmp/$archive"',
  "contains an out-of-bundle member",
  "contains duplicate member",
  "contains a symlink or special filesystem entry",
]) {
  requireText(installer, macArchiveBoundary, `macOS pre-extraction archive boundary ${macArchiveBoundary}`);
}

for (const helperEntitlementContract of [
  "com.apple.security.application-groups",
  "$(PORTABLEFS_APP_GROUP)",
]) {
  requireText(
    helperEntitlements,
    helperEntitlementContract,
    `helper entitlement contract ${helperEntitlementContract}`
  );
}
if (helperEntitlements.includes("com.apple.security.app-sandbox")) {
  failures.push("non-sandboxed helpers were accidentally given the app sandbox entitlement");
}
for (const { relativePath, contents } of appGroupBuildInputs) {
  requireText(
    contents,
    "$(PORTABLEFS_APP_GROUP)",
    `${relativePath} exact app-group build setting`
  );
}
for (const { relativePath, contents } of appGroupBuildConfigs) {
  requireText(
    contents,
    "PORTABLEFS_APP_GROUP = $(TeamIdentifierPrefix)pfsoss",
    `${relativePath} TeamID-prefixed app-group derivation`
  );
  requireText(
    contents,
    "PORTABLEFS_SERVICE_SIGN_IDENTITY = Developer ID Application: TrendUp AI, Inc. (B47U2LLKHW)",
    `${relativePath} explicit daemon Developer ID identity`
  );
}
for (const { relativePath, contents } of appGroupBuildConfigs) {
  if (relativePath === "swift/PortableFSKitMacOS27Dev/Config/Development.xcconfig") {
    const qualificationLines = contents.match(
      /^PORTABLEFS_NATIVE_QUALIFICATION = sdk27-live-qualification-only$/gm
    ) ?? [];
    if (qualificationLines.length !== 1) {
      failures.push(`${relativePath} must carry the one exact native qualification stamp`);
    }
  } else {
    const emptyQualificationLines = contents.match(
      /^PORTABLEFS_NATIVE_QUALIFICATION =$/gm
    ) ?? [];
    if (emptyQualificationLines.length !== 1 || contents.includes("sdk27-live-qualification-only")) {
      failures.push(`${relativePath} must explicitly force an empty native qualification`);
    }
  }
}
for (const { relativePath, contents } of developmentProjects) {
  const exactVersions = contents.match(/MARKETING_VERSION = 0\.2\.3;/g) ?? [];
  if (exactVersions.length !== 4 || /MARKETING_VERSION = (?!0\.2\.3;)/.test(contents)) {
    failures.push(
      `${relativePath} must give all four development build configurations exact release version 0.2.3`
    );
  }
  for (const contract of [
    'name = "Embed PortableFS tools";',
    "../PortableFSApp/Scripts/embed-portablefs-tools.sh",
    "PortableFSDService.app/Contents/MacOS/portablefsd",
  ]) {
    requireText(contents, contract, `${relativePath} sealed helper build ${contract}`);
  }
}
for (const { relativePath, phaseValue, contents } of qualificationPhaseProjects) {
  const occurrences = contents.split(phaseValue).length - 1;
  if (occurrences !== 1) {
    failures.push(
      `${relativePath} must seal its native qualification exactly once at the embed-phase command`
    );
  }
  if (
    phaseValue === "PORTABLEFS_NATIVE_QUALIFICATION= " &&
    contents.includes("PORTABLEFS_NATIVE_QUALIFICATION=sdk27-live-qualification-only ")
  ) {
    failures.push(`${relativePath} contains the macOS 27 development qualification`);
  }
}
for (const signedHelperContract of [
  'script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)',
  'repo_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd)',
  'helper_entitlements_source="$script_dir/../Config/PortableFSHelpers.entitlements"',
  "PORTABLEFS_GO must name the exact Go compiler used for PortableFS helpers",
  'portablefs_go=$(/bin/realpath "$PORTABLEFS_GO")',
  'if [ "$portablefs_go" != "$PORTABLEFS_GO" ]',
  "PORTABLEFS_GO must be owned by root or the build account",
  "PORTABLEFS_GO must not be group- or other-writable",
  'required_go_version=$(/usr/bin/awk',
  'actual_go_version=$(printf \'%s\\n\' "$go_version" | /usr/bin/awk \'{ print $3 }\')',
  'GOFLAGS= GOTOOLCHAIN=local CGO_ENABLED=1 GOOS=darwin GOARCH="$goarch" "$portablefs_go" build',
  'case "$native_qualification" in',
  "sdk27-live-qualification-only)",
  'qualification_build_tags=portablefs_macos27_qualification',
  'set -- -tags "$qualification_build_tags"',
  'if [ "$tool" = portablefs ] && [ -n "$native_qualification" ]',
  "github.com/steerlabs/portablefs/vcs/cmd/portablefs/internal/cli.nativeFSKitPolicyQualification=$native_qualification",
  "signed PortableFS builds require an explicit Developer ID Application identity for the daemon service",
  '"Developer ID Application: "*',
  '--sign "$PORTABLEFS_SERVICE_SIGN_IDENTITY"',
  'build_universal portablefs "$helper_dir/portablefs"',
  'build_universal portablefsd "$service_executable"',
  'service_app="$launch_agents_dir/PortableFSDService.app"',
  "/usr/bin/plutil -insert LSBackgroundOnly -bool YES",
  "Contents/Library/LaunchAgents/PortableFSDService.app/Contents/MacOS/portablefsd",
  '--entitlements "$helper_entitlements"',
]) {
  requireText(
    helperEmbedder,
    signedHelperContract,
    `embedded helper signing contract ${signedHelperContract.trim()}`
  );
}
for (const contract of [
  "type macOSInstallCodeIdentityPolicy uint8",
  "macOSInstallDeveloperIDRelease",
  "macOSInstallAppleDevelopmentQualification",
  "macOSInstallAppleDevelopmentRecoverySource",
  'appName:               macOSAppName',
  'appExecutable:         macOSAppExecutable',
  'extensionExecutable:   macOSExtensionExecutable',
  'serviceMinimumOS:      "26.0"',
  'codeIdentity:          macOSInstallDeveloperIDRelease',
  'installedCodeIdentity: macOSInstallDeveloperIDRelease',
  "installedMacOSCodeIdentityForHostHash(",
  "hostCodeDirectoryHash == layout.installedRecovery.hostCodeDirectoryHash",
  "validateInstalledMacOSBundleForPublicationWithLayout(",
  "layout.installedCodeIdentity",
  "validateRecoveryCodeDirectoryIdentity(",
  "return runInstallMacOSAppWithLayout(",
  "validateMacOSInstallSourceWithLayout(sourceApp, layout)",
  "validateMacOSBundleForPublicationWithLayout(",
  "validateMacOSSigningAuthorities(",
  "decodeExactCodeEntitlements(entitlements, tempRoot)",
  'entitlements["com.apple.security.application-groups"]',
  "validateExactEntitlementDictionary(observed, wanted, code)",
  "signed %s must carry no entitlements",
  "currentMacOSProvisioningUDID()",
  "validateQualificationProfileLayout(app, profilePath)",
  "qualification app must contain exactly its extension profile",
  "qualification extension profile does not authorize this exact Mac provisioning UDID",
  'plistNativeExtract(profilePath, "Entitlements", "dictionary", "xml1")',
  "result.DeveloperCertificates, err = plistNativeDataArray(",
  'profilePath, "DeveloperCertificates",',
  'plistNativeDate(profilePath, "CreationDate")',
  'plistNativeDate(profilePath, "ExpirationDate")',
  '"/usr/bin/codesign", "-d", "--extract-certificates="+prefix, code',
  "qualification extension profile does not authorize its exact signing certificate",
]) {
  requireText(cliMacOSInstaller, contract, `immutable macOS installer layout ${contract}`);
}
for (const forbidden of [
  'plistStringArray(entitlementPath, "com.apple.security.application-groups")',
  'Print :com.apple.security.application-groups',
  "convert qualification extension profile",
]) {
  if (cliMacOSInstaller.includes(forbidden)) {
    failures.push(`macOS installer parses literal dotted entitlement keys as paths: ${forbidden}`);
  }
}
for (const forbidden of [
  "PORTABLEFS_INSTALL_LAYOUT",
  "PORTABLEFS_APP_NAME",
  "PORTABLEFS_EXTENSION_NAME",
]) {
  if (cliMacOSInstaller.includes(forbidden)) {
    failures.push(`macOS installer layout became runtime-configurable through ${forbidden}`);
  }
}
for (const contract of [
  "//go:build darwin && portablefs_macos27_qualification",
  'appName:               "PortableFSKitDev.app"',
  'stagedAppName:         "PortableFSKitDev.next"',
  'appExecutable:         "PortableFSKitDev"',
  'extensionExecutable:   "PortableFSDev"',
  'serviceMinimumOS:      "27.0"',
  'requiredAppID:         "dev.portablefs.oss.KitDev"',
  "codeIdentity:          macOSInstallAppleDevelopmentQualification",
  "installedCodeIdentity: macOSInstallAppleDevelopmentQualification",
  'hostCodeDirectoryHash:      "f09258ec96fa0e468b91c51005e6f76bee16a660"',
  'extensionCodeDirectoryHash: "311e2cc459ec796bc88de293957dc3079a579d45"',
  'cliCodeDirectoryHash:       "027789129c4e749ef4b89887abca1be097d49a56"',
  'serviceCodeDirectoryHash:   "076636f6ffb95880c83d72fefe08e1a50b126f7d"',
  'daemonExecutableSHA256:     "eb2d4f8225f11076ddc76bd6208503d5068dc8d7105ddb47b74e4d9748b63a84"',
  'name:    "install-macos27-qualification-app"',
  'func qualificationCommandHelp(name string) (string, bool)',
]) {
  requireText(macOS27QualificationLayout, contract, `macOS 27 qualification layout ${contract}`);
}
for (const [source, label] of [
  [macOS26DevelopmentHost, "macOS 26 development host"],
  [macOS27DevelopmentHost, "macOS 27 development host"],
]) {
  for (const contract of [
    "resumeNormalLifecycle: { [weak self] in",
    "Task { @MainActor [weak self] in",
    "self?.publishEnabledPresentation()",
    "statusLabel?.stringValue",
  ]) {
    requireText(source, contract, `${label} resumed presentation ${contract}`);
  }
}
for (const contract of [
  'UserDefaults.standard.set(state, forKey: "PFSLaunchAgentState")',
  'UserDefaults.standard.set(detail, forKey: "PFSLaunchAgentDetail")',
  "presentation-only diagnostics",
]) {
  requireText(macOS27DevelopmentHost, contract, `macOS 27 diagnostic presentation ${contract}`);
}
for (const forbiddenRead of [
  'string(forKey: "PFSLaunchAgentState")',
  'object(forKey: "PFSLaunchAgentState")',
  'bool(forKey: "PFSLaunchAgentState")',
]) {
  if (macOS27DevelopmentHost.includes(forbiddenRead)) {
    failures.push(`macOS 27 host treats presentation defaults as authority: ${forbiddenRead}`);
  }
}
for (const contract of [
  "//go:build darwin && portablefs_macos27_qualification",
  "runInstallMacOSAppWithLayout(",
  "macOS27QualificationInstallLayout",
  "macOS27QualificationInstallerAdmitted(nativeFSKitPolicyQualification)",
  "return stamp == sdk27QualificationStamp",
]) {
  requireText(macOS27QualificationCommand, contract, `tagged qualification installer ${contract}`);
}
requireText(
  disabledQualificationLayout,
  "//go:build !darwin || !portablefs_macos27_qualification",
  "production qualification command exclusion build constraint"
);
requireText(
  disabledQualificationLayout,
  'func qualificationCommandHelp(string) (string, bool) { return "", false }',
  "production qualification help exclusion"
);
requireText(
  cliCommands,
  "return append(commands, qualificationCommands()...)",
  "compile-time qualification command registration"
);
for (const forbiddenSource of [installer, packager, workflow, ciWorkflow, goreleaser]) {
  if (forbiddenSource.includes("portablefs_macos27_qualification")) {
    failures.push("shipping/release lane can compile the macOS 27 qualification installer tag");
  }
}
for (const canonicalDevOutput of [
  "path = PortableFSKitDev.app;",
  "productName = PortableFSKitDev;",
  "PRODUCT_NAME = PortableFSKitDev;",
]) {
  requireText(
    qualificationProject,
    canonicalDevOutput,
    `canonical macOS 27 development bundle ${canonicalDevOutput}`
  );
}
if (qualificationProject.includes("path = PortableFSKitMacOS27Dev.app;") ||
    qualificationProject.includes("PRODUCT_NAME = PortableFSKitMacOS27Dev;")) {
  failures.push("macOS 27 development target still emits a noncanonical app or executable name");
}
if (helperEmbedder.includes('Contents/Helpers/portablefsd')) {
  failures.push("embedded daemon retained the obsolete raw Helpers path");
}
for (const verification of [
  'verify_app_group_entitlement "$source_app" host',
  'verify_app_group_entitlement "$source_extension" extension',
  'verify_app_group_entitlement "$source_daemon" daemon',
  'verify_no_app_group_entitlement "$source_cli" cli',
  'service_remaining_entitlements=',
]) {
  requireText(installer, verification, `installer ${verification}`);
}
for (const verification of [
  'verify_app_group_entitlement "$app" host',
  'verify_app_group_entitlement "$extension" extension',
  'verify_app_group_entitlement "$daemon" daemon',
  'verify_no_app_group_entitlement "$cli" cli',
  "verify_exact_service_entitlements",
]) {
  requireText(packager, verification, `packager ${verification}`);
}
for (const unsignedBuildVerification of [
  '[ "$host_group" = "$app_group" ]',
  '[ "$extension_group" = "$app_group" ]',
  '[ "$host_group" = "$extension_group" ]',
  '[ "$cli_group" = "$app_group" ]',
  '[ "$daemon_group" = "$app_group" ]',
  '[ "$app_version" = "$version" ]',
  '[ "$extension_version" = "$version" ]',
  '[ "$service_version" = "$version" ]',
  '"$cli" version | grep -Fx "portablefs $version"',
  '"$daemon" -version | grep -Fx "$version"',
  'PORTABLEFS_APP_GROUP="$app_group"',
  'MARKETING_VERSION="$version"',
  'PORTABLEFS_GO="$go_binary"',
  "PORTABLEFS_NATIVE_QUALIFICATION=",
  'go_root=$(GOTOOLCHAIN=auto "$go_candidate" -C "$repo_root/vcs" env GOROOT)',
  '[ "$actual_go_version" = "$required_go_version" ]',
]) {
  requireText(
    packager,
    unsignedBuildVerification,
    `unsigned package app-group proof ${unsignedBuildVerification}`
  );
}

for (const exactHostContract of [
  "openApplicationAtURL:appURL",
  "configuration.activates = NO",
  "configuration.allowsRunningApplicationSubstitution = NO",
  "pthread_main_np() == 0",
  "[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode",
  "[completion abandonWaiter]",
]) {
  requireText(
    darwinNativeBridge,
    exactHostContract,
    `exact NSWorkspace host launch ${exactHostContract}`
  );
}
for (const singleNativeBridgeContract of [
  "containerURLForSecurityApplicationGroupIdentifier:group",
  "portablefs_app_group_container_path",
  "portablefs_launch_exact_host",
]) {
  requireText(
    darwinNativeBridge,
    singleNativeBridgeContract,
    `single Darwin native bridge ${singleNativeBridgeContract}`
  );
}
requireText(
  appHostLauncher,
  "requestNativeExactApp(path)",
  "app host delegates to the single Darwin native bridge"
);
requireText(
  appHostLauncher,
  "runtime.LockOSThread()",
  "app host retains the CLI startup goroutine on the process main thread"
);
for (const ambiguousLaunchContract of [
  "ErrLaunchCompletionAmbiguous",
  "requestExactMacOSHostForProof(destinationApp)",
  "requireLiveMacOSServiceRelease(targetRelease, 15*time.Second)",
]) {
  requireText(
    ambiguousLaunchContract === "ErrLaunchCompletionAmbiguous"
      ? cliFSKit
      : cliMacOSInstaller,
    ambiguousLaunchContract,
    `ambiguous exact-app launch proof ${ambiguousLaunchContract}`
  );
}
for (const resumeContract of [
  "resume-target",
  "resume-rollback",
  "ResumeActive(",
  "acceptOrResumeMacOSActivation(",
  "completeOrResumeMacOSActivation(",
  "ActivationRequestAmbiguousError",
]) {
  const source = resumeContract === "resume-target" || resumeContract === "resume-rollback"
    ? hostControlProtocol
    : resumeContract === "ResumeActive(" || resumeContract === "ActivationRequestAmbiguousError"
      ? hostControlClient
      : cliMacOSInstaller;
  requireText(source, resumeContract, `token-bound activation recovery ${resumeContract}`);
}
for (const deadlineContract of [
  "macOSActivationTransactionTimeout",
  "macOSActivationDeadlineMargin",
  "macOSActivationCompletionReserve",
  "macOSActivationPostLaunchReserve",
  "macOSActivationFenceAndRollbackReserve",
  "activationAdmission(",
  "activationChildContext(",
  "fenceReadyMacOSActivation(",
  "activationFencedForBudgetError",
]) {
  requireText(
    cliMacOSInstaller,
    deadlineContract,
    `activation residual-budget contract ${deadlineContract}`
  );
}
for (const serverResumeContract of [
  "handleActiveResume",
  "try actions.proveActive(expectedRelease)",
  "active.oldRelease == request.oldRelease",
  "active.targetRelease == request.targetRelease",
  "try store.load() == active",
]) {
  requireText(
    serviceUpdateServer,
    serverResumeContract,
    `host active-resume proof ${serverResumeContract}`
  );
}
requireText(
  appGroupResolver,
  "darwinnative.ResolveAppGroupContainer(identifier)",
  "app-group resolver delegates to the single Darwin native bridge"
);
for (const cliControlContract of [
  'filepath.Join(home, ".local", "state", "portablefs", "portablefsd", "control.sock")',
  "apphost.LaunchContainingApp(executable)",
  '"/v1/attaches/"+url.PathEscape(ref)+"/frontend-preflight"',
]) {
  requireText(cliFSKit, cliControlContract, `unentitled CLI control contract ${cliControlContract}`);
}
for (const forbiddenCLIDataVaultPath of [
  "appgroupcontainer",
  "Group Containers",
  "containerURL",
  "exec.Command(daemon.path",
]) {
  if (cliFSKit.includes(forbiddenCLIDataVaultPath)) {
    failures.push(`shell CLI regained Data Vault or direct-spawn path (${forbiddenCLIDataVaultPath})`);
  }
}
requireText(
  daemonControl,
  'case "frontend-preflight":',
  "versioned daemon-owned frontend preflight endpoint"
);

for (const permission of ["id-token: write", "attestations: write"]) {
  requireText(workflow, permission, `release permission ${permission}`);
}
requireText(
  workflow,
  "actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d",
  "pinned attestation action"
);
requireText(
  workflow,
  'subject-path: "${{ github.workspace }}/dist/portablefs_*_linux_amd64.tar.gz"',
  "Linux amd64 attestation subject"
);
requireText(
  workflow,
  'subject-path: "${{ github.workspace }}/dist/portablefs_*_linux_arm64.tar.gz"',
  "Linux arm64 attestation subject"
);
requireText(
  workflow,
  'subject-path: "${{ github.workspace }}/dist/portablefs-server_*_linux_amd64.tar.gz"',
  "Linux server amd64 attestation subject"
);
requireText(
  workflow,
  'subject-path: "${{ github.workspace }}/dist/portablefs-server_*_linux_arm64.tar.gz"',
  "Linux server arm64 attestation subject"
);
requireText(
  workflow,
  "portablefs_${version}_linux_amd64.tar.gz.attestation.jsonl",
  "deterministic amd64 attestation bundle asset"
);
requireText(
  workflow,
  "portablefs_${version}_linux_arm64.tar.gz.attestation.jsonl",
  "deterministic arm64 attestation bundle asset"
);
requireText(
  workflow,
  "portablefs-server_${version}_linux_amd64.tar.gz.attestation.jsonl",
  "deterministic server amd64 attestation bundle asset"
);
requireText(
  workflow,
  "portablefs-server_${version}_linux_arm64.tar.gz.attestation.jsonl",
  "deterministic server arm64 attestation bundle asset"
);
for (const serverArchiveContract of [
  'server_archive="dist/portablefs-server_${version}_linux_${arch}.tar.gz"',
  "printf '%s\\n' portablefs-authority",
  '"$RUNNER_TEMP/server-member-types-${arch}"',
]) {
  requireText(workflow, serverArchiveContract, `exact server archive contract ${serverArchiveContract}`);
}
for (const immutablePublication of [
  "Refuse a pre-existing GitHub release for this tag",
  "Verify exact Linux installer archive membership",
  "test \"$(gh release view",
]) {
  requireText(workflow, immutablePublication, `immutable release publication ${immutablePublication}`);
}
if (workflow.includes("--clobber")) {
  failures.push("release workflow can replace an existing asset with --clobber");
}
for (const releaseGate of [
  "Prove an exact stable tag at this source revision",
  "CGO_ENABLED=0 GOOS=linux go -C vcs build ./...",
  "Verify the Foundation-enabled Darwin data plane",
  "CGO_ENABLED=1 GOOS=darwin go -C vcs build ./...",
  "CGO_ENABLED=1 GOOS=darwin go -C vcs vet ./...",
  "CGO_ENABLED=1 GOOS=darwin go -C vcs test ./...",
  "go -C vcs vet ./...",
  "go -C vcs test ./...",
  "go -C vcs test -race ./...",
  "sh -n scripts/install.sh",
  "node scripts/check-workflow-pins.mjs",
  "node scripts/check-install-release-trust.mjs",
  "govulncheck@v1.6.0",
  "args: check",
  "needs: validate",
  "needs: [validate, goreleaser]",
  "needs: [validate, goreleaser, macos-app]",
  "run: bash scripts/test-swift-xcode.sh",
]) {
  requireText(workflow, releaseGate, `release validation gate ${releaseGate}`);
}
for (const ciGate of [
  "swift-xcode-native:",
  "name: swift-xcode-native",
  "run: bash scripts/test-swift-xcode.sh",
]) {
  requireText(ciWorkflow, ciGate, `CI Xcode-native Swift gate ${ciGate}`);
}
for (const gateContract of [
  "-enumerate-tests",
  "-test-enumeration-format json",
  "-parallel-testing-enabled NO",
  "-onlyUsePackageVersionsFromResolvedFile",
  "test-without-building",
  "xcresulttool get test-results tests",
  "scripts/test_verify_xcode_tests.py",
  "scripts/verify_xcode_tests.py",
]) {
  requireText(xcodeSwiftGate, gateContract, `Xcode-native Swift contract ${gateContract}`);
}
for (const evidenceContract of [
  'EXPECTED_TEST_MODULES = frozenset({"PortableFSAppCoreTests", "PortableFSKitTests"})',
  'value.get("disabledTests") != []',
  'value.get("nodeType") == "Test Case"',
  'result != "Passed"',
  "missing = sorted(set(expected) - set(actual))",
  "unexpected = sorted(set(actual) - set(expected))",
]) {
  requireText(
    xcodeEvidenceVerifier,
    evidenceContract,
    `Xcode test evidence verifier ${evidenceContract}`
  );
}
for (const negativeEvidenceTest of [
  "test_enumeration_rejects_errors_disabled_duplicates_and_unknown_modules",
  "test_results_reject_failure_missing_unexpected_duplicate_and_wrong_destination",
  "test_json_loader_rejects_duplicate_keys_and_unbounded_input",
]) {
  requireText(
    xcodeEvidenceTests,
    negativeEvidenceTest,
    `Xcode test evidence negative test ${negativeEvidenceTest}`
  );
}
for (const forbiddenSwiftPMWorkaround of [
  "swift-partition-coverage",
  "SWIFT_TEST_FILTER",
  "swift-test-attempt",
  "swiftpm-testing-helper",
  "process.wait(timeout=240)",
]) {
  if (
    ciWorkflow.includes(forbiddenSwiftPMWorkaround) ||
    workflow.includes(forbiddenSwiftPMWorkaround) ||
    xcodeSwiftGate.includes(forbiddenSwiftPMWorkaround)
  ) {
    failures.push(`Swift verification retains workaround ${forbiddenSwiftPMWorkaround}`);
  }
}
// The v3 tree publishes exactly two trust chains: the Linux archives (Sigstore
// provenance) and the notarized macOS app. The journal-era control-plane
// container images are gone, so the release workflow must not push any image.
for (const retiredControlPlane of ["ghcr.io", "docker/build-push-action", "Dockerfile"]) {
  if (workflow.includes(retiredControlPlane)) {
    failures.push(`release workflow still publishes retired control-plane images (${retiredControlPlane})`);
  }
}

if (failures.length > 0) {
  process.stderr.write(`install release trust policy failed:\n- ${failures.join("\n- ")}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write("install release trust policy ok\n");
}
