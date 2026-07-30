# PortableFS.app — deferred product polish

The distribution and mount-lifecycle architecture is implemented in the app,
embedded CLI, and release pipeline. Remaining work is presentation-only:

- Add a branch picker per volume.
- Add an app icon and localizations.
- Consider Keychain-backed control-plane credentials while retaining CLI/app
  interoperability.

The app must remain a UI over the embedded CLI. Do not add app-owned daemon,
mount, lease, recovery, or alternate state-root behavior.
