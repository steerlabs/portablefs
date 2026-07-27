<!--
Thanks for contributing to PortableFS. Keep the description focused on WHY.
-->

## Summary

<!-- What does this change and why? Link any issue it closes. -->

## Changes

<!-- Bullet the notable changes. -->

-

## Testing

<!-- How did you verify this? Paste the commands you ran. -->

- [ ] `pnpm verify` (TS build/test/typecheck + Go vet/test + race)
- [ ] `pnpm verify:postgres` (if metadata-db / migrations changed)
- [ ] New or updated tests cover the change

## Checklist

- [ ] Commits are signed off (`git commit -s`) — the DCO check requires it (see [CONTRIBUTING.md](https://github.com/steerlabs/portablefs/blob/main/CONTRIBUTING.md#sign-your-work-dco)).
- [ ] Changes to surfaces in [COMPATIBILITY.md](https://github.com/steerlabs/portablefs/blob/main/COMPATIBILITY.md) are called out above and reviewed.
- [ ] No secrets, tokens, or personal paths added; no new `..`/symlink path handling that bypasses the volume root.
- [ ] Docs updated if behavior or guarantees changed.
