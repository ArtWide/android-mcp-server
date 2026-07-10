# Provenance

This skill is **vendored** (copied) from an upstream open-source project. It is
not maintained here — update it by re-syncing from upstream, not by editing in place.

- **Upstream**: https://github.com/vichhka-git/renef-skills
- **Author**: vichhka-git
- **License**: Apache-2.0 (see `LICENSE` in this folder)
- **Vendored commit**: `c0a23d6f5cdd95eb87fe86e9eef672dbad300ba4`
- **Vendored on**: 2026-07-10
- **Underlying tool**: renef / renef.io by @Ahmeth4n (https://github.com/Ahmeth4n/renef), Apache-2.0

## Why it's here

renef is an **alternative dynamic-instrumentation engine** for Android ARM64
(Lua 5.4, memfd injection, no ptrace). It is kept as a **fallback to Frida** for
anti-Frida / RASP targets — see the cross-reference in
`../malware-analysis/SKILL.md` ("대안 계측 엔진 (Frida가 탐지·차단될 때) — renef").

## Integration status (read before relying on it)

- **NOT integrated with this project's MCP server.** There are no `renef_*` MCP
  tools; renef is driven as a host CLI (`renef ... -l script.lua`) over an
  ADB-forwarded socket. The MCP `execute_adb_shell_command` can help with the
  device side, but the renef client itself runs on the host shell.
- **Requires**: rooted device (or gadget mode) + ARM64 target + the `renef`
  client installed on the host. The team's default analysis device must satisfy
  these before this skill is actionable.

## Re-syncing from upstream

```bash
git clone --depth 1 https://github.com/vichhka-git/renef-skills /tmp/renef-skills
cp -r /tmp/renef-skills/skills/renef/. skills/renef/
cp /tmp/renef-skills/LICENSE skills/renef/LICENSE
# then update the "Vendored commit"/"Vendored on" lines above
```
