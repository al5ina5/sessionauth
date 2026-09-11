# Changelog

## 1.2.2 — reviewer round 2, part 2

Follow-ups from re-auditing 1.2.1:
- Store: `provision` KDF out of the global lock, legacy-upgrade race closed,
  `setStrict`/`resetIps`/`unregister` report save failures, atomic-move
  fallback on any IO error, malformed-salt handling fail-closed, empty names
  rejected.
- Session: `reset` shares the de-auth helper (locks + re-prompts), `changepw`
  lockout cleans session state, break-speed fully cancelled, momentum killed
  before first-tick anchor, `fallDistance` reset, admin targets re-prompted.
- Mask: `(?is)` so multi-line echoes can't split token off password; docs now
  state the slash-less-chat scope limit honestly.

## 1.2.1 — reviewer round 2

Fixes from a 5-way audit:
- Admin `provision`/`unregister` now de-auth live sessions and clear login
  blocks (was: player stayed authed); blocked-join no longer leaks lock state.
- Fresh joins never inherit stale sessions (cleared at login start).
- `/changepw` now counts toward brute-force protection like `/login`.
- Store: KDF moved out of the global lock, saves report failure, corrupt
  accounts files are quarantined (not overwritten), atomic-move fallback,
  null/malformed-record hardening, unknown algorithms fail closed,
  `/changepw` also forgets known IPs.
- Freeze: break-speed cancelled + harvest denied, containers closed on open,
  momentum zeroed each tick.
- Mask: any `namespace:` prefix covered (`sessionauth:login` leaked before).
- UX: `/changepw` new password may contain spaces, `ips`/`strict` handle
  unknown accounts first, block times render as `10m`/`1h`, weak-password
  nudge after login, `/logout` re-freezes immediately.

## 1.2.0

- Default `minPasswordLength` 4 → 6 (range still 1–128, so owners who want
  4-char PINs can lower it back — not recommended, 4-digit PINs fall to
  offline brute force in under a second against the old hash).
- Password storage: PBKDF2-HMAC-SHA256 (210,000 iterations, JDK built-in,
  still dependency-free). Pre-1.2.0 SHA-256 records verify and auto-upgrade
  on next successful login.
- Log masking: case-insensitive, covers `minecraft:`-namespaced commands
  (`/minecraft:login <pw>` leaked before).

## 1.1.3

- Login prompt is now persistent: re-shown every 2 seconds while frozen
  (vanilla action bars fade, so a single send disappears). The reminder
  interval config is gone — the prompt simply stays until login.

## 1.1.2

- Login prompt moved from chat to the action bar (centered above the hotbar):
  one line on join, repeated while frozen. No more stacked chat messages.

## 1.1.1

- Join message is now one line for everyone: first visit → `/register`,
  returning → `/login` (was two redundant lines).

## 1.1.0 — review pass

Fixes:
- `/changepw` always failed (greedy first argument swallowed the second) —
  now plain single-word arguments
- `provision` kept old known addresses (auto-login bypass after takeover) —
  now forgets them
- Console `authadmin provision` passwords could reach the logs — now masked

New:
- Brute-force protection: configurable attempt limit + temporary login block
- Periodic login reminder for frozen players (configurable, off = 0)
- `authadmin help`, `strict` rejects non-true/false values
- `reset` finds players regardless of name casing

Internal: dead code removed. (A consolidation of the interact handlers was
tried and reverted — the base event class is abstract and can't take
subscriptions; boot-testing caught it.) README rewritten for players,
internals moved to docs/TECHNICAL.md.

## 1.0.0 — first public release

- `/register`, `/login`, `/changepw`, `/logout` (real text passwords, not numeric PINs)
- Known-IP auto-login with per-player IP memory (configurable cap)
- Per-player `strict` mode (always require password)
- Freeze for unauthenticated players: no move, chat, commands, interact,
  damage dealt/taken, pickup or drop
- Salted SHA-256 password storage (`sessionauth-accounts.json`)
- Automatic masking of password lines in server logs
- `authadmin` console/op commands: provision, reset, unregister, ips, strict
- Config file (`sessionauth-common.toml`): min password length, max known
  IPs, auto-login toggle
- Idle on non-dedicated servers (singleplayer/LAN unaffected)
- NeoForge 26.1.2 (26.1.2.106), Java 25, no dependencies, no mixins
