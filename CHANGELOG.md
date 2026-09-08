# Changelog

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
