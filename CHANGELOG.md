# Changelog

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
