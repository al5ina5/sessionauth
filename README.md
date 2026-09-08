# SessionAuth

Stop strangers from playing as you on offline-mode (`online-mode=false`) servers.
Server-side only — players join with plain vanilla clients, nothing to install.

## For players (show them this)

**First join:** `/register <password>` — pick any password.

**Every visit after that:** nothing. The server recognizes your internet
address and logs you in by itself.

**If your internet address changes** (new wifi, phone hotspot, moved house):
`/login <password>` once — then you're remembered again.

**Change password:** `/changepw <old> <new>`

**Forgot it?** Ask a server admin to reset you.

## For server owners

1. Drop the jar in the server `mods/` folder. Needs NeoForge, nothing else.
2. Start the server once so it creates `config/sessionauth-common.toml`.
3. That's it. Optional tweaks in the config file:
   - `minPasswordLength` (default 4)
   - `maxKnownIps` (default 8)
   - `autoLoginKnownIp` (default true — set false to ask the password every time)
   - `maxLoginAttempts` / `loginBlockSeconds` (brute-force protection)
   - `loginReminderSeconds` (how often frozen players are told what to do)

Admin commands (ops + console): `authadmin provision | reset | unregister |
ips | strict | help`. Full details in [`docs/TECHNICAL.md`](docs/TECHNICAL.md).

Back up `sessionauth-accounts.json` (next to `server.properties`) with your world.

## Good to know

- Safe to have in a client pack or singleplayer world: it only acts on
  dedicated servers.
- Family sharing one internet connection just works — every name is tracked
  separately. (Same-house players *can* use each other's names; turn on
  `strict` for anyone who wants a password every time.)
- Passwords are stored hashed, never plaintext, and never reach the server logs.

MIT — see `LICENSE`. Details for the curious: [`docs/TECHNICAL.md`](docs/TECHNICAL.md).
