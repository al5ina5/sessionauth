# SessionAuth

Stop strangers from playing as you on offline-mode (`online-mode=false`) servers.
Server-side only — players join with plain vanilla clients, nothing to install.

## For players (show them this)

**First join:** `/register <password>` — pick any password.

**Every visit after that:** nothing. The server recognizes your internet
address and logs you in by itself.

**If your internet address changes** (new wifi, phone hotspot, moved house):
`/login <password>` once — then you're remembered again.

**Change password:** `/changepw <old> <new>` (single-word old password; new may contain spaces)

**Forgot it?** Ask a server admin to reset you.

## For server owners

1. Drop the jar in the server `mods/` folder. Needs NeoForge, nothing else.
2. Start the server once so it creates `config/sessionauth-common.toml`.
3. That's it. Optional tweaks in the config file:
   - `minPasswordLength` (default 6, range 1–128 — can be lowered to 4, not recommended)
   - `maxKnownIps` (default 8)
   - `autoLoginKnownIp` (default true — set false to ask the password every time)
   - `maxLoginAttempts` / `loginBlockSeconds` (brute-force protection)

Admin commands (server ops + console/command blocks): `authadmin provision | reset | unregister |
ips | strict | help`. Full details in [`docs/TECHNICAL.md`](docs/TECHNICAL.md).

Back up `sessionauth-accounts.json` (next to `server.properties`) with your world.

## Good to know

- Safe to have in a client pack or singleplayer world: it only acts on
  dedicated servers.
- Family sharing one internet connection just works — every name is tracked
  separately. (Same-house players *can* use each other's names; per-player
  `strict` mode via `authadmin strict <name> true` asks for a password every time.)
- Passwords are stored hashed (PBKDF2), never plaintext, and single-line
  slash-form password command lines never reach the server logs. Typing your
  password into chat by mistake (without `/`) is NOT masked — always use `/login`.

MIT — see `LICENSE`. Details for the curious: [`docs/TECHNICAL.md`](docs/TECHNICAL.md).
