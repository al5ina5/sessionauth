# SessionAuth

Password login with known-IP auto-login for **offline-mode** (`online-mode=false`)
NeoForge servers. Server-side only — vanilla clients work, no client mod needed.

On offline-mode servers a name proves nothing: anyone can join as anyone,
including your ops. SessionAuth fixes that without annoying your regulars:

- First join: `/register <password>` (real text password, any length you configure).
- Returning from a known internet address: **logged in automatically**, zero typing.
- New address: `/login <password>` once — then it's remembered too.
- Until logged in, players can't move, chat, run commands, interact, take or
  deal damage, or pick up / drop items. A name-mimic gets exactly nowhere.
- Passwords are stored salted + SHA-256 hashed (never plaintext), and password
  lines are masked out of the server logs automatically.

Household-safe: each name has its own independent record, so family members
sharing one IP never interfere. (Same-IP players *can* wear each other's names —
use `strict` mode below for anyone who wants a password every time.)

## Commands

Players:

- `/register <password>` — first join only
- `/login <password>` — when asked (new address)
- `/changepw <old> <new>` — change password
- `/logout` — de-authenticate (shared PCs)

Admins (ops + console), all prefixed `authadmin`:

- `provision <player> <password>` — pre-create an account (give the password
  to your friend out-of-band; beats first-to-register theft)
- `reset <player>` — forget all known IPs (password required next join)
- `unregister <player>` — delete the account
- `ips <player>` — list remembered addresses
- `strict <player> <true|false>` — always require the password

## Config (`config/sessionauth-common.toml`)

- `minPasswordLength` (default 4)
- `maxKnownIps` (default 8, oldest forgotten first)
- `autoLoginKnownIp` (default true — set false to require the password every join)

## Notes

- Designed for offline-mode servers. Also runs on online-mode servers, but
  accounts are keyed by player name, so a Mojang name-change orphans the old
  record (same behavior as the vanilla whitelist).
- Does nothing unless on a **dedicated server** — safe (if pointless) in a
  client pack or singleplayer world.
- Data file: `sessionauth-accounts.json` next to `server.properties`.
  **Back it up** alongside your world.
- No mixins, no client code, no dependencies beyond NeoForge itself.

## Building

Needs JDK 21+ to run Gradle and a JDK 25 for the toolchain:

```bash
./gradlew build -Porg.gradle.java.installations.paths=/path/to/jdk25,/path/to/jdk21
```

The jar lands in `build/libs/`.

## License

MIT — see `LICENSE`.
