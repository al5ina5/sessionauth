# SessionAuth — technical notes

For server owners who want the full picture and for contributors.
Player-facing docs live in the README.

## How it works

Offline-mode servers verify nothing: the client just announces a name.
SessionAuth adds a password + known-address memory on top:

- Accounts keyed by lowercase name in `sessionauth-accounts.json`
  (atomic write via temp file + rename), next to `server.properties`.
- Passwords: per-user 16-byte salt, PBKDF2-HMAC-SHA256 (210,000 iterations,
  256-bit key), hex. Pre-1.2.0 single-round SHA-256 records still verify and
  auto-upgrade to PBKDF2 on next successful login.
  Compared with `MessageDigest.isEqual` (constant-time).
- On login: unknown name → must `/register`. Known name + remembered
  address (and not `strict`, and `autoLoginKnownIp` on) → auto-login.
  Otherwise → `/login`, and the address is learned on success.
- Unauthenticated players are frozen: no chat, no non-auth commands, no
  block/item/entity interaction, position locked (teleport-back), immune to
  and incapable of damage, no pickup/drop. Plus a periodic reminder message.
- Brute force: configurable wrong-attempt limit per name, then a temporary
  login block (kick on join while blocked). In-memory only; a restart clears
  blocks, the store is the persistent part.
- `provision` (and any password overwrite) forgets known addresses, so taking
  over an account can't inherit its trust.

## Log masking

A global Log4j filter drops any line containing `/register|/login|/changepw`
(with any casing, with or without a `minecraft:` namespace prefix)
or `authadmin provision` (covers typed passwords and syntax-error echoes).
Everything else logs normally — unlike the `logAdminCommands` gamerule.
Fail-closed by design: our own log messages avoid those tokens.

## Limitations (honest)

- Not for Bungee/Velocity networks: every player arrives from the proxy's
  address, so one login would auto-auth everyone behind it.
- Name-keyed accounts: a Mojang name-change orphans the old record on
  online-mode servers (same as the vanilla whitelist). Offline-mode servers
  (the target use case) are unaffected — offline UUIDs derive from names.
- Same-address impersonation (households, shared VPN exits) is trusted by
  design; `strict` mode covers anyone who wants out of that.
- Whoever can read the accounts file can attempt offline guessing; PBKDF2
  (210k iterations) slows this by ~5 orders of magnitude vs single-round
  SHA-256, but short passwords still fall — the default minimum is 6 and
  existing weak passwords should be reset.
- No permission nodes yet — admin commands check op level / console.

## Building

JDK 21+ to run Gradle, JDK 25 toolchain for compilation:

```bash
./gradlew build -Porg.gradle.java.installations.paths=/path/to/jdk25,/path/to/jdk21
```

Jar lands in `build/libs/`. Pinned to NeoForge 26.1.2.106 / MC 26.1.2.

## Roadmap ideas

Permission nodes, UUID-keyed accounts with migration,
configurable freeze granularity, kick-after-timeout for idle unauthed players.
