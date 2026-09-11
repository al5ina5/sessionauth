package com.seebi.sessionauth;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.mojang.logging.LogUtils;
import org.slf4j.Logger;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Password + known-IP store, persisted as JSON in the server game directory.
 * One record per (lowercased) player name. Multiple names may share one IP
 * (households) — records are fully independent, so housemates can never
 * lock each other out.
 */
public final class AuthStore {
    private static final Logger LOGGER = LogUtils.getLogger();
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static final SecureRandom SHARED_RANDOM = new SecureRandom();

    /** PBKDF2-HMAC-SHA256 cost for new passwords (OWASP 210k, JDK built-in, still dependency-free). */
    static final int PBKDF2_ITERATIONS = 210_000;
    private static final int PBKDF2_KEY_BITS = 256;
    private static final String ALGO_PBKDF2 = "pbkdf2-210k";

    private final Path file;
    private final Map<String, Account> accounts = new ConcurrentHashMap<>();

    public AuthStore(Path gameDir) {
        this.file = gameDir.resolve("sessionauth-accounts.json");
        load();
    }

    public static final class Account {
        String salt = "";
        String hash = "";
        // "" (or missing) = legacy single-round SHA-256, "pbkdf2-210k" = PBKDF2-HMAC-SHA256.
        // Old records without this field keep verifying and auto-upgrade on next successful login.
        // Unknown non-empty values fail closed (never tried as legacy).
        String algo = "";
        List<String> ips = new ArrayList<>();
        boolean strict = false; // true = always require password, even from known IPs
    }

    public boolean exists(String name) {
        return accounts.containsKey(key(name));
    }

    /** Create a new account. Returns false if it already exists or the save failed. */
    public boolean register(String name, String password, String ip) {
        if (name == null || password == null) return false;
        String k = key(name);
        if (accounts.containsKey(k)) return false;
        // Costly KDF runs outside any lock so login bursts can't serialize the server.
        String salt = newSalt();
        String hash;
        try {
            hash = hashPbkdf2(salt, password);
        } catch (IllegalArgumentException e) {
            return false;
        }
        synchronized (this) {
            if (accounts.containsKey(k)) return false;
            Account a = new Account();
            a.salt = salt;
            a.hash = hash;
            a.algo = ALGO_PBKDF2;
            if (ip != null && !ip.isEmpty()) a.ips.add(ip);
            accounts.put(k, a);
            return save();
        }
    }

    /**
     * Overwrite (provision/reset) an account, e.g. by console for a friend.
     * Known IPs are forgotten too: whoever had the old credentials must prove
     * the new password from their own address. Without this, provisioning over
     * an attacker's first-registration would leave their address trusted.
     * Returns false if the save failed.
     */
    public synchronized boolean provision(String name, String password) {
        if (name == null || password == null) return false;
        String salt = newSalt();
        String hash;
        try {
            hash = hashPbkdf2(salt, password);
        } catch (IllegalArgumentException e) {
            return false;
        }
        synchronized (this) {
            String k = key(name);
            Account a = accounts.computeIfAbsent(k, x -> new Account());
            a.salt = salt;
            a.hash = hash;
            a.algo = ALGO_PBKDF2;
            a.ips.clear();
            return save();
        }
    }

    public boolean verify(String name, String password) {
        if (name == null || password == null) return false;
        Account snapshot;
        synchronized (this) {
            Account a = accounts.get(key(name));
            if (a == null) return false;
            snapshot = new Account();
            snapshot.salt = a.salt;
            snapshot.hash = a.hash;
            snapshot.algo = a.algo;
        }
        boolean ok;
        boolean legacy = false;
        try {
            if (isPbkdf2(snapshot)) {
                String attempt = hashPbkdf2(snapshot.salt, password);
                ok = constantTimeEqual(attempt, snapshot.hash);
            } else if (snapshot.algo == null || snapshot.algo.isEmpty()) {
                legacy = true;
                String attempt = hashLegacy(snapshot.salt, password);
                ok = constantTimeEqual(attempt, snapshot.hash);
            } else {
                // Unknown future algorithm: fail closed, never try as legacy.
                LOGGER.warn("[SessionAuth] Unknown password algorithm for '{}', denying login.", key(name));
                return false;
            }
        } catch (IllegalArgumentException e) {
            // Malformed salt/parameters: treat as failed login, never throw into the login path.
            return false;
        }
        if (ok && legacy) {
            // Transparent upgrade: legacy passwords re-hashed with PBKDF2 on next good login.
            String salt = newSalt();
            String hash;
            try {
                hash = hashPbkdf2(salt, password);
            } catch (IllegalArgumentException e) {
                return true; // auth succeeded; upgrade can retry next login
            }
            synchronized (this) {
                Account a = accounts.get(key(name));
                if (a != null) {
                    a.salt = salt;
                    a.hash = hash;
                    a.algo = ALGO_PBKDF2;
                    save();
                }
            }
        }
        return ok;
    }

    /**
     * User-initiated password change. Like provisioning, known IPs are forgotten:
     * every device must prove the new password once. Returns false if unknown or save failed.
     */
    public boolean setPassword(String name, String password) {
        if (name == null || password == null) return false;
        String salt = newSalt();
        String hash;
        try {
            hash = hashPbkdf2(salt, password);
        } catch (IllegalArgumentException e) {
            return false;
        }
        synchronized (this) {
            Account a = accounts.get(key(name));
            if (a == null) return false;
            a.salt = salt;
            a.hash = hash;
            a.algo = ALGO_PBKDF2;
            a.ips.clear();
            return save();
        }
    }

    /** Record a successfully-authed IP (LRU-ish, capped at {@code maxIps}). */
    public synchronized void learnIp(String name, String ip, int maxIps) {
        if (name == null) return;
        Account a = accounts.get(key(name));
        if (a == null || ip == null || ip.isEmpty() || a.ips == null) return;
        a.ips.remove(ip);
        a.ips.add(0, ip);
        while (a.ips.size() > Math.max(1, maxIps)) a.ips.remove(a.ips.size() - 1);
        save();
    }

    public synchronized boolean knowsIp(String name, String ip) {
        if (name == null || ip == null || ip.isEmpty()) return false;
        Account a = accounts.get(key(name));
        return a != null && a.ips != null && a.ips.contains(ip);
    }

    public synchronized List<String> ipsOf(String name) {
        if (name == null) return List.of();
        Account a = accounts.get(key(name));
        if (a == null || a.ips == null) return List.of();
        return List.copyOf(a.ips);
    }

    public synchronized boolean isStrict(String name) {
        if (name == null) return false;
        Account a = accounts.get(key(name));
        return a != null && a.strict;
    }

    public synchronized boolean setStrict(String name, boolean strict) {
        if (name == null) return false;
        Account a = accounts.get(key(name));
        if (a == null) return false;
        a.strict = strict;
        save();
        return true;
    }

    /** Forget all IPs: next join from anywhere requires the password. */
    public synchronized boolean resetIps(String name) {
        if (name == null) return false;
        Account a = accounts.get(key(name));
        if (a == null) return false;
        if (a.ips != null) a.ips.clear();
        save();
        return true;
    }

    public synchronized boolean unregister(String name) {
        if (name == null) return false;
        boolean removed = accounts.remove(key(name)) != null;
        if (removed) save();
        return removed;
    }

    // Every caller goes through the purpose-built methods above so invariants
    // (like IP handling on provision) can't be skipped by reaching into accounts.

    private static String key(String name) {
        if (name == null) return "";
        return name.toLowerCase(java.util.Locale.ROOT);
    }

    private static boolean constantTimeEqual(String a, String b) {
        if (a == null || b == null) return false;
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8));
    }

    private static String newSalt() {
        byte[] salt = new byte[16];
        SHARED_RANDOM.nextBytes(salt);
        return HexFormat.of().formatHex(salt);
    }

    private static boolean isPbkdf2(Account a) {
        return ALGO_PBKDF2.equals(a.algo);
    }

    static String hashPbkdf2(String saltHex, String password) {
        final byte[] salt;
        try {
            salt = HexFormat.of().parseHex(saltHex);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("malformed salt", e);
        }
        try {
            PBEKeySpec spec = new PBEKeySpec(
                    password.toCharArray(), salt, PBKDF2_ITERATIONS, PBKDF2_KEY_BITS);
            try {
                byte[] out = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                        .generateSecret(spec).getEncoded();
                return HexFormat.of().formatHex(out);
            } finally {
                spec.clearPassword();
            }
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("PBKDF2 unavailable", e);
        }
    }

    /** Legacy single-round SHA-256, kept only to verify + migrate pre-1.2.0 accounts. */
    static String hashLegacy(String salt, String password) {
        if (salt == null || password == null) throw new IllegalArgumentException("null salt/password");
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] out = md.digest((salt + "\u0000" + password).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(out);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private void load() {
        if (!Files.isRegularFile(file)) {
            LOGGER.info("[SessionAuth] No accounts file yet, starting fresh.");
            return;
        }
        try {
            String text = Files.readString(file, StandardCharsets.UTF_8);
            JsonObject root = JsonParser.parseString(text).getAsJsonObject();
            if (!root.has("players") || !root.get("players").isJsonObject()) {
                throw new IllegalStateException("missing 'players' object");
            }
            JsonObject players = root.getAsJsonObject("players");
            for (Map.Entry<String, com.google.gson.JsonElement> e : players.entrySet()) {
                try {
                    Account a = GSON.fromJson(e.getValue(), Account.class);
                    if (a == null) continue;
                    normalize(a);
                    String k = key(e.getKey());
                    if (accounts.containsKey(k)) {
                        LOGGER.warn("[SessionAuth] Duplicate account key '{}', keeping first.", k);
                        continue;
                    }
                    accounts.put(k, a);
                } catch (Exception ex) {
                    LOGGER.warn("[SessionAuth] Skipping unreadable account '{}': {}", e.getKey(), ex.toString());
                }
            }
            LOGGER.info("[SessionAuth] Loaded {} account(s).", accounts.size());
        } catch (Exception e) {
            // Quarantine the corrupt file so the next save can't destroy the only copy.
            try {
                Path bad = file.resolveSibling(
                        file.getFileName() + ".corrupt-" + System.currentTimeMillis() + ".bak");
                Files.move(file, bad, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                LOGGER.error("[SessionAuth] Accounts file unreadable, quarantined to {} and starting empty: {}",
                        bad.getFileName(), e.toString());
            } catch (Exception moveEx) {
                LOGGER.error("[SessionAuth] Failed to load accounts and failed to quarantine (old file kept): {}",
                        e.toString());
            }
        }
    }

    private static void normalize(Account a) {
        if (a.salt == null) a.salt = "";
        if (a.hash == null) a.hash = "";
        if (a.algo == null) a.algo = "";
        if (a.ips == null) a.ips = new ArrayList<>();
        a.ips.removeIf(ip -> ip == null);
    }

    /** Persists the store. Returns false (and keeps memory) if the write failed. */
    public synchronized boolean save() {
        try {
            JsonObject root = new JsonObject();
            JsonObject players = new JsonObject();
            for (Map.Entry<String, Account> e : accounts.entrySet()) {
                players.add(e.getKey(), GSON.toJsonTree(e.getValue()));
            }
            root.add("players", players);
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            Files.writeString(tmp, GSON.toJson(root), StandardCharsets.UTF_8);
            try {
                Files.move(tmp, file,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                        java.nio.file.StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException amnse) {
                Files.move(tmp, file, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
            return true;
        } catch (IOException e) {
            LOGGER.error("[SessionAuth] Failed to save accounts: {}", e.toString());
            return false;
        }
    }
}
