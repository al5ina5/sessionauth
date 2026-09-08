package com.seebi.sessionauth;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.mojang.logging.LogUtils;
import org.slf4j.Logger;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Password + known-IP store, persisted as JSON in the server game directory.
 * One record per (lowercased) player name. Multiple names may share one IP
 * (households) — records are fully independent, so housemates can never
 * lock each other out.
 */
public final class AuthStore {
    private static final Logger LOGGER = LogUtils.getLogger();
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    private final Path file;
    private final Map<String, Account> accounts = new ConcurrentHashMap<>();

    public AuthStore(Path gameDir) {
        this.file = gameDir.resolve("sessionauth-accounts.json");
        load();
    }

    public static final class Account {
        String salt = "";
        String hash = "";
        final List<String> ips = new ArrayList<>();
        boolean strict = false; // true = always require password, even from known IPs
    }

    public synchronized boolean exists(String name) {
        return accounts.containsKey(key(name));
    }

    /** Create a new account. Returns false if it already exists. */
    public synchronized boolean register(String name, String password, String ip) {
        String k = key(name);
        if (accounts.containsKey(k)) return false;
        Account a = new Account();
        a.salt = newSalt();
        a.hash = hash(a.salt, password);
        if (ip != null && !ip.isEmpty()) a.ips.add(ip);
        accounts.put(k, a);
        save();
        return true;
    }

    /**
     * Overwrite (provision/reset) an account, e.g. by console for a friend.
     * Known IPs are forgotten too: whoever had the old credentials must prove
     * the new password from their own address. Without this, provisioning over
     * an attacker's first-registration would leave their address trusted.
     */
    public synchronized void provision(String name, String password) {
        String k = key(name);
        Account a = accounts.computeIfAbsent(k, x -> new Account());
        a.salt = newSalt();
        a.hash = hash(a.salt, password);
        a.ips.clear();
        save();
    }

    public synchronized boolean verify(String name, String password) {
        Account a = accounts.get(key(name));
        if (a == null) return false;
        String attempt = hash(a.salt, password);
        return MessageDigest.isEqual(
                attempt.getBytes(StandardCharsets.UTF_8),
                a.hash.getBytes(StandardCharsets.UTF_8));
    }

    public synchronized boolean setPassword(String name, String password) {
        Account a = accounts.get(key(name));
        if (a == null) return false;
        a.salt = newSalt();
        a.hash = hash(a.salt, password);
        save();
        return true;
    }

    /** Record a successfully-authed IP (LRU-ish, capped at {@code maxIps}). */
    public synchronized void learnIp(String name, String ip, int maxIps) {
        Account a = accounts.get(key(name));
        if (a == null || ip == null || ip.isEmpty()) return;
        a.ips.remove(ip);
        a.ips.add(0, ip);
        while (a.ips.size() > Math.max(1, maxIps)) a.ips.remove(a.ips.size() - 1);
        save();
    }

    public synchronized boolean knowsIp(String name, String ip) {
        Account a = accounts.get(key(name));
        return a != null && ip != null && a.ips.contains(ip);
    }

    public synchronized List<String> ipsOf(String name) {
        Account a = accounts.get(key(name));
        return a == null ? List.of() : List.copyOf(a.ips);
    }

    public synchronized boolean isStrict(String name) {
        Account a = accounts.get(key(name));
        return a != null && a.strict;
    }

    public synchronized boolean setStrict(String name, boolean strict) {
        Account a = accounts.get(key(name));
        if (a == null) return false;
        a.strict = strict;
        save();
        return true;
    }

    /** Forget all IPs: next join from anywhere requires the password. */
    public synchronized boolean resetIps(String name) {
        Account a = accounts.get(key(name));
        if (a == null) return false;
        a.ips.clear();
        save();
        return true;
    }

    public synchronized boolean unregister(String name) {
        boolean removed = accounts.remove(key(name)) != null;
        if (removed) save();
        return removed;
    }

    // Every caller goes through the purpose-built methods above so invariants
    // (like IP handling on provision) can't be skipped by reaching into accounts.

    private static String key(String name) {
        return name.toLowerCase(java.util.Locale.ROOT);
    }

    private static String newSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return HexFormat.of().formatHex(salt);
    }

    static String hash(String salt, String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] out = md.digest((salt + "\u0000" + password).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(out);
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
            JsonObject players = root.has("players") ? root.getAsJsonObject("players") : root;
            for (Map.Entry<String, com.google.gson.JsonElement> e : players.entrySet()) {
                try {
                    Account a = GSON.fromJson(e.getValue(), Account.class);
                    if (a != null) accounts.put(key(e.getKey()), a);
                } catch (Exception ex) {
                    LOGGER.warn("[SessionAuth] Skipping unreadable account '{}': {}", e.getKey(), ex.toString());
                }
            }
            LOGGER.info("[SessionAuth] Loaded {} account(s).", accounts.size());
        } catch (Exception e) {
            LOGGER.error("[SessionAuth] Failed to load accounts, starting empty (old file kept): {}", e.toString());
        }
    }

    public synchronized void save() {
        try {
            JsonObject root = new JsonObject();
            JsonObject players = new JsonObject();
            for (Map.Entry<String, Account> e : accounts.entrySet()) {
                players.add(e.getKey(), GSON.toJsonTree(e.getValue()));
            }
            root.add("players", players);
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            Files.writeString(tmp, GSON.toJson(root), StandardCharsets.UTF_8);
            Files.move(tmp, file,
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            LOGGER.error("[SessionAuth] Failed to save accounts: {}", e.toString());
        }
    }
}
