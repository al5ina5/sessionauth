package com.seebi.sessionauth;

import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.builder.LiteralArgumentBuilder;
import com.mojang.logging.LogUtils;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.network.chat.Component;
import net.minecraft.server.level.ServerPlayer;
import net.neoforged.bus.api.SubscribeEvent;
import net.neoforged.neoforge.event.RegisterCommandsEvent;
import net.neoforged.neoforge.event.ServerChatEvent;
import net.neoforged.neoforge.event.CommandEvent;
import net.neoforged.neoforge.event.entity.item.ItemTossEvent;
import net.neoforged.neoforge.event.entity.living.LivingIncomingDamageEvent;
import net.neoforged.neoforge.event.entity.player.ItemEntityPickupEvent;
import net.neoforged.neoforge.event.entity.player.PlayerEvent;
import net.neoforged.neoforge.event.entity.player.PlayerInteractEvent;
import net.neoforged.neoforge.event.server.ServerStoppingEvent;
import net.neoforged.neoforge.event.tick.PlayerTickEvent;
import net.minecraft.server.players.NameAndId;
import org.slf4j.Logger;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Login flow + freeze enforcement.
 * <p>
 * Unauthenticated players cannot chat, run commands (except the auth ones),
 * interact, move, take or deal damage, or pick up / drop items — so a
 * name-mimic gets exactly nowhere.
 */
public final class AuthEvents {
    private static final Logger LOGGER = LogUtils.getLogger();

    private final AuthStore store;
    private final Set<UUID> authed = ConcurrentHashMap.newKeySet();
    private final Map<UUID, double[]> lockPos = new ConcurrentHashMap<>();
    private final Map<UUID, Long> lastWarn = new ConcurrentHashMap<>();
    private final Map<UUID, Long> lastNag = new ConcurrentHashMap<>();
    // Brute-force protection (in-memory; a restart clears them — acceptable,
    // the store itself is the persistent part).
    private final Map<String, long[]> failures = new ConcurrentHashMap<>(); // key -> {count, windowStartSec}
    private final Map<String, Long> blockedUntil = new ConcurrentHashMap<>(); // key -> epoch millis
    /** Wrong-attempt window: failures older than this reset the counter. */
    private static final long FAILURE_WINDOW_SECONDS = 300;

    public AuthEvents(AuthStore store) {
        this.store = store;
    }

    // ---------------- helpers ----------------

    public static String ipOf(ServerPlayer player) {
        try {
            SocketAddress addr = player.connection.getRemoteAddress();
            if (addr instanceof InetSocketAddress isa && isa.getAddress() != null) {
                String host = isa.getAddress().getHostAddress();
                int pct = host.indexOf('%'); // strip IPv6 scope id
                return pct >= 0 ? host.substring(0, pct) : host;
            }
        } catch (Exception e) {
            LOGGER.debug("[SessionAuth] Could not read player IP: {}", e.toString());
        }
        return "";
    }

    private boolean isAuthed(ServerPlayer player) {
        return authed.contains(player.getUUID());
    }

    private void markAuthed(ServerPlayer player) {
        authed.add(player.getUUID());
        lockPos.remove(player.getUUID());
        lastNag.remove(player.getUUID());
    }

    private void warn(ServerPlayer player, String msg) {
        long now = System.currentTimeMillis();
        Long last = lastWarn.get(player.getUUID());
        if (last != null && now - last < 3000) return;
        lastWarn.put(player.getUUID(), now);
        player.sendSystemMessage(Component.literal(msg).withColor(0xFF5555));
    }

    private void info(ServerPlayer player, String msg) {
        player.sendSystemMessage(Component.literal(msg).withColor(0x55FF55));
    }

    // ---------------- brute-force protection ----------------

    private static String blockKey(String name) {
        return name.toLowerCase(java.util.Locale.ROOT);
    }

    /** Epoch millis until which this name may not log in, or 0. */
    private long blockedUntil(String name) {
        if (name == null) return 0;
        purgeExpiredBlocks();
        Long until = blockedUntil.get(blockKey(name));
        if (until == null) return 0;
        if (until < System.currentTimeMillis()) {
            blockedUntil.remove(blockKey(name));
            failures.remove(blockKey(name));
            return 0;
        }
        return until;
    }

    private void clearBlocks(String name) {
        if (name == null) return;
        failures.remove(blockKey(name));
        blockedUntil.remove(blockKey(name));
    }

    /** Drop expired blocks/failures so name-enumeration can't grow the maps unbounded. */
    private void purgeExpiredBlocks() {
        long now = System.currentTimeMillis();
        blockedUntil.entrySet().removeIf(e -> e.getValue() == null || e.getValue() < now);
        if (failures.size() > 1024) {
            long nowSec = now / 1000;
            failures.entrySet().removeIf(e ->
                    e.getValue() == null || nowSec - e.getValue()[1] > FAILURE_WINDOW_SECONDS);
        }
    }

    /** 600 -> "10m", 90 -> "90s", 3600 -> "1h" for player-facing kick messages. */
    private static String formatDuration(long totalSeconds) {
        if (totalSeconds < 90) return totalSeconds + "s";
        if (totalSeconds < 5400) return (totalSeconds / 60) + "m";
        return (totalSeconds / 3600) + "h";
    }

    /**
     * Records a wrong password. Returns attempts remaining before a block,
     * or -1 if this attempt tripped the limit and the name is now blocked.
     */
    private int recordFailure(String name) {
        int max = Config.MAX_LOGIN_ATTEMPTS.get();
        if (max <= 0) return Integer.MAX_VALUE;
        String k = blockKey(name);
        purgeExpiredBlocks();
        long nowSec = System.currentTimeMillis() / 1000;
        long[] slot = failures.get(k);
        if (slot == null || nowSec - slot[1] > FAILURE_WINDOW_SECONDS) slot = new long[]{0, nowSec};
        slot[0]++;
        slot[1] = nowSec;
        if (slot[0] >= max) {
            blockedUntil.put(k, System.currentTimeMillis() + Config.LOGIN_BLOCK_SECONDS.get() * 1000L);
            failures.remove(k);
            return -1;
        }
        failures.put(k, slot);
        return max - (int) slot[0];
    }

    // ---------------- commands ----------------

    @SubscribeEvent
    public void onRegisterCommands(RegisterCommandsEvent event) {
        var d = event.getDispatcher();

        d.register(LiteralArgumentBuilder.<CommandSourceStack>literal("register")
                .requires(src -> src.getEntity() instanceof ServerPlayer)
                .then(Commands.argument("password", StringArgumentType.greedyString())
                        .executes(ctx -> {
                            ServerPlayer p = (ServerPlayer) ctx.getSource().getEntityOrException();
                            String pw = StringArgumentType.getString(ctx, "password").trim();
                            return cmdRegister(p, pw);
                        })));

        d.register(LiteralArgumentBuilder.<CommandSourceStack>literal("login")
                .requires(src -> src.getEntity() instanceof ServerPlayer)
                .then(Commands.argument("password", StringArgumentType.greedyString())
                        .executes(ctx -> {
                            ServerPlayer p = (ServerPlayer) ctx.getSource().getEntityOrException();
                            String pw = StringArgumentType.getString(ctx, "password").trim();
                            return cmdLogin(p, pw);
                        })));

        // NOTE: first arg stays a single word (a greedy first arg would swallow
        // the whole input and the second arg could never parse). The new
        // password is greedy so it may contain spaces; old passwords containing
        // spaces must be reset by an admin (provision) instead.
        d.register(LiteralArgumentBuilder.<CommandSourceStack>literal("changepw")
                .requires(src -> src.getEntity() instanceof ServerPlayer)
                .then(Commands.argument("old", StringArgumentType.word())
                        .then(Commands.argument("new", StringArgumentType.greedyString())
                                .executes(ctx -> {
                                    ServerPlayer p = (ServerPlayer) ctx.getSource().getEntityOrException();
                                    return cmdChangePw(p,
                                            StringArgumentType.getString(ctx, "old").trim(),
                                            StringArgumentType.getString(ctx, "new").trim());
                                }))));

        d.register(LiteralArgumentBuilder.<CommandSourceStack>literal("logout")
                .requires(src -> src.getEntity() instanceof ServerPlayer)
                .executes(ctx -> {
                    ServerPlayer p = (ServerPlayer) ctx.getSource().getEntityOrException();
                    authed.remove(p.getUUID());
                    lockPos.put(p.getUUID(), new double[]{p.getX(), p.getY(), p.getZ()});
                    lastNag.put(p.getUUID(), System.currentTimeMillis());
                    info(p, "Logged out. Use /login to log back in.");
                    prompt(p);
                    return 1;
                }));

        // ---- admin (server ops + console). Command blocks can already do
        // anything an op can, so entity-less sources are trusted.
        var admin = LiteralArgumentBuilder.<CommandSourceStack>literal("authadmin")
                .requires(AuthEvents::isOp);

        admin.then(Commands.literal("provision")
                .then(Commands.argument("player", StringArgumentType.word())
                        .then(Commands.argument("password", StringArgumentType.greedyString())
                                .executes(ctx -> {
                                    String name = StringArgumentType.getString(ctx, "player");
                                    String pw = StringArgumentType.getString(ctx, "password").trim();
                                    if (pw.length() < Config.MIN_PASSWORD_LENGTH.get()) {
                                        ctx.getSource().sendFailure(Component.literal("Password too short (min " + Config.MIN_PASSWORD_LENGTH.get() + ")."));
                                        return 0;
                                    }
                                    if (!store.provision(name, pw)) {
                                        ctx.getSource().sendFailure(Component.literal("Could not save account '" + name + "'. Check server logs."));
                                        return 0;
                                    }
                                    clearBlocks(name);
                                    deauthOnline(ctx.getSource(), name);
                                    ctx.getSource().sendSuccess(
                                            () -> Component.literal("Account '" + name + "' provisioned (known IPs forgotten, blocks cleared). Give them the password out-of-band."), true);
                                    return 1;
                                }))));

        admin.then(Commands.literal("reset")
                .then(Commands.argument("player", StringArgumentType.word())
                        .executes(ctx -> {
                            String name = StringArgumentType.getString(ctx, "player");
                            if (!store.exists(name)) {
                                ctx.getSource().sendFailure(Component.literal("No account '" + name + "'."));
                                return 0;
                            }
                            store.resetIps(name);
                            clearBlocks(name);
                            // Case-insensitive: getPlayerByName casing is unreliable,
                            // and the mimicking session may use odd caps.
                            for (ServerPlayer p : ctx.getSource().getServer().getPlayerList().getPlayers()) {
                                if (p.getGameProfile().name().equalsIgnoreCase(name)) {
                                    authed.remove(p.getUUID());
                                }
                            }
                            ctx.getSource().sendSuccess(
                                    () -> Component.literal("'" + name + "' will need their password on next join (known IPs forgotten, blocks cleared)."), true);
                            return 1;
                        })));

        admin.then(Commands.literal("unregister")
                .then(Commands.argument("player", StringArgumentType.word())
                        .executes(ctx -> {
                            String name = StringArgumentType.getString(ctx, "player");
                            if (!store.unregister(name)) {
                                ctx.getSource().sendFailure(Component.literal("No account '" + name + "'."));
                                return 0;
                            }
                            clearBlocks(name);
                            deauthOnline(ctx.getSource(), name);
                            ctx.getSource().sendSuccess(() -> Component.literal("Account '" + name + "' deleted (online session de-authed)."), true);
                            return 1;
                        })));

        admin.then(Commands.literal("ips")
                .then(Commands.argument("player", StringArgumentType.word())
                        .executes(ctx -> {
                            String name = StringArgumentType.getString(ctx, "player");
                            if (!store.exists(name)) {
                                ctx.getSource().sendFailure(Component.literal("No account '" + name + "'."));
                                return 0;
                            }
                            ctx.getSource().sendSuccess(
                                    () -> Component.literal("Known IPs for '" + name + "': " + store.ipsOf(name)), false);
                            return 1;
                        })));

        admin.then(Commands.literal("strict")
                .then(Commands.argument("player", StringArgumentType.word())
                        .then(Commands.argument("value", StringArgumentType.word())
                                .executes(ctx -> {
                                    String name = StringArgumentType.getString(ctx, "player");
                                    if (!store.exists(name)) {
                                        ctx.getSource().sendFailure(Component.literal("No account '" + name + "'."));
                                        return 0;
                                    }
                                    String raw = StringArgumentType.getString(ctx, "value");
                                    if (!raw.equalsIgnoreCase("true") && !raw.equalsIgnoreCase("false")) {
                                        ctx.getSource().sendFailure(Component.literal("Value must be true or false."));
                                        return 0;
                                    }
                                    boolean v = Boolean.parseBoolean(raw);
                                    store.setStrict(name, v);
                                    ctx.getSource().sendSuccess(
                                            () -> Component.literal("'" + name + "' strict mode = " + v + " (always require password)."), true);
                                    return 1;
                                }))));

        admin.then(Commands.literal("help")
                .executes(ctx -> {
                    var src = ctx.getSource();
                    src.sendSuccess(() -> Component.literal("SessionAuth admin: provision, reset, unregister, ips, strict, help"), false);
                    src.sendSuccess(() -> Component.literal("provision <player> <pw> — (re)create account, forgets known IPs"), false);
                    src.sendSuccess(() -> Component.literal("reset <player> — forget known IPs AND clear login blocks"), false);
                    src.sendSuccess(() -> Component.literal("unregister <player> — delete account entirely"), false);
                    src.sendSuccess(() -> Component.literal("ips <player> — list remembered addresses"), false);
                    src.sendSuccess(() -> Component.literal("strict <player> <true|false> — always require password"), false);
                    return 1;
                }));

        d.register(admin);
        // NOTE: keep slash-command names out of log messages — the log mask
        // drops any line containing them (fail-closed by design).
        LOGGER.info("[SessionAuth] auth commands registered (register, login, changepw, logout, authadmin)");
    }

    private static boolean isOp(CommandSourceStack src) {
        if (src.getEntity() instanceof ServerPlayer p) {
            return src.getServer().getPlayerList()
                    .isOp(new NameAndId(p.getUUID(), p.getGameProfile().name()));
        }
        return !src.isPlayer(); // console / RCON
    }

    /** Drop the live session for every online player matching a name (case-insensitive). */
    private void deauthOnline(CommandSourceStack src, String name) {
        for (ServerPlayer p : src.getServer().getPlayerList().getPlayers()) {
            if (p.getGameProfile().name().equalsIgnoreCase(name)) {
                authed.remove(p.getUUID());
                lockPos.put(p.getUUID(), new double[]{p.getX(), p.getY(), p.getZ()});
            }
        }
    }

    private int cmdRegister(ServerPlayer p, String pw) {
        String name = p.getGameProfile().name();
        if (store.exists(name)) {
            warn(p, "This name is already registered. Use /login <password>.");
            return 0;
        }
        if (pw.length() < Config.MIN_PASSWORD_LENGTH.get()) {
            warn(p, "Password too short — minimum " + Config.MIN_PASSWORD_LENGTH.get() + " characters.");
            return 0;
        }
        if (!store.register(name, pw, ipOf(p))) {
            warn(p, "Could not save account. Ask an admin to check server logs.");
            return 0;
        }
        markAuthed(p);
        info(p, "Registered! From your usual internet address you will log in automatically.");
        info(p, "If your address changes, just /login <password> once.");
        return 1;
    }

    private int cmdLogin(ServerPlayer p, String pw) {
        String name = p.getGameProfile().name();
        if (isAuthed(p)) {
            info(p, "You are already logged in.");
            return 1;
        }
        if (!store.exists(name)) {
            warn(p, "This name is not registered yet. Use /register <password>.");
            return 0;
        }
        long blocked = blockedUntil(name);
        if (blocked > 0) {
            long secs = (blocked - System.currentTimeMillis() + 999) / 1000;
            warn(p, "Too many wrong passwords. Try again in " + formatDuration(secs) + ".");
            return 0;
        }
        if (!store.verify(name, pw)) {
            int left = recordFailure(name);
            if (left < 0) {
                p.connection.disconnect(Component.literal(
                        "Too many wrong passwords. Try again in " + formatDuration(Config.LOGIN_BLOCK_SECONDS.get()) + "."));
            } else if (left == Integer.MAX_VALUE) {
                warn(p, "Wrong password.");
            } else {
                warn(p, "Wrong password. " + left + " attempt(s) left before a temporary block.");
            }
            return 0;
        }
        clearBlocks(name);
        store.learnIp(name, ipOf(p), Config.MAX_KNOWN_IPS.get());
        markAuthed(p);
        info(p, "Login successful — have fun!");
        if (pw.length() < Config.MIN_PASSWORD_LENGTH.get()) {
            warn(p, "Your password is shorter than the current minimum ("
                    + Config.MIN_PASSWORD_LENGTH.get() + "). Change it with /changepw <old> <new>.");
        }
        return 1;
    }

    private int cmdChangePw(ServerPlayer p, String oldPw, String newPw) {
        String name = p.getGameProfile().name();
        if (!isAuthed(p)) {
            warn(p, "Log in first: /login <password>");
            return 0;
        }
        long blocked = blockedUntil(name);
        if (blocked > 0) {
            long secs = (blocked - System.currentTimeMillis() + 999) / 1000;
            warn(p, "Too many wrong passwords. Try again in " + formatDuration(secs) + ".");
            return 0;
        }
        if (!store.verify(name, oldPw)) {
            int left = recordFailure(name);
            if (left < 0) {
                p.connection.disconnect(Component.literal(
                        "Too many wrong passwords. Try again in " + formatDuration(Config.LOGIN_BLOCK_SECONDS.get()) + "."));
            } else {
                warn(p, "Current password is wrong.");
            }
            return 0;
        }
        if (newPw.length() < Config.MIN_PASSWORD_LENGTH.get()) {
            warn(p, "New password too short — minimum " + Config.MIN_PASSWORD_LENGTH.get() + " characters.");
            return 0;
        }
        clearBlocks(name);
        if (!store.setPassword(name, newPw)) {
            warn(p, "Could not save new password. Ask an admin to check server logs.");
            return 0;
        }
        info(p, "Password changed. Known addresses were forgotten — you'll confirm it once on next join.");
        return 1;
    }

    // ---------------- login flow ----------------

    @SubscribeEvent
    public void onPlayerLogin(PlayerEvent.PlayerLoggedInEvent event) {
        if (!(event.getEntity() instanceof ServerPlayer p)) return;
        String name = p.getGameProfile().name();
        String ip = ipOf(p);
        // Never inherit a stale session: a previous crash/kick may have skipped logout cleanup.
        authed.remove(p.getUUID());

        long blocked = blockedUntil(name);
        if (blocked > 0) {
            long secs = (blocked - System.currentTimeMillis() + 999) / 1000;
            lockPos.put(p.getUUID(), new double[]{p.getX(), p.getY(), p.getZ()});
            p.connection.disconnect(Component.literal(
                    "Too many wrong passwords. Try again in " + formatDuration(secs) + "."));
            lockPos.remove(p.getUUID());
            lastNag.remove(p.getUUID());
            return;
        }
        lockPos.put(p.getUUID(), new double[]{p.getX(), p.getY(), p.getZ()});

        if (!store.exists(name)) {
            prompt(p);
            return;
        }
        if (!ip.isEmpty() && Config.AUTO_LOGIN_KNOWN_IP.get() && !store.isStrict(name) && store.knowsIp(name, ip)) {
            markAuthed(p);
            info(p, "Recognized address — logged in automatically.");
            return;
        }
        prompt(p);
    }

    /**
     * The single login prompt, shown centered above the hotbar (action bar)
     * instead of chat — one line for new and returning players alike.
     */
    private void prompt(ServerPlayer player) {
        player.sendOverlayMessage(Component.literal(
                "First visit? /register <password>   ·   Returning? /login <password>")
                .withColor(0xFFFF55));
        lastNag.put(player.getUUID(), System.currentTimeMillis());
    }

    @SubscribeEvent
    public void onPlayerLogout(PlayerEvent.PlayerLoggedOutEvent event) {
        if (event.getEntity() instanceof ServerPlayer p) {
            authed.remove(p.getUUID());
            lockPos.remove(p.getUUID());
            lastWarn.remove(p.getUUID());
            lastNag.remove(p.getUUID());
        }
    }

    @SubscribeEvent
    public void onServerStopping(ServerStoppingEvent event) {
        store.save();
    }

    // ---------------- freeze ----------------

    @SubscribeEvent
    public void onChat(ServerChatEvent event) {
        if (event.getPlayer() instanceof ServerPlayer p && !isAuthed(p)) {
            event.setCanceled(true);
            warn(p, "Log in first: /login <password>  (new here? /register <password>)");
        }
    }

    @SubscribeEvent
    public void onCommand(CommandEvent event) {
        CommandSourceStack src;
        try {
            src = event.getParseResults().getContext().getSource();
        } catch (Exception ignored) {
            return;
        }
        if (!(src.getEntity() instanceof ServerPlayer p)) return;
        if (isAuthed(p)) return;
        String raw = "";
        try {
            raw = event.getParseResults().getReader().getString().trim();
        } catch (Exception ignored) {
        }
        if (raw.startsWith("/")) raw = raw.substring(1);
        String root = raw.contains(" ") ? raw.substring(0, raw.indexOf(' ')) : raw;
        // Bukkit-style namespaced form: "minecraft:login" etc.
        if (root.contains(":")) root = root.substring(root.indexOf(':') + 1);
        if (root.equals("register") || root.equals("login") || root.equals("changepw") || root.equals("logout")) return;
        event.setCanceled(true);
        warn(p, "Log in first: /login <password>  (new here? /register <password>)");
    }

    private boolean frozen(ServerPlayer p) {
        return !isAuthed(p);
    }

    // One small handler per interaction type (the base PlayerInteractEvent is
    // abstract, so it can't take a subscription itself).
    @SubscribeEvent
    public void onRightClickBlock(PlayerInteractEvent.RightClickBlock event) {
        if (event.getEntity() instanceof ServerPlayer p && frozen(p)) event.setCanceled(true);
    }

    @SubscribeEvent
    public void onLeftClickBlock(PlayerInteractEvent.LeftClickBlock event) {
        if (event.getEntity() instanceof ServerPlayer p && frozen(p)) event.setCanceled(true);
    }

    @SubscribeEvent
    public void onRightClickItem(PlayerInteractEvent.RightClickItem event) {
        if (event.getEntity() instanceof ServerPlayer p && frozen(p)) event.setCanceled(true);
    }

    @SubscribeEvent
    public void onEntityInteract(PlayerInteractEvent.EntityInteract event) {
        if (event.getEntity() instanceof ServerPlayer p && frozen(p)) event.setCanceled(true);
    }

    @SubscribeEvent
    public void onEntityInteractSpecific(PlayerInteractEvent.EntityInteractSpecific event) {
        if (event.getEntity() instanceof ServerPlayer p && frozen(p)) event.setCanceled(true);
    }

    @SubscribeEvent
    public void onPlayerTick(PlayerTickEvent.Pre event) {
        if (!(event.getEntity() instanceof ServerPlayer p)) return;
        if (!frozen(p)) return;
        if (p.level().isClientSide()) return;
        double[] lock = lockPos.get(p.getUUID());
        if (lock == null) {
            lockPos.put(p.getUUID(), new double[]{p.getX(), p.getY(), p.getZ()});
            return;
        }
        // Kill momentum (flight/elytra/fall) so rubber-banding can't be used to scout or fight the lock.
        try {
            p.setDeltaMovement(net.minecraft.world.phys.Vec3.ZERO);
        } catch (Exception ignored) {
        }
        double dx = p.getX() - lock[0], dy = p.getY() - lock[1], dz = p.getZ() - lock[2];
        if (dx * dx + dy * dy + dz * dz > 0.0625) {
            p.teleportTo(lock[0], lock[1], lock[2]);
        }
        // Action bars fade after a couple of seconds, so re-show the prompt
        // continuously while frozen — it stays until the player logs in.
        long now = System.currentTimeMillis();
        Long last = lastNag.get(p.getUUID());
        if (last == null || now - last > 2000) {
            lastNag.put(p.getUUID(), now);
            p.sendOverlayMessage(Component.literal(
                    "First visit? /register <password>   ·   Returning? /login <password>")
                    .withColor(0xFFFF55));
        }
    }

    @SubscribeEvent
    public void onAttack(LivingIncomingDamageEvent event) {
        // victim frozen -> immune
        if (event.getEntity() instanceof ServerPlayer victim && frozen(victim)) {
            event.setCanceled(true);
            return;
        }
        // attacker frozen -> cannot hurt anything
        if (event.getSource().getEntity() instanceof ServerPlayer attacker && frozen(attacker)) {
            event.setCanceled(true);
        }
    }

    @SubscribeEvent
    public void onPickup(ItemEntityPickupEvent.Pre event) {
        if (event.getPlayer() instanceof ServerPlayer p && frozen(p)) {
            event.setCanPickup(net.minecraft.util.TriState.FALSE);
        }
    }

    @SubscribeEvent
    public void onToss(ItemTossEvent event) {
        if (event.getPlayer() instanceof ServerPlayer p && frozen(p)) event.setCanceled(true);
    }

    @SubscribeEvent
    public void onBreakSpeed(PlayerEvent.BreakSpeed event) {
        if (event.getEntity() instanceof ServerPlayer p && frozen(p)) event.setNewSpeed(0f);
    }

    @SubscribeEvent
    public void onHarvestCheck(PlayerEvent.HarvestCheck event) {
        if (event.getEntity() instanceof ServerPlayer p && frozen(p)) event.setCanHarvest(false);
    }

    @SubscribeEvent
    public void onContainerOpen(net.neoforged.neoforge.event.entity.player.PlayerContainerEvent.Open event) {
        if (event.getEntity() instanceof ServerPlayer p && frozen(p)) {
            try {
                p.closeContainer();
            } catch (Exception ignored) {
            }
        }
    }
}
