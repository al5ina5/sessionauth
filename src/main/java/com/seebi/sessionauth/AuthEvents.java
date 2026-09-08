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

        d.register(LiteralArgumentBuilder.<CommandSourceStack>literal("changepw")
                .requires(src -> src.getEntity() instanceof ServerPlayer)
                .then(Commands.argument("old", StringArgumentType.greedyString())
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
                    info(p, "Logged out. Use /login to log back in.");
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
                                    store.provision(name, pw);
                                    ctx.getSource().sendSuccess(
                                            () -> Component.literal("Account '" + name + "' provisioned. Give them the password out-of-band."), true);
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
                            var p = ctx.getSource().getServer().getPlayerList().getPlayerByName(name);
                            if (p != null) authed.remove(p.getUUID());
                            ctx.getSource().sendSuccess(
                                    () -> Component.literal("'" + name + "' will need their password on next join (all known IPs forgotten)."), true);
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
                            ctx.getSource().sendSuccess(() -> Component.literal("Account '" + name + "' deleted."), true);
                            return 1;
                        })));

        admin.then(Commands.literal("ips")
                .then(Commands.argument("player", StringArgumentType.word())
                        .executes(ctx -> {
                            String name = StringArgumentType.getString(ctx, "player");
                            ctx.getSource().sendSuccess(
                                    () -> Component.literal("Known IPs for '" + name + "': " + store.ipsOf(name)), false);
                            return 1;
                        })));

        admin.then(Commands.literal("strict")
                .then(Commands.argument("player", StringArgumentType.word())
                        .then(Commands.argument("value", StringArgumentType.word())
                                .executes(ctx -> {
                                    String name = StringArgumentType.getString(ctx, "player");
                                    boolean v = Boolean.parseBoolean(StringArgumentType.getString(ctx, "value"));
                                    if (!store.setStrict(name, v)) {
                                        ctx.getSource().sendFailure(Component.literal("No account '" + name + "'."));
                                        return 0;
                                    }
                                    ctx.getSource().sendSuccess(
                                            () -> Component.literal("'" + name + "' strict mode = " + v + " (always require password)."), true);
                                    return 1;
                                }))));

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
        store.register(name, pw, ipOf(p));
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
        if (!store.verify(name, pw)) {
            warn(p, "Wrong password.");
            return 0;
        }
        store.learnIp(name, ipOf(p), Config.MAX_KNOWN_IPS.get());
        markAuthed(p);
        info(p, "Login successful — have fun!");
        return 1;
    }

    private int cmdChangePw(ServerPlayer p, String oldPw, String newPw) {
        String name = p.getGameProfile().name();
        if (!isAuthed(p)) {
            warn(p, "Log in first.");
            return 0;
        }
        if (!store.verify(name, oldPw)) {
            warn(p, "Current password is wrong.");
            return 0;
        }
        if (newPw.length() < Config.MIN_PASSWORD_LENGTH.get()) {
            warn(p, "New password too short — minimum " + Config.MIN_PASSWORD_LENGTH.get() + " characters.");
            return 0;
        }
        store.setPassword(name, newPw);
        info(p, "Password changed.");
        return 1;
    }

    // ---------------- login flow ----------------

    @SubscribeEvent
    public void onPlayerLogin(PlayerEvent.PlayerLoggedInEvent event) {
        if (!(event.getEntity() instanceof ServerPlayer p)) return;
        String name = p.getGameProfile().name();
        String ip = ipOf(p);
        lockPos.put(p.getUUID(), new double[]{p.getX(), p.getY(), p.getZ()});

        if (!store.exists(name)) {
            p.sendSystemMessage(Component.literal("Welcome! Protect your name: /register <password>").withColor(0xFFFF55));
            p.sendSystemMessage(Component.literal("Pick any password, min " + Config.MIN_PASSWORD_LENGTH.get() + " characters.").withColor(0xFFFF55));
            return;
        }
        if (Config.AUTO_LOGIN_KNOWN_IP.get() && !store.isStrict(name) && store.knowsIp(name, ip)) {
            markAuthed(p);
            info(p, "Recognized address — logged in automatically.");
            return;
        }
        p.sendSystemMessage(Component.literal("New internet address — please /login <password>.").withColor(0xFFFF55));
    }

    @SubscribeEvent
    public void onPlayerLogout(PlayerEvent.PlayerLoggedOutEvent event) {
        if (event.getEntity() instanceof ServerPlayer p) {
            authed.remove(p.getUUID());
            lockPos.remove(p.getUUID());
            lastWarn.remove(p.getUUID());
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
        double dx = p.getX() - lock[0], dy = p.getY() - lock[1], dz = p.getZ() - lock[2];
        if (dx * dx + dy * dy + dz * dz > 0.0625) {
            p.teleportTo(lock[0], lock[1], lock[2]);
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
}
