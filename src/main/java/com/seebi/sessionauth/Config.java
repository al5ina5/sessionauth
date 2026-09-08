package com.seebi.sessionauth;

import net.neoforged.neoforge.common.ModConfigSpec;

/**
 * Server config file: {@code config/sessionauth-common.toml}.
 * Everything gameplay-affecting lives here so server owners never have
 * to take the mod apart to change a number.
 */
public final class Config {
    private static final ModConfigSpec.Builder BUILDER = new ModConfigSpec.Builder();

    public static final ModConfigSpec.IntValue MIN_PASSWORD_LENGTH = BUILDER
            .comment("Minimum password length for /register, /changepw and provisioned accounts.")
            .defineInRange("minPasswordLength", 4, 1, 128);

    public static final ModConfigSpec.IntValue MAX_KNOWN_IPS = BUILDER
            .comment("How many recent internet addresses are remembered per player for auto-login.",
                    "Oldest entries are forgotten first. Households sharing one address use a single slot.")
            .defineInRange("maxKnownIps", 8, 1, 64);

    public static final ModConfigSpec.BooleanValue AUTO_LOGIN_KNOWN_IP = BUILDER
            .comment("If true, players joining from a remembered address skip the password.",
                    "If false, the password is required on every join (IP memory still recorded).")
            .define("autoLoginKnownIp", true);

    public static final ModConfigSpec.IntValue MAX_LOGIN_ATTEMPTS = BUILDER
            .comment("Wrong passwords allowed per player before a temporary login block.",
                    "0 disables brute-force protection (not recommended on public servers).")
            .defineInRange("maxLoginAttempts", 5, 0, 100);

    public static final ModConfigSpec.IntValue LOGIN_BLOCK_SECONDS = BUILDER
            .comment("How long a name is blocked from logging in after too many wrong passwords.")
            .defineInRange("loginBlockSeconds", 600, 30, 86400);

    public static final ModConfigSpec.IntValue LOGIN_REMINDER_SECONDS = BUILDER
            .comment("Frozen players are re-told how to log in every this many seconds.",
                    "0 disables the reminder (they only see hints when they try to act).")
            .defineInRange("loginReminderSeconds", 20, 0, 3600);

    static final ModConfigSpec SPEC = BUILDER.build();

    private Config() {
    }
}
