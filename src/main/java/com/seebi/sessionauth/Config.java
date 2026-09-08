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

    static final ModConfigSpec SPEC = BUILDER.build();

    private Config() {
    }
}
