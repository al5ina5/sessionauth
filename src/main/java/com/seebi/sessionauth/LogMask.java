package com.seebi.sessionauth;

import com.mojang.logging.LogUtils;
import net.neoforged.api.distmarker.Dist;
import net.neoforged.fml.loading.FMLEnvironment;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Filter;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.filter.RegexFilter;
import org.slf4j.Logger;

/**
 * Drops any log line that looks like it contains an auth password
 * (e.g. a player typing {@code /login hunter2}, or a syntax-error echo of
 * what they typed). Everything else keeps logging normally — unlike the
 * {@code logAdminCommands} gamerule, which is all-or-nothing.
 * <p>
 * Server-side only; never installed on clients.
 */
public final class LogMask {
    private static final Logger LOGGER = LogUtils.getLogger();
    private static boolean installed = false;

    /**
     * Matches any line that could contain a password: the player commands,
     * plus console/RCON provisioning (which takes a password argument but
     * has no leading slash in the command name).
     */
    private static final String PATTERN =
            ".*/(register|login|changepw)\\b.*|.*authadmin\\s+provision\\b.*";

    public static synchronized void install() {
        if (installed) return;
        installed = true;
        if (FMLEnvironment.getDist() != Dist.DEDICATED_SERVER) return;
        try {
            LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
            Configuration cfg = ctx.getConfiguration();
            Filter mask = RegexFilter.createFilter(PATTERN, null, false,
                    Filter.Result.DENY, Filter.Result.NEUTRAL);
            cfg.addFilter(mask);
            ctx.updateLoggers();
            LOGGER.info("[SessionAuth] Log masking active for password command lines.");
        } catch (Exception e) {
            LOGGER.warn("[SessionAuth] Could not install log masking (passwords may appear in logs): {}", e.toString());
        }
    }
}
