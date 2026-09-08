package com.seebi.sessionauth;

import com.mojang.logging.LogUtils;
import net.neoforged.api.distmarker.Dist;
import net.neoforged.bus.api.IEventBus;
import net.neoforged.fml.ModContainer;
import net.neoforged.fml.common.Mod;
import net.neoforged.fml.config.ModConfig;
import net.neoforged.fml.loading.FMLEnvironment;
import net.neoforged.neoforge.common.NeoForge;
import org.slf4j.Logger;

import java.nio.file.Path;

/**
 * SessionAuth — password login with known-IP auto-login for offline-mode
 * (cracked-friendly) servers. Server-side only: vanilla clients work.
 * <p>
 * Does nothing unless running on a dedicated server, so it is safe (if
 * pointless) to have in a client mod folder or a singleplayer world.
 */
@Mod(SessionAuth.MODID)
public class SessionAuth {
    public static final String MODID = "sessionauth";
    public static final Logger LOGGER = LogUtils.getLogger();

    public SessionAuth(IEventBus modEventBus, ModContainer modContainer) {
        modContainer.registerConfig(ModConfig.Type.COMMON, Config.SPEC);
        if (FMLEnvironment.getDist() != Dist.DEDICATED_SERVER) {
            LOGGER.info("[SessionAuth] Not a dedicated server — staying idle.");
            return;
        }
        LogMask.install(); // before anything else can log a password
        // Game dir is known even before the server starts; the store file
        // lives next to server.properties, shared across worlds/restarts.
        Path gameDir = net.neoforged.fml.loading.FMLPaths.GAMEDIR.get();
        AuthStore store = new AuthStore(gameDir);
        NeoForge.EVENT_BUS.register(new AuthEvents(store));
        LOGGER.info("[SessionAuth] loaded — password login + known-IP auto-login active.");
    }
}
