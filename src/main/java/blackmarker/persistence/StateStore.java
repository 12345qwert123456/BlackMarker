package blackmarker.persistence;

import blackmarker.engine.MaskingEngine;
import blackmarker.model.PluginSettings;
import blackmarker.model.RuleCategory;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * Loads and saves rules and settings through Burp's Persistence API.
 *
 * State is written when the extension unloads and also periodically (only keys whose
 * content changed), so settings are not lost if Burp is killed. The autosave thread is a
 * daemon thread that is stopped in {@link #shutdown()}.
 */
public final class StateStore {

    private static final String KEY_CUSTOM_RULES = "blackmarker.custom_rules";
    private static final String KEY_BUILTIN_STATE = "blackmarker.builtin_state";
    private static final String KEY_BUILTIN_OVERRIDES = "blackmarker.builtin_overrides";
    private static final String KEY_SETTINGS = "blackmarker.settings";
    private static final String KEY_PLUGIN_SETTINGS = "blackmarker.plugin_settings";

    private static final long AUTOSAVE_SECONDS = 15;

    private final MontoyaApi api;
    private final MaskingEngine engine;
    private final Map<String, String> lastSaved = new HashMap<>();
    private ScheduledExecutorService autosave;

    public StateStore(MontoyaApi api, MaskingEngine engine) {
        this.api = api;
        this.engine = engine;
    }

    // =====================================================================
    // Load
    // =====================================================================

    /** Restore saved state. Each part is independent: one corrupt value does not block the others. */
    public void load() {
        PersistedObject store = api.persistence().extensionData();

        // Order matters: overrides replace/remove built-ins, then enabled flags, then custom rules
        loadPart(store, KEY_BUILTIN_OVERRIDES, engine::loadBuiltInOverrides);
        loadPart(store, KEY_BUILTIN_STATE, engine::loadBuiltInState);
        loadPart(store, KEY_CUSTOM_RULES, engine::loadCustomRules);
        loadPart(store, KEY_SETTINGS, this::loadSettings);
        loadPart(store, KEY_PLUGIN_SETTINGS, PluginSettings.getInstance()::deserialize);
    }

    private void loadPart(PersistedObject store, String key, java.util.function.Consumer<String> loader) {
        try {
            String json = store.getString(key);
            if (json != null && !json.isEmpty()) loader.accept(json);
        } catch (Exception e) {
            api.logging().logToError("[BlackMarker] Could not restore '" + key + "': " + e);
        }
    }

    private void loadSettings(String json) {
        JsonObject o = JsonParser.parseString(json).getAsJsonObject();

        engine.setEnabled(bool(o, "enabled", engine.isEnabled()));
        engine.getEntropyDetector().setEnabled(bool(o, "entropyEnabled", engine.getEntropyDetector().isEnabled()));
        engine.getSessionValueTracker().setEnabled(bool(o, "sessionAutoLearn", engine.getSessionValueTracker().isEnabled()));

        if (o.has("entropyThreshold")) engine.getEntropyDetector().setEntropyThreshold(o.get("entropyThreshold").getAsDouble());
        if (o.has("entropyMinLength")) engine.getEntropyDetector().setMinLength(o.get("entropyMinLength").getAsInt());
        if (o.has("entropyMaxLength")) engine.getEntropyDetector().setMaxLength(o.get("entropyMaxLength").getAsInt());

        if (o.has("disabledCategories") && o.get("disabledCategories").isJsonArray()) {
            for (JsonElement e : o.getAsJsonArray("disabledCategories")) {
                try {
                    engine.setCategoryEnabled(RuleCategory.valueOf(e.getAsString()), false);
                } catch (IllegalArgumentException ignored) {}
            }
        }
    }

    private static boolean bool(JsonObject o, String key, boolean fallback) {
        JsonElement e = o.get(key);
        return e != null && e.isJsonPrimitive() && e.getAsJsonPrimitive().isBoolean() ? e.getAsBoolean() : fallback;
    }

    // =====================================================================
    // Save
    // =====================================================================

    private String serializeSettings() {
        JsonObject o = new JsonObject();
        o.addProperty("enabled", engine.isEnabled());
        o.addProperty("entropyEnabled", engine.getEntropyDetector().isEnabled());
        o.addProperty("entropyThreshold", engine.getEntropyDetector().getEntropyThreshold());
        o.addProperty("entropyMinLength", engine.getEntropyDetector().getMinLength());
        o.addProperty("entropyMaxLength", engine.getEntropyDetector().getMaxLength());
        o.addProperty("sessionAutoLearn", engine.getSessionValueTracker().isEnabled());
        JsonArray disabled = new JsonArray();
        for (RuleCategory c : RuleCategory.values()) {
            if (!engine.isCategoryEnabled(c)) disabled.add(c.name());
        }
        o.add("disabledCategories", disabled);
        return o.toString();
    }

    /** Write every part whose serialized form changed since the last save. */
    public synchronized void save() {
        PersistedObject store = api.persistence().extensionData();
        savePart(store, KEY_CUSTOM_RULES, engine::serializeCustomRules);
        savePart(store, KEY_BUILTIN_STATE, engine::serializeBuiltInState);
        savePart(store, KEY_BUILTIN_OVERRIDES, engine::serializeBuiltInOverrides);
        savePart(store, KEY_SETTINGS, this::serializeSettings);
        savePart(store, KEY_PLUGIN_SETTINGS, PluginSettings.getInstance()::serialize);
    }

    private void savePart(PersistedObject store, String key, Supplier<String> serializer) {
        String json = serializer.get();
        if (!json.equals(lastSaved.get(key))) {
            store.setString(key, json);
            lastSaved.put(key, json);
        }
    }

    // =====================================================================
    // Lifecycle
    // =====================================================================

    public synchronized void startAutosave() {
        if (autosave != null) return;
        autosave = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "BlackMarker-autosave");
            t.setDaemon(true);
            return t;
        });
        autosave.scheduleWithFixedDelay(() -> {
            try {
                save();
            } catch (Throwable t) {
                // Burp does not report exceptions from extension threads
                api.logging().logToError("[BlackMarker] Autosave failed: " + t);
            }
        }, AUTOSAVE_SECONDS, AUTOSAVE_SECONDS, TimeUnit.SECONDS);
    }

    /** Stop the autosave thread and write the final state. */
    public void shutdown() {
        ScheduledExecutorService s;
        synchronized (this) {
            s = autosave;
            autosave = null;
        }
        if (s != null) {
            s.shutdownNow();
            try {
                s.awaitTermination(2, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        try {
            save();
        } catch (Throwable t) {
            api.logging().logToError("[BlackMarker] Failed to persist state: " + t);
        }
    }
}
