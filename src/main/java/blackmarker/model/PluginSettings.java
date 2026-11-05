package blackmarker.model;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.awt.Color;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Global plugin settings — singleton accessible across all components.
 *
 * Settings:
 * - Monochrome mode: disables per-category colors, uses single gray
 * - Global mask character: default mask char for all rules (rules can still override)
 * - Mask truncation: shorten long masked strings to maxVisibleLength with "…" indicator
 * - Custom categories: user-defined categories with custom names and colors
 */
public final class PluginSettings {

    private static final PluginSettings INSTANCE = new PluginSettings();

    // --- Monochrome ---
    private volatile boolean monochrome = false;
    private static final Color MONO_FG = new Color(60, 60, 60);
    private static final Color MONO_BG = new Color(210, 210, 210);

    // --- Global mask character ---
    private volatile char globalMaskChar = '\u2588'; // █

    // --- Mask truncation ---
    private volatile boolean truncationEnabled = false;
    private volatile int maxMaskedLength = 16;  // max visible mask chars before truncating

    // --- Custom categories ---
    private final CopyOnWriteArrayList<CustomCategory> customCategories = new CopyOnWriteArrayList<>();

    // --- Category color overrides for built-in categories ---
    private final Map<RuleCategory, Color> categoryFgOverrides = new ConcurrentHashMap<>();
    private final Map<RuleCategory, Color> categoryBgOverrides = new ConcurrentHashMap<>();

    private final List<Runnable> changeListeners = new CopyOnWriteArrayList<>();

    private PluginSettings() {}

    public static PluginSettings getInstance() {
        return INSTANCE;
    }

    // ============================ Monochrome ============================

    public boolean isMonochrome() { return monochrome; }

    public void setMonochrome(boolean monochrome) {
        this.monochrome = monochrome;
        fireChange();
    }

    public Color getMonochromeForeground() { return MONO_FG; }
    public Color getMonochromeBackground() { return MONO_BG; }

    // ============================ Global Mask Char ============================

    public char getGlobalMaskChar() { return globalMaskChar; }

    public void setGlobalMaskChar(char c) {
        this.globalMaskChar = c;
        fireChange();
    }

    // ============================ Truncation ============================

    public boolean isTruncationEnabled() { return truncationEnabled; }

    public void setTruncationEnabled(boolean enabled) {
        this.truncationEnabled = enabled;
        fireChange();
    }

    public int getMaxMaskedLength() { return maxMaskedLength; }

    public void setMaxMaskedLength(int max) {
        this.maxMaskedLength = Math.max(4, max);
        fireChange();
    }

    // ============================ Custom Categories ============================

    public List<CustomCategory> getCustomCategories() {
        return Collections.unmodifiableList(customCategories);
    }

    public void addCustomCategory(CustomCategory cat) {
        customCategories.add(cat);
        fireChange();
    }

    public void removeCustomCategory(int index) {
        if (index >= 0 && index < customCategories.size()) {
            customCategories.remove(index);
            fireChange();
        }
    }

    public void updateCustomCategory(int index, CustomCategory cat) {
        if (index >= 0 && index < customCategories.size()) {
            customCategories.set(index, cat);
            fireChange();
        }
    }

    public CustomCategory findCustomCategory(String id) {
        for (CustomCategory c : customCategories) {
            if (c.getId().equals(id)) return c;
        }
        return null;
    }

    // ============================ Category Color Overrides ============================

    public void setCategoryFgOverride(RuleCategory cat, Color fg) {
        if (fg != null) categoryFgOverrides.put(cat, fg);
        else categoryFgOverrides.remove(cat);
        fireChange();
    }

    public void setCategoryBgOverride(RuleCategory cat, Color bg) {
        if (bg != null) categoryBgOverrides.put(cat, bg);
        else categoryBgOverrides.remove(cat);
        fireChange();
    }

    public Color getCategoryFgOverride(RuleCategory cat) {
        return categoryFgOverrides.get(cat);
    }

    public Color getCategoryBgOverride(RuleCategory cat) {
        return categoryBgOverrides.get(cat);
    }

    public Map<RuleCategory, Color> getAllFgOverrides() {
        return Collections.unmodifiableMap(categoryFgOverrides);
    }

    public Map<RuleCategory, Color> getAllBgOverrides() {
        return Collections.unmodifiableMap(categoryBgOverrides);
    }

    // ============================ Change listeners ============================

    public void addChangeListener(Runnable listener) {
        changeListeners.add(listener);
    }

    private void fireChange() {
        for (Runnable r : changeListeners) {
            try { r.run(); } catch (Exception ignored) {}
        }
    }

    // ============================ Serialization ============================

    public String serialize() {
        JsonObject o = new JsonObject();
        o.addProperty("monochrome", monochrome);
        o.addProperty("globalMaskChar", String.valueOf(globalMaskChar));
        o.addProperty("truncationEnabled", truncationEnabled);
        o.addProperty("maxMaskedLength", maxMaskedLength);

        JsonArray cats = new JsonArray();
        for (CustomCategory c : customCategories) {
            JsonObject co = new JsonObject();
            co.addProperty("id", c.getId());
            co.addProperty("name", c.getName());
            co.addProperty("fg", colorToHex(c.getForeground()));
            co.addProperty("bg", colorToHex(c.getBackground()));
            cats.add(co);
        }
        o.add("customCategories", cats);
        o.add("fgOverrides", overridesToJson(categoryFgOverrides));
        o.add("bgOverrides", overridesToJson(categoryBgOverrides));
        return o.toString();
    }

    /**
     * Restore settings from {@link #serialize()} output (also reads files written by 1.0.0,
     * which used the same JSON shape). Missing or malformed fields keep their current values.
     */
    public void deserialize(String json) {
        if (json == null || json.isBlank()) return;
        JsonObject o;
        try {
            o = JsonParser.parseString(json).getAsJsonObject();
        } catch (RuntimeException e) {
            return;
        }

        monochrome = bool(o, "monochrome", monochrome);
        truncationEnabled = bool(o, "truncationEnabled", truncationEnabled);

        JsonElement mc = o.get("globalMaskChar");
        if (mc != null && mc.isJsonPrimitive() && !mc.getAsString().isEmpty()) {
            globalMaskChar = mc.getAsString().charAt(0);
        }
        JsonElement ml = o.get("maxMaskedLength");
        if (ml != null && ml.isJsonPrimitive()) {
            try { maxMaskedLength = Math.max(4, ml.getAsInt()); } catch (RuntimeException ignored) {}
        }

        if (o.has("customCategories") && o.get("customCategories").isJsonArray()) {
            customCategories.clear();
            for (JsonElement e : o.getAsJsonArray("customCategories")) {
                try {
                    JsonObject c = e.getAsJsonObject();
                    customCategories.add(new CustomCategory(
                        c.get("id").getAsString(), c.get("name").getAsString(),
                        hexToColor(c.get("fg").getAsString()), hexToColor(c.get("bg").getAsString())));
                } catch (RuntimeException ignored) {}
            }
        }

        categoryFgOverrides.clear();
        overridesFromJson(o.get("fgOverrides"), categoryFgOverrides);
        categoryBgOverrides.clear();
        overridesFromJson(o.get("bgOverrides"), categoryBgOverrides);
    }

    private static boolean bool(JsonObject o, String key, boolean fallback) {
        JsonElement e = o.get(key);
        return e != null && e.isJsonPrimitive() && e.getAsJsonPrimitive().isBoolean()
            ? e.getAsBoolean() : fallback;
    }

    private static JsonObject overridesToJson(Map<RuleCategory, Color> map) {
        JsonObject o = new JsonObject();
        for (var e : map.entrySet()) {
            o.addProperty(e.getKey().name(), colorToHex(e.getValue()));
        }
        return o;
    }

    private static void overridesFromJson(JsonElement el, Map<RuleCategory, Color> map) {
        if (el == null || !el.isJsonObject()) return;
        for (var e : el.getAsJsonObject().entrySet()) {
            try {
                map.put(RuleCategory.valueOf(e.getKey()), hexToColor(e.getValue().getAsString()));
            } catch (RuntimeException ignored) {}
        }
    }

    private static String colorToHex(Color c) {
        return String.format("#%02x%02x%02x", c.getRed(), c.getGreen(), c.getBlue());
    }

    private static Color hexToColor(String hex) {
        if (hex == null || hex.length() < 7) return Color.GRAY;
        return new Color(
            Integer.parseInt(hex.substring(1, 3), 16),
            Integer.parseInt(hex.substring(3, 5), 16),
            Integer.parseInt(hex.substring(5, 7), 16)
        );
    }
}
