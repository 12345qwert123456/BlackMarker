package blackmarker.model;

import java.awt.Color;
import java.util.*;
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
    private final Map<RuleCategory, Color> categoryFgOverrides = new LinkedHashMap<>();
    private final Map<RuleCategory, Color> categoryBgOverrides = new LinkedHashMap<>();

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
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"monochrome\":").append(monochrome).append(",");
        sb.append("\"globalMaskChar\":\"").append(escapeChar(globalMaskChar)).append("\",");
        sb.append("\"truncationEnabled\":").append(truncationEnabled).append(",");
        sb.append("\"maxMaskedLength\":").append(maxMaskedLength).append(",");

        // Custom categories
        sb.append("\"customCategories\":[");
        boolean first = true;
        for (CustomCategory c : customCategories) {
            if (!first) sb.append(",");
            first = false;
            sb.append("{\"id\":\"").append(esc(c.getId()))
              .append("\",\"name\":\"").append(esc(c.getName()))
              .append("\",\"fg\":\"").append(colorToHex(c.getForeground()))
              .append("\",\"bg\":\"").append(colorToHex(c.getBackground()))
              .append("\"}");
        }
        sb.append("],");

        // Category color overrides
        sb.append("\"fgOverrides\":{");
        first = true;
        for (var e : categoryFgOverrides.entrySet()) {
            if (!first) sb.append(",");
            first = false;
            sb.append("\"").append(e.getKey().name()).append("\":\"").append(colorToHex(e.getValue())).append("\"");
        }
        sb.append("},");
        sb.append("\"bgOverrides\":{");
        first = true;
        for (var e : categoryBgOverrides.entrySet()) {
            if (!first) sb.append(",");
            first = false;
            sb.append("\"").append(e.getKey().name()).append("\":\"").append(colorToHex(e.getValue())).append("\"");
        }
        sb.append("}}");
        return sb.toString();
    }

    public void deserialize(String json) {
        if (json == null || json.isEmpty()) return;
        try {
            monochrome = json.contains("\"monochrome\":true");

            java.util.regex.Matcher m;

            m = java.util.regex.Pattern.compile("\"globalMaskChar\":\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(json);
            if (m.find()) {
                String val = m.group(1);
                if (val.startsWith("\\u")) {
                    globalMaskChar = (char) Integer.parseInt(val.substring(2), 16);
                } else if (!val.isEmpty()) {
                    globalMaskChar = val.charAt(0);
                }
            }

            truncationEnabled = json.contains("\"truncationEnabled\":true");

            m = java.util.regex.Pattern.compile("\"maxMaskedLength\":(\\d+)").matcher(json);
            if (m.find()) maxMaskedLength = Math.max(4, Integer.parseInt(m.group(1)));

            // Custom categories
            customCategories.clear();
            m = java.util.regex.Pattern.compile(
                "\\{\"id\":\"([^\"]*)\",\"name\":\"([^\"]*)\",\"fg\":\"([^\"]*)\",\"bg\":\"([^\"]*)\"\\}"
            ).matcher(json);
            while (m.find()) {
                customCategories.add(new CustomCategory(
                    m.group(1), m.group(2),
                    hexToColor(m.group(3)), hexToColor(m.group(4))
                ));
            }

            // Category FG overrides
            categoryFgOverrides.clear();
            java.util.regex.Matcher fgBlock = java.util.regex.Pattern.compile(
                "\"fgOverrides\":\\{([^}]*)\\}"
            ).matcher(json);
            if (fgBlock.find()) {
                parseColorOverrides(fgBlock.group(1), categoryFgOverrides);
            }

            // Category BG overrides
            categoryBgOverrides.clear();
            java.util.regex.Matcher bgBlock = java.util.regex.Pattern.compile(
                "\"bgOverrides\":\\{([^}]*)\\}"
            ).matcher(json);
            if (bgBlock.find()) {
                parseColorOverrides(bgBlock.group(1), categoryBgOverrides);
            }
        } catch (Exception ignored) {}
    }

    private void parseColorOverrides(String block, Map<RuleCategory, Color> map) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(
            "\"(\\w+)\":\"(#[0-9a-fA-F]{6})\""
        ).matcher(block);
        while (m.find()) {
            try {
                RuleCategory cat = RuleCategory.valueOf(m.group(1));
                map.put(cat, hexToColor(m.group(2)));
            } catch (Exception ignored) {}
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

    private static String esc(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String escapeChar(char c) {
        if (c > 127) return "\\u" + String.format("%04x", (int) c);
        return String.valueOf(c);
    }
}
