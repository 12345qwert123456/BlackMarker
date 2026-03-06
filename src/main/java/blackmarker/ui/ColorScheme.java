package blackmarker.ui;

import blackmarker.model.CustomCategory;
import blackmarker.model.PluginSettings;
import blackmarker.model.RuleCategory;

import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Font;
import java.util.EnumMap;
import java.util.Map;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.UIManager;

/**
 * Centralized color scheme for the BlackMarker UI.
 * Respects PluginSettings: monochrome mode, category color overrides,
 * and custom user-defined categories.
 */
public final class ColorScheme {

    private ColorScheme() {}

    // --- Default category colors (used when no override is set) ---
    private static final Map<RuleCategory, Color> DEFAULT_BG_COLORS = new EnumMap<>(RuleCategory.class);
    private static final Map<RuleCategory, Color> DEFAULT_FG_COLORS = new EnumMap<>(RuleCategory.class);

    static {
        DEFAULT_BG_COLORS.put(RuleCategory.PII,            new Color(200, 215, 255));
        DEFAULT_BG_COLORS.put(RuleCategory.AUTH,            new Color(255, 200, 200));
        DEFAULT_BG_COLORS.put(RuleCategory.INFRASTRUCTURE,  new Color(255, 225, 180));
        DEFAULT_BG_COLORS.put(RuleCategory.CRYPTO,          new Color(225, 210, 245));
        DEFAULT_BG_COLORS.put(RuleCategory.SESSION,         new Color(200, 240, 200));
        DEFAULT_BG_COLORS.put(RuleCategory.CUSTOM,          new Color(220, 220, 220));

        DEFAULT_FG_COLORS.put(RuleCategory.PII,            new Color(30, 60, 180));
        DEFAULT_FG_COLORS.put(RuleCategory.AUTH,            new Color(180, 10, 40));
        DEFAULT_FG_COLORS.put(RuleCategory.INFRASTRUCTURE,  new Color(200, 110, 0));
        DEFAULT_FG_COLORS.put(RuleCategory.CRYPTO,          new Color(120, 80, 160));
        DEFAULT_FG_COLORS.put(RuleCategory.SESSION,         new Color(30, 130, 30));
        DEFAULT_FG_COLORS.put(RuleCategory.CUSTOM,          new Color(100, 100, 100));
    }

    /**
     * Get background color for a category, respecting monochrome + overrides.
     */
    public static Color getCategoryBackgroundColor(RuleCategory category) {
        PluginSettings s = PluginSettings.getInstance();
        if (s.isMonochrome()) return s.getMonochromeBackground();
        Color override = s.getCategoryBgOverride(category);
        if (override != null) return override;
        return DEFAULT_BG_COLORS.getOrDefault(category, new Color(220, 220, 220));
    }

    /**
     * Get foreground color for a category, respecting monochrome + overrides.
     */
    public static Color getCategoryForegroundColor(RuleCategory category) {
        PluginSettings s = PluginSettings.getInstance();
        if (s.isMonochrome()) return s.getMonochromeForeground();
        Color override = s.getCategoryFgOverride(category);
        if (override != null) return override;
        return DEFAULT_FG_COLORS.getOrDefault(category, Color.DARK_GRAY);
    }

    /**
     * Get background color for a custom category (by ID), respecting monochrome.
     */
    public static Color getCustomCategoryBackgroundColor(String customCatId) {
        PluginSettings s = PluginSettings.getInstance();
        if (s.isMonochrome()) return s.getMonochromeBackground();
        CustomCategory cc = s.findCustomCategory(customCatId);
        return cc != null ? cc.getBackground() : new Color(220, 220, 220);
    }

    /**
     * Get foreground color for a custom category (by ID), respecting monochrome.
     */
    public static Color getCustomCategoryForegroundColor(String customCatId) {
        PluginSettings s = PluginSettings.getInstance();
        if (s.isMonochrome()) return s.getMonochromeForeground();
        CustomCategory cc = s.findCustomCategory(customCatId);
        return cc != null ? cc.getForeground() : Color.DARK_GRAY;
    }

    // --- General UI Colors ---

    public static final Color PANEL_BACKGROUND = UIManager.getColor("Panel.background") != null
        ? UIManager.getColor("Panel.background") : Color.WHITE;
    public static final Color PANEL_BACKGROUND_LIGHT = new Color(245, 245, 245);
    public static final Color TEXT_PRIMARY = Color.BLACK;
    public static final Color TEXT_SECONDARY = new Color(100, 100, 100);
    public static final Color ACCENT = new Color(65, 105, 225);
    public static final Color ACCENT_HOVER = new Color(85, 125, 245);
    public static final Color SUCCESS = new Color(44, 160, 44);
    public static final Color WARNING = new Color(200, 140, 0);
    public static final Color DANGER = new Color(220, 20, 60);

    public static final Color EDITOR_BACKGROUND = Color.WHITE;
    public static final Color EDITOR_FOREGROUND = Color.BLACK;
    public static final Color EDITOR_LINE_HIGHLIGHT = new Color(245, 245, 245);

    public static final Color STATUS_ENABLED = new Color(44, 160, 44);
    public static final Color STATUS_DISABLED = new Color(220, 20, 60);

    /**
     * Create a legend panel with colored squares for each category (no HTML).
     */
    public static JPanel createLegendPanel() {
        PluginSettings s = PluginSettings.getInstance();
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
        panel.setOpaque(false);

        JLabel title = new JLabel("Legend: ");
        title.setFont(new Font("SansSerif", Font.BOLD, 11));
        panel.add(title);

        for (RuleCategory cat : RuleCategory.values()) {
            Color c = getCategoryForegroundColor(cat);
            JLabel swatch = new JLabel("\u2588\u2588");
            swatch.setFont(new Font("SansSerif", Font.PLAIN, 11));
            swatch.setForeground(c);
            panel.add(swatch);
            JLabel name = new JLabel(cat.getDisplayName() + "  ");
            name.setFont(new Font("SansSerif", Font.PLAIN, 11));
            panel.add(name);
        }
        for (CustomCategory cc : s.getCustomCategories()) {
            Color c = s.isMonochrome() ? s.getMonochromeForeground() : cc.getForeground();
            JLabel swatch = new JLabel("\u2588\u2588");
            swatch.setFont(new Font("SansSerif", Font.PLAIN, 11));
            swatch.setForeground(c);
            panel.add(swatch);
            JLabel name = new JLabel(cc.getName() + "  ");
            name.setFont(new Font("SansSerif", Font.PLAIN, 11));
            panel.add(name);
        }
        return panel;
    }
}
