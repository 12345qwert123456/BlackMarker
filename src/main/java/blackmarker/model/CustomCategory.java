package blackmarker.model;

import java.awt.Color;

/**
 * User-defined category with custom name and colors.
 * Stored in PluginSettings and selectable in rule editor.
 */
public class CustomCategory {

    private final String id;
    private String name;
    private Color foreground;
    private Color background;

    public CustomCategory(String id, String name, Color foreground, Color background) {
        this.id = id;
        this.name = name;
        this.foreground = foreground;
        this.background = background;
    }

    /**
     * Create with auto-generated ID.
     */
    public CustomCategory(String name, Color foreground, Color background) {
        this("custom_" + System.currentTimeMillis(), name, foreground, background);
    }

    public String getId() { return id; }
    public String getName() { return name; }
    public Color getForeground() { return foreground; }
    public Color getBackground() { return background; }

    public void setName(String name) { this.name = name; }
    public void setForeground(Color foreground) { this.foreground = foreground; }
    public void setBackground(Color background) { this.background = background; }

    @Override
    public String toString() {
        return name;
    }
}
