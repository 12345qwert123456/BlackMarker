package blackmarker.model;

import java.awt.Color;

/**
 * Categories for masking rules, each with a display name and UI color.
 */
public enum RuleCategory {
    PII("PII / Personal Data", new Color(65, 105, 225)),
    AUTH("Authentication & Secrets", new Color(220, 20, 60)),
    INFRASTRUCTURE("Infrastructure", new Color(255, 140, 0)),
    CRYPTO("Crypto & Keys", new Color(148, 103, 189)),
    SESSION("Session Data", new Color(44, 160, 44)),
    CUSTOM("Custom Rules", new Color(128, 128, 128));

    private final String displayName;
    private final Color color;

    RuleCategory(String displayName, Color color) {
        this.displayName = displayName;
        this.color = color;
    }

    public String getDisplayName() {
        return displayName;
    }

    public Color getColor() {
        return color;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
