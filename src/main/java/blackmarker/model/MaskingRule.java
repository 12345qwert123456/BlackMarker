package blackmarker.model;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Represents a single masking rule with regex pattern and metadata.
 */
public class MaskingRule {

    private String name;
    private String regex;
    private RuleCategory category;
    private boolean enabled;
    private char maskChar;
    private boolean builtIn;
    private String description;
    /** If > 0, regex must have group(1) — only group(1) is masked, rest is kept visible. */
    private int captureGroupToMask;
    /** If true, preserve edge characters of the masked value (3+3 for long, 1+1 for short). */
    private boolean preserveEdges;
    private transient Pattern compiledPattern;
    private transient boolean compilationFailed;

    public MaskingRule(String name, String regex, RuleCategory category, char maskChar,
                       boolean enabled, boolean builtIn, String description) {
        this(name, regex, category, maskChar, enabled, builtIn, description, 0, false);
    }

    public MaskingRule(String name, String regex, RuleCategory category, char maskChar,
                       boolean enabled, boolean builtIn, String description,
                       int captureGroupToMask, boolean preserveEdges) {
        this.name = name;
        this.regex = regex;
        this.category = category;
        this.maskChar = maskChar;
        this.enabled = enabled;
        this.builtIn = builtIn;
        this.description = description;
        this.captureGroupToMask = captureGroupToMask;
        this.preserveEdges = preserveEdges;
        compilePattern();
    }

    public MaskingRule(String name, String regex, RuleCategory category, String description) {
        this(name, regex, category, '\u2588', true, true, description);
    }

    public MaskingRule(MaskingRule other) {
        this(other.name, other.regex, other.category, other.maskChar,
             other.enabled, other.builtIn, other.description,
             other.captureGroupToMask, other.preserveEdges);
    }

    private void compilePattern() {
        try {
            this.compiledPattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
            this.compilationFailed = false;
        } catch (PatternSyntaxException e) {
            this.compiledPattern = null;
            this.compilationFailed = true;
        }
    }

    // --- Getters ---

    public String getName() { return name; }
    public String getRegex() { return regex; }
    public RuleCategory getCategory() { return category; }
    public boolean isEnabled() { return enabled; }
    public char getMaskChar() { return maskChar; }
    public boolean isBuiltIn() { return builtIn; }
    public String getDescription() { return description; }
    public boolean isCompilationFailed() { return compilationFailed; }
    public int getCaptureGroupToMask() { return captureGroupToMask; }
    public boolean isPreserveEdges() { return preserveEdges; }

    public Pattern getCompiledPattern() {
        if (compiledPattern == null && !compilationFailed) {
            compilePattern();
        }
        return compiledPattern;
    }

    // --- Setters ---

    public void setName(String name) { this.name = name; }

    public void setRegex(String regex) {
        this.regex = regex;
        compilePattern();
    }

    public void setCategory(RuleCategory category) { this.category = category; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public void setMaskChar(char maskChar) { this.maskChar = maskChar; }
    public void setBuiltIn(boolean builtIn) { this.builtIn = builtIn; }
    public void setDescription(String description) { this.description = description; }
    public void setCaptureGroupToMask(int captureGroupToMask) { this.captureGroupToMask = captureGroupToMask; }
    public void setPreserveEdges(boolean preserveEdges) { this.preserveEdges = preserveEdges; }

    /**
     * Generates a mask string of the same length as the matched text.
     */
    public String generateMask(String matchedText) {
        int len = matchedText.length();
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            sb.append(maskChar);
        }
        return sb.toString();
    }

    @Override
    public String toString() {
        return String.format("[%s] %s (%s)", category.name(), name, enabled ? "ON" : "OFF");
    }
}
