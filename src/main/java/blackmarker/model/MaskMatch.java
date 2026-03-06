package blackmarker.model;

/**
 * Represents a single match found by the masking engine.
 * Stores positions, category (for coloring), and the rule that matched.
 */
public class MaskMatch implements Comparable<MaskMatch> {

    private final int start;
    private final int end;
    private final RuleCategory category;
    private final String ruleName;
    private final char maskChar;
    private final boolean preserveEdges;

    public MaskMatch(int start, int end, RuleCategory category, String ruleName, char maskChar) {
        this(start, end, category, ruleName, maskChar, false);
    }

    public MaskMatch(int start, int end, RuleCategory category, String ruleName, char maskChar, boolean preserveEdges) {
        this.start = start;
        this.end = end;
        this.category = category;
        this.ruleName = ruleName;
        this.maskChar = maskChar;
        this.preserveEdges = preserveEdges;
    }

    public int getStart() { return start; }
    public int getEnd() { return end; }
    public RuleCategory getCategory() { return category; }
    public String getRuleName() { return ruleName; }
    public char getMaskChar() { return maskChar; }
    public int getLength() { return end - start; }
    public boolean isPreserveEdges() { return preserveEdges; }

    /**
     * Generate the masked replacement string (same length as original).
     */
    public String getMaskedText() {
        StringBuilder sb = new StringBuilder(getLength());
        for (int i = 0; i < getLength(); i++) {
            sb.append(maskChar);
        }
        return sb.toString();
    }

    /**
     * Check if this match overlaps with another.
     */
    public boolean overlaps(MaskMatch other) {
        return this.start < other.end && other.start < this.end;
    }

    /**
     * Check if this match fully contains another.
     */
    public boolean contains(MaskMatch other) {
        return this.start <= other.start && this.end >= other.end;
    }

    @Override
    public int compareTo(MaskMatch other) {
        int cmp = Integer.compare(this.start, other.start);
        if (cmp != 0) return cmp;
        // Longer matches first (for merging preference)
        return Integer.compare(other.end, this.end);
    }

    @Override
    public String toString() {
        return String.format("MaskMatch[%d-%d, %s, %s]", start, end, category, ruleName);
    }
}
