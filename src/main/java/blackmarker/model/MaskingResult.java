package blackmarker.model;

import java.util.Collections;
import java.util.List;

/**
 * Result of masking operation: the masked text and metadata about all matches.
 */
public class MaskingResult {

    private final String originalText;
    private final String maskedText;
    private final List<MaskMatch> matches;

    public MaskingResult(String originalText, String maskedText, List<MaskMatch> matches) {
        this.originalText = originalText;
        this.maskedText = maskedText;
        this.matches = Collections.unmodifiableList(matches);
    }

    public String getOriginalText() { return originalText; }
    public String getMaskedText() { return maskedText; }
    public List<MaskMatch> getMatches() { return matches; }
    public int getMatchCount() { return matches.size(); }
    public boolean hasMatches() { return !matches.isEmpty(); }

    /**
     * Get matches filtered by category.
     */
    public List<MaskMatch> getMatchesByCategory(RuleCategory category) {
        return matches.stream()
                .filter(m -> m.getCategory() == category)
                .toList();
    }

    /**
     * Summary string for status display.
     */
    public String getSummary() {
        if (!hasMatches()) return "No sensitive data detected";
        StringBuilder sb = new StringBuilder();
        sb.append(matches.size()).append(" item(s) masked: ");
        for (RuleCategory cat : RuleCategory.values()) {
            long count = matches.stream().filter(m -> m.getCategory() == cat).count();
            if (count > 0) {
                sb.append(cat.getDisplayName()).append("=").append(count).append(" ");
            }
        }
        return sb.toString().trim();
    }
}
