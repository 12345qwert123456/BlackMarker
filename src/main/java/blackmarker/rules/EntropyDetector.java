package blackmarker.rules;

import blackmarker.model.MaskMatch;
import blackmarker.model.RuleCategory;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Detects high-entropy strings that may be secrets, tokens, or keys.
 * Uses Shannon entropy calculation to identify random-looking strings.
 */
public class EntropyDetector {

    private volatile boolean enabled = true;
    private volatile double entropyThreshold = 4.5;
    private volatile int minLength = 20;
    private volatile int maxLength = 500;

    // Character classes for entropy analysis
    // Note: '=' excluded so that name=value is split into two tokens
    // ':' excluded so that Header:value is split into two tokens
    private static final String TOKEN_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_+/.;";

    private static final boolean[] IS_TOKEN_CHAR = new boolean[128];
    static {
        for (int i = 0; i < TOKEN_CHARS.length(); i++) {
            IS_TOKEN_CHAR[TOKEN_CHARS.charAt(i)] = true;
        }
    }

    private static final double LN2 = Math.log(2);
    private static final Pattern LOWER_ONLY = Pattern.compile("[a-z]+");
    private static final Pattern UPPER_ONLY = Pattern.compile("[A-Z]+");

    /**
     * Detect high-entropy strings in the given text.
     */
    public List<MaskMatch> detect(String text) {
        List<MaskMatch> matches = new ArrayList<>();
        if (!enabled || text == null || text.isEmpty()) {
            return matches;
        }

        final int min = minLength;
        final int max = maxLength;
        final double threshold = entropyThreshold;

        // Scan for contiguous token-like strings
        int i = 0;
        while (i < text.length()) {
            // Skip whitespace and common delimiters
            if (!isTokenChar(text.charAt(i))) {
                i++;
                continue;
            }

            // Find the end of this token
            int start = i;
            while (i < text.length() && isTokenChar(text.charAt(i))) {
                i++;
            }

            int length = i - start;
            if (length >= min && length <= max) {
                String token = text.substring(start, i);

                // Skip if it looks like a common word, URL path, or known non-secret
                if (!looksLikeNoise(token)) {
                    double entropy = calculateShannonEntropy(token);
                    if (entropy >= threshold) {
                        matches.add(new MaskMatch(
                            start, i,
                            RuleCategory.CRYPTO,
                            "High Entropy String (H=" + String.format("%.2f", entropy) + ")",
                            '█'
                        ));
                    }
                }
            }
        }

        return matches;
    }

    /**
     * Calculate Shannon entropy of a string.
     * Higher entropy = more random = more likely to be a secret.
     */
    public static double calculateShannonEntropy(String text) {
        if (text == null || text.isEmpty()) return 0.0;

        int[] freq = new int[256];
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c < 256) freq[c]++;
        }

        double entropy = 0.0;
        double len = text.length();
        for (int f : freq) {
            if (f > 0) {
                double p = f / len;
                entropy -= p * (Math.log(p) / LN2);
            }
        }
        return entropy;
    }

    private static boolean isTokenChar(char c) {
        return c < 128 && IS_TOKEN_CHAR[c];
    }

    /**
     * Filter out likely non-secrets: common words, repeated patterns, etc.
     */
    private static boolean looksLikeNoise(String token) {
        // Skip if it's all the same character
        if (token.chars().distinct().count() <= 3) return true;

        // Skip if it looks like a version string or common path component
        if (LOWER_ONLY.matcher(token).matches() || UPPER_ONLY.matcher(token).matches()) return true;

        // Skip if mostly dots (like a domain name)
        long dotCount = token.chars().filter(c -> c == '.').count();
        if (dotCount > token.length() / 4) return true;

        // Skip known common long strings
        if (token.startsWith("application/") || token.startsWith("text/")) return true;
        if (token.startsWith("http://") || token.startsWith("https://")) return true;

        return false;
    }

    // --- Configuration ---

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public double getEntropyThreshold() { return entropyThreshold; }
    public void setEntropyThreshold(double threshold) { this.entropyThreshold = threshold; }

    public int getMinLength() { return minLength; }
    public void setMinLength(int minLength) { this.minLength = minLength; }

    public int getMaxLength() { return maxLength; }
    public void setMaxLength(int maxLength) { this.maxLength = maxLength; }
}
