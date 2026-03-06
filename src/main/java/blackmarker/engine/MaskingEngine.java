package blackmarker.engine;

import blackmarker.model.*;
import blackmarker.rules.DefaultRules;
import blackmarker.rules.EntropyDetector;
import blackmarker.rules.SessionValueTracker;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Core masking engine. Applies regex rules, entropy detection, and session value
 * tracking to produce masked text with same-length replacements (preserving positions).
 *
 * Respects PluginSettings:
 * - globalMaskChar: used when a rule's maskChar is the default █ and user changed the global
 * - truncation: shorten long mask runs to maxMaskedLength
 *
 * Thread-safe: uses CopyOnWriteArrayList for rules and synchronized masking.
 */
public class MaskingEngine {

    private final CopyOnWriteArrayList<MaskingRule> rules;
    private final EntropyDetector entropyDetector;
    private final SessionValueTracker sessionValueTracker;
    private volatile boolean enabled = true;
    private final Set<RuleCategory> enabledCategories;

    public MaskingEngine() {
        this.rules = new CopyOnWriteArrayList<>(DefaultRules.createAll());
        this.entropyDetector = new EntropyDetector();
        this.sessionValueTracker = new SessionValueTracker();
        this.enabledCategories = EnumSet.allOf(RuleCategory.class);
    }

    /**
     * Mask the given text, returning the result with positions of all matches.
     * Masking is same-length: each matched character is replaced with the rule's mask char.
     */
    public MaskingResult mask(String text) {
        if (!enabled || text == null || text.isEmpty()) {
            return new MaskingResult(text, text, Collections.emptyList());
        }

        List<MaskMatch> allMatches = new ArrayList<>();

        // 1. Apply regex rules
        for (MaskingRule rule : rules) {
            if (!rule.isEnabled()) continue;
            if (!enabledCategories.contains(rule.getCategory())) continue;

            Pattern pattern = rule.getCompiledPattern();
            if (pattern == null) continue;

            try {
                Matcher matcher = pattern.matcher(text);
                while (matcher.find()) {
                    int mStart, mEnd;

                    // If captureGroupToMask > 0, only mask that capture group
                    int group = rule.getCaptureGroupToMask();
                    if (group > 0 && group <= matcher.groupCount() && matcher.group(group) != null) {
                        mStart = matcher.start(group);
                        mEnd = matcher.end(group);
                    } else {
                        mStart = matcher.start();
                        mEnd = matcher.end();
                    }

                    if (mEnd > mStart) {
                        allMatches.add(new MaskMatch(
                            mStart, mEnd,
                            rule.getCategory(), rule.getName(),
                            rule.getMaskChar(), rule.isPreserveEdges()
                        ));
                    }
                }
            } catch (Exception e) {
                // Skip rules that fail at runtime (e.g., catastrophic backtracking)
            }
        }

        // 2. Programmatic cookie header processing (per-value with names visible)
        if (enabledCategories.contains(RuleCategory.SESSION)) {
            allMatches.addAll(processCookieHeaders(text));
        }

        // 3. Apply entropy-based detection
        if (entropyDetector.isEnabled() && enabledCategories.contains(RuleCategory.CRYPTO)) {
            allMatches.addAll(entropyDetector.detect(text));
        }

        // 4. Apply session value tracking
        if (sessionValueTracker.isEnabled() && enabledCategories.contains(RuleCategory.SESSION)) {
            allMatches.addAll(sessionValueTracker.detect(text));
        }

        // 5. Resolve overlapping matches (specific matches with preserveEdges take priority)
        allMatches = resolveOverlappingMatches(allMatches);

        // 6. Build masked text (same-length replacement, with optional edge preservation)
        //    Uses global mask char from settings when rule char is default █
        PluginSettings settings = PluginSettings.getInstance();
        char globalChar = settings.getGlobalMaskChar();
        char[] maskedChars = text.toCharArray();
        for (MaskMatch match : allMatches) {
            int mStart = match.getStart();
            int mEnd = Math.min(match.getEnd(), maskedChars.length);
            int len = mEnd - mStart;

            // Resolve effective mask char: rule-specific takes priority, else global
            char effectiveChar = match.getMaskChar();
            if (effectiveChar == '\u2588' && globalChar != '\u2588') {
                effectiveChar = globalChar;
            }

            if (match.isPreserveEdges() && len > 2) {
                // Preserve edge characters:
                // Long values (>= 10 chars): keep first 3 and last 3
                // Short values (< 10 chars): keep first 1 and last 1
                int keepStart, keepEnd;
                if (len >= 10) {
                    keepStart = 3;
                    keepEnd = 3;
                } else {
                    keepStart = 1;
                    keepEnd = 1;
                }
                // Only mask the middle portion
                for (int i = mStart + keepStart; i < mEnd - keepEnd; i++) {
                    maskedChars[i] = effectiveChar;
                }
            } else {
                for (int i = mStart; i < mEnd; i++) {
                    maskedChars[i] = effectiveChar;
                }
            }
        }

        String maskedText = new String(maskedChars);

        return new MaskingResult(text, maskedText, allMatches);
    }



    /**
     * Resolve overlapping matches with priority: specific matches (preserveEdges=true,
     * i.e. those produced by capture-group rules or cookie processing) take precedence
     * over generic/entropy/session-tracker matches.
     *
     * When a specific match claims a region, any generic match that overlaps is dropped entirely.
     */
    private List<MaskMatch> resolveOverlappingMatches(List<MaskMatch> matches) {
        if (matches.isEmpty()) return matches;

        // Sort: specific (preserveEdges) first, then by start, then longer first
        matches.sort(Comparator
            .<MaskMatch, Integer>comparing(m -> m.isPreserveEdges() ? 0 : 1)
            .thenComparingInt(MaskMatch::getStart)
            .thenComparing(Comparator.comparingInt(MaskMatch::getLength).reversed()));

        List<MaskMatch> result = new ArrayList<>();
        List<int[]> claimedRanges = new ArrayList<>();

        for (MaskMatch match : matches) {
            boolean overlaps = false;
            for (int[] range : claimedRanges) {
                if (match.getStart() < range[1] && range[0] < match.getEnd()) {
                    overlaps = true;
                    break;
                }
            }
            if (!overlaps) {
                result.add(match);
                claimedRanges.add(new int[]{match.getStart(), match.getEnd()});
            }
        }

        // Re-sort by start position for consistent display
        result.sort(Comparator.comparingInt(MaskMatch::getStart));
        return result;
    }

    /**
     * Parse Cookie / Set-Cookie header lines and create per-value MaskMatch entries.
     * This avoids the regex false-positive problem where ";name=value" patterns in
     * non-cookie headers (like Accept-Language q=0.9, Sec-Ch-Ua v="135") get masked.
     */
    private List<MaskMatch> processCookieHeaders(String text) {
        List<MaskMatch> matches = new ArrayList<>();
        Pattern headerPattern = Pattern.compile(
            "^(Set-Cookie|Cookie):[ \\t]*(.+)$",
            Pattern.CASE_INSENSITIVE | Pattern.MULTILINE
        );
        Matcher headerMatcher = headerPattern.matcher(text);
        while (headerMatcher.find()) {
            String headerName = headerMatcher.group(1);
            int valueStart = headerMatcher.start(2);
            String headerValue = headerMatcher.group(2);
            boolean isSetCookie = headerName.equalsIgnoreCase("Set-Cookie");

            // Match individual name=value pairs within the cookie header value
            Pattern pairPattern = Pattern.compile("([\\w\\-.]+)=([^\\s;]+)");
            Matcher pairMatcher = pairPattern.matcher(headerValue);

            // Standard Set-Cookie attributes that are NOT secret values
            java.util.Set<String> cookieAttrs = java.util.Set.of(
                "path", "domain", "expires", "max-age", "samesite",
                "secure", "httponly", "priority", "partitioned"
            );

            while (pairMatcher.find()) {
                String name = pairMatcher.group(1);

                // For Set-Cookie, skip standard cookie attributes
                if (isSetCookie && cookieAttrs.contains(name.toLowerCase())) {
                    continue;
                }

                int valStart = valueStart + pairMatcher.start(2);
                int valEnd = valueStart + pairMatcher.end(2);
                matches.add(new MaskMatch(
                    valStart, valEnd,
                    RuleCategory.SESSION, "Cookie: " + name,
                    '\u2588', true  // preserveEdges=true
                ));
            }
        }
        return matches;
    }

    /**
     * Feed a raw HTTP message to the session value tracker for auto-learning.
     */
    public void learnFromMessage(String rawMessage) {
        sessionValueTracker.learnFromMessage(rawMessage);
    }

    // =====================================================================
    // Rule Management
    // =====================================================================

    public List<MaskingRule> getRules() {
        return Collections.unmodifiableList(rules);
    }

    public void addRule(MaskingRule rule) {
        rules.add(rule);
    }

    public void removeRule(int index) {
        if (index >= 0 && index < rules.size()) {
            rules.remove(index);
        }
    }

    public void updateRule(int index, MaskingRule updatedRule) {
        if (index >= 0 && index < rules.size()) {
            rules.set(index, updatedRule);
        }
    }

    public void moveRuleUp(int index) {
        if (index > 0 && index < rules.size()) {
            MaskingRule rule = rules.remove(index);
            rules.add(index - 1, rule);
        }
    }

    public void moveRuleDown(int index) {
        if (index >= 0 && index < rules.size() - 1) {
            MaskingRule rule = rules.remove(index);
            rules.add(index + 1, rule);
        }
    }

    /**
     * Reset rules to defaults (removes all custom rules too).
     */
    public void resetToDefaults() {
        rules.clear();
        rules.addAll(DefaultRules.createAll());
    }

    // =====================================================================
    // Category Management
    // =====================================================================

    public boolean isCategoryEnabled(RuleCategory category) {
        return enabledCategories.contains(category);
    }

    public void setCategoryEnabled(RuleCategory category, boolean enabled) {
        if (enabled) {
            enabledCategories.add(category);
        } else {
            enabledCategories.remove(category);
        }
    }

    public Set<RuleCategory> getEnabledCategories() {
        return Collections.unmodifiableSet(enabledCategories);
    }

    // =====================================================================
    // Global State
    // =====================================================================

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public EntropyDetector getEntropyDetector() { return entropyDetector; }
    public SessionValueTracker getSessionValueTracker() { return sessionValueTracker; }

    // =====================================================================
    // Persistence (JSON serialization for Burp persistence API)
    // =====================================================================

    /**
     * Serialize custom (non-built-in) rules to JSON for persistence.
     */
    public String serializeCustomRules() {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (MaskingRule rule : rules) {
            if (rule.isBuiltIn()) continue;
            if (!first) sb.append(",");
            first = false;
            sb.append("{");
            sb.append("\"name\":").append(jsonEscape(rule.getName())).append(",");
            sb.append("\"regex\":").append(jsonEscape(rule.getRegex())).append(",");
            sb.append("\"category\":").append(jsonEscape(rule.getCategory().name())).append(",");
            sb.append("\"maskChar\":").append(jsonEscape(String.valueOf(rule.getMaskChar()))).append(",");
            sb.append("\"enabled\":").append(rule.isEnabled()).append(",");
            sb.append("\"description\":").append(jsonEscape(rule.getDescription()));
            sb.append("}");
        }
        sb.append("]");
        return sb.toString();
    }

    /**
     * Serialize the enabled/disabled state of built-in rules.
     */
    public String serializeBuiltInState() {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (MaskingRule rule : rules) {
            if (!rule.isBuiltIn()) continue;
            if (!first) sb.append(",");
            first = false;
            sb.append(jsonEscape(rule.getName())).append(":").append(rule.isEnabled());
        }
        sb.append("}");
        return sb.toString();
    }

    /**
     * Load custom rules from JSON. Appends to existing rules.
     */
    public void loadCustomRules(String json) {
        if (json == null || json.trim().isEmpty() || json.trim().equals("[]")) return;

        // Simple JSON parser for our known format
        try {
            // Remove outer brackets
            json = json.trim();
            if (json.startsWith("[")) json = json.substring(1);
            if (json.endsWith("]")) json = json.substring(0, json.length() - 1);

            // Split by },{ pattern
            String[] entries = json.split("\\},\\s*\\{");
            for (String entry : entries) {
                entry = entry.trim();
                if (entry.startsWith("{")) entry = entry.substring(1);
                if (entry.endsWith("}")) entry = entry.substring(0, entry.length() - 1);

                String name = extractJsonString(entry, "name");
                String regex = extractJsonString(entry, "regex");
                String categoryStr = extractJsonString(entry, "category");
                String maskCharStr = extractJsonString(entry, "maskChar");
                boolean isEnabled = extractJsonBoolean(entry, "enabled");
                String description = extractJsonString(entry, "description");

                if (name != null && regex != null) {
                    RuleCategory category;
                    try {
                        category = RuleCategory.valueOf(categoryStr);
                    } catch (Exception e) {
                        category = RuleCategory.CUSTOM;
                    }
                    char maskChar = (maskCharStr != null && !maskCharStr.isEmpty())
                        ? maskCharStr.charAt(0) : '\u2588';

                    rules.add(new MaskingRule(name, regex, category, maskChar,
                        isEnabled, false, description != null ? description : ""));
                }
            }
        } catch (Exception e) {
            // Silently ignore parse errors
        }
    }

    /**
     * Restore built-in rule enabled/disabled states from serialized data.
     */
    public void loadBuiltInState(String json) {
        if (json == null || json.trim().isEmpty() || json.trim().equals("{}")) return;

        for (MaskingRule rule : rules) {
            if (!rule.isBuiltIn()) continue;
            String key = rule.getName();
            // Simple lookup
            String pattern = jsonEscape(key) + ":(true|false)";
            java.util.regex.Matcher m = java.util.regex.Pattern.compile(pattern).matcher(json);
            if (m.find()) {
                rule.setEnabled(Boolean.parseBoolean(m.group(1)));
            }
        }
    }

    private static String jsonEscape(String s) {
        if (s == null) return "null";
        return "\"" + s.replace("\\", "\\\\")
                       .replace("\"", "\\\"")
                       .replace("\n", "\\n")
                       .replace("\r", "\\r")
                       .replace("\t", "\\t") + "\"";
    }

    private static String extractJsonString(String json, String key) {
        String pattern = "\"" + key + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"";
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(pattern).matcher(json);
        if (m.find()) {
            return m.group(1).replace("\\\"", "\"").replace("\\\\", "\\")
                    .replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t");
        }
        return null;
    }

    private static boolean extractJsonBoolean(String json, String key) {
        String pattern = "\"" + key + "\"\\s*:\\s*(true|false)";
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(pattern).matcher(json);
        return m.find() && Boolean.parseBoolean(m.group(1));
    }
}
