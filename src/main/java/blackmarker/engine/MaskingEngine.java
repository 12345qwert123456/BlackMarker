package blackmarker.engine;

import blackmarker.model.*;
import blackmarker.rules.DefaultRules;
import blackmarker.rules.EntropyDetector;
import blackmarker.rules.SessionValueTracker;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
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
 * Thread-safe: uses CopyOnWriteArrayList for rules and a concurrent set for categories.
 * HTTP content is untrusted, so every regex runs under a time budget (see {@link DeadlineCharSequence}).
 */
public class MaskingEngine {

    /** Messages longer than this are clipped for display/export (see {@link #clip}). */
    public static final int MAX_DISPLAY_CHARS = 2_000_000;

    /** Time budget for a single rule over a single text. */
    private static final long RULE_BUDGET_MILLIS = 250;

    private static final Pattern COOKIE_HEADER = Pattern.compile(
        "^(Set-Cookie|Cookie):[ \\t]*(.+)$",
        Pattern.CASE_INSENSITIVE | Pattern.MULTILINE
    );
    private static final Pattern COOKIE_PAIR = Pattern.compile("([\\w\\-.]+)=([^\\s;]+)");

    /** Standard Set-Cookie attributes that are NOT secret values. */
    private static final Set<String> COOKIE_ATTRS = Set.of(
        "path", "domain", "expires", "max-age", "samesite",
        "secure", "httponly", "priority", "partitioned"
    );

    private final CopyOnWriteArrayList<MaskingRule> rules;
    private final EntropyDetector entropyDetector;
    private final SessionValueTracker sessionValueTracker;
    private volatile boolean enabled = true;
    private final Set<RuleCategory> enabledCategories;

    private final Set<String> timedOutRules = ConcurrentHashMap.newKeySet();
    private volatile Consumer<String> errorSink = msg -> {};

    private static volatile Map<String, MaskingRule> defaultsByName;

    public MaskingEngine() {
        this.rules = new CopyOnWriteArrayList<>(DefaultRules.createAll());
        this.entropyDetector = new EntropyDetector();
        this.sessionValueTracker = new SessionValueTracker();
        this.enabledCategories = ConcurrentHashMap.newKeySet();
        this.enabledCategories.addAll(EnumSet.allOf(RuleCategory.class));
    }

    /** Where rule problems (e.g. regex timeouts) are reported; set by the extension to Burp's error log. */
    public void setErrorSink(Consumer<String> errorSink) {
        this.errorSink = errorSink != null ? errorSink : msg -> {};
    }

    /**
     * Clip very large messages so masking/rendering stays responsive. The remainder is
     * dropped (never shown unmasked) and replaced with a note.
     */
    public static String clip(String raw) {
        if (raw == null || raw.length() <= MAX_DISPLAY_CHARS) return raw;
        return raw.substring(0, MAX_DISPLAY_CHARS)
            + "\n\n[BlackMarker: message truncated, " + (raw.length() - MAX_DISPLAY_CHARS)
            + " more characters not shown]";
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
                Matcher matcher = pattern.matcher(new DeadlineCharSequence(text, RULE_BUDGET_MILLIS));
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
            } catch (DeadlineCharSequence.RegexTimeoutException e) {
                // Pathological pattern/input (catastrophic backtracking): skip rule for this text
                if (timedOutRules.add(rule.getName())) {
                    errorSink.accept("Rule '" + rule.getName() + "' exceeded its " + RULE_BUDGET_MILLIS
                        + " ms time budget and was skipped for a message; its regex may be too expensive.");
                }
            } catch (RuntimeException e) {
                // Skip rules that fail at runtime
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
            if (effectiveChar == '█' && globalChar != '█') {
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
        Matcher headerMatcher = COOKIE_HEADER.matcher(text);
        while (headerMatcher.find()) {
            String headerName = headerMatcher.group(1);
            int valueStart = headerMatcher.start(2);
            String headerValue = headerMatcher.group(2);
            boolean isSetCookie = headerName.equalsIgnoreCase("Set-Cookie");

            // Match individual name=value pairs within the cookie header value
            Matcher pairMatcher = COOKIE_PAIR.matcher(headerValue);
            while (pairMatcher.find()) {
                String name = pairMatcher.group(1);

                // For Set-Cookie, skip standard cookie attributes
                if (isSetCookie && COOKIE_ATTRS.contains(name.toLowerCase(Locale.ROOT))) {
                    continue;
                }

                int valStart = valueStart + pairMatcher.start(2);
                int valEnd = valueStart + pairMatcher.end(2);
                matches.add(new MaskMatch(
                    valStart, valEnd,
                    RuleCategory.SESSION, "Cookie: " + name,
                    '█', true  // preserveEdges=true
                ));
            }
        }
        return matches;
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
        timedOutRules.clear();
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
    // Persistence / import-export (JSON)
    // =====================================================================

    /** Outcome of importing rules from JSON. */
    public record ImportSummary(int added, int duplicates, int invalid) {}

    /**
     * Serialize custom (non-built-in) rules to JSON for persistence and export.
     */
    public String serializeCustomRules() {
        JsonArray arr = new JsonArray();
        for (MaskingRule rule : rules) {
            if (!rule.isBuiltIn()) arr.add(ruleToJson(rule));
        }
        return arr.toString();
    }

    /**
     * Serialize the enabled/disabled state of built-in rules (name -> enabled).
     */
    public String serializeBuiltInState() {
        JsonObject obj = new JsonObject();
        for (MaskingRule rule : rules) {
            if (rule.isBuiltIn()) obj.addProperty(rule.getName(), rule.isEnabled());
        }
        return obj.toString();
    }

    /**
     * Serialize edits and deletions of built-in rules relative to the shipped defaults,
     * so they survive a restart: {"modified":[rule...],"deleted":[name...]}.
     */
    public String serializeBuiltInOverrides() {
        Map<String, MaskingRule> defaults = defaults();
        JsonArray modified = new JsonArray();
        Set<String> present = new HashSet<>();
        for (MaskingRule rule : rules) {
            if (!rule.isBuiltIn()) continue;
            present.add(rule.getName());
            MaskingRule def = defaults.get(rule.getName());
            if (def != null && !sameDefinition(def, rule)) modified.add(ruleToJson(rule));
        }
        JsonArray deleted = new JsonArray();
        for (String name : defaults.keySet()) {
            if (!present.contains(name)) deleted.add(name);
        }
        JsonObject obj = new JsonObject();
        obj.add("modified", modified);
        obj.add("deleted", deleted);
        return obj.toString();
    }

    /**
     * Apply edits/deletions of built-in rules produced by {@link #serializeBuiltInOverrides()}.
     * Call before {@link #loadBuiltInState(String)}.
     */
    public void loadBuiltInOverrides(String json) {
        if (json == null || json.isBlank()) return;
        JsonObject obj = JsonParser.parseString(json).getAsJsonObject();

        if (obj.has("deleted")) {
            Set<String> deleted = new HashSet<>();
            for (JsonElement e : obj.getAsJsonArray("deleted")) deleted.add(e.getAsString());
            rules.removeIf(r -> r.isBuiltIn() && deleted.contains(r.getName()));
        }
        if (obj.has("modified")) {
            for (JsonElement e : obj.getAsJsonArray("modified")) {
                MaskingRule edited = ruleFromJson(e.getAsJsonObject(), true);
                if (edited == null || edited.isCompilationFailed()) continue;
                for (int i = 0; i < rules.size(); i++) {
                    MaskingRule r = rules.get(i);
                    if (r.isBuiltIn() && r.getName().equals(edited.getName())) {
                        rules.set(i, edited);
                        break;
                    }
                }
            }
        }
    }

    /**
     * Restore built-in rule enabled/disabled states from {@link #serializeBuiltInState()} data.
     */
    public void loadBuiltInState(String json) {
        if (json == null || json.isBlank()) return;
        JsonObject obj = JsonParser.parseString(json).getAsJsonObject();
        for (MaskingRule rule : rules) {
            if (!rule.isBuiltIn()) continue;
            JsonElement state = obj.get(rule.getName());
            if (state != null && state.isJsonPrimitive() && state.getAsJsonPrimitive().isBoolean()) {
                rule.setEnabled(state.getAsBoolean());
            }
        }
    }

    /**
     * Load custom rules from JSON (persistence and user import). Appends to existing rules,
     * skipping rules already present (same name and regex) and rules with invalid regexes.
     *
     * @throws RuntimeException if the JSON is malformed or not an array of rules
     */
    public ImportSummary loadCustomRules(String json) {
        if (json == null || json.isBlank()) return new ImportSummary(0, 0, 0);

        JsonArray arr = JsonParser.parseString(json).getAsJsonArray();
        int added = 0, duplicates = 0, invalid = 0;
        for (JsonElement e : arr) {
            MaskingRule rule = e.isJsonObject() ? ruleFromJson(e.getAsJsonObject(), false) : null;
            if (rule == null || rule.isCompilationFailed()) {
                invalid++;
                continue;
            }
            boolean exists = false;
            for (MaskingRule existing : rules) {
                if (existing.getName().equals(rule.getName()) && existing.getRegex().equals(rule.getRegex())) {
                    exists = true;
                    break;
                }
            }
            if (exists) {
                duplicates++;
            } else {
                rules.add(rule);
                added++;
            }
        }
        return new ImportSummary(added, duplicates, invalid);
    }

    private static JsonObject ruleToJson(MaskingRule rule) {
        JsonObject o = new JsonObject();
        o.addProperty("name", rule.getName());
        o.addProperty("regex", rule.getRegex());
        o.addProperty("category", rule.getCategory().name());
        o.addProperty("maskChar", String.valueOf(rule.getMaskChar()));
        o.addProperty("enabled", rule.isEnabled());
        o.addProperty("description", rule.getDescription());
        o.addProperty("captureGroupToMask", rule.getCaptureGroupToMask());
        o.addProperty("preserveEdges", rule.isPreserveEdges());
        return o;
    }

    /** Fields are optional so files written by older versions (without capture group info) still load. */
    private static MaskingRule ruleFromJson(JsonObject o, boolean builtIn) {
        String name = str(o, "name");
        String regex = str(o, "regex");
        if (name == null || regex == null || name.isBlank() || regex.isEmpty()) return null;

        RuleCategory category;
        try {
            category = RuleCategory.valueOf(str(o, "category"));
        } catch (RuntimeException e) {
            category = RuleCategory.CUSTOM;
        }
        String maskStr = str(o, "maskChar");
        char maskChar = (maskStr != null && !maskStr.isEmpty()) ? maskStr.charAt(0) : '█';
        boolean enabled = !o.has("enabled") || !o.get("enabled").isJsonPrimitive() || o.get("enabled").getAsBoolean();
        String description = str(o, "description");
        int group = o.has("captureGroupToMask") && o.get("captureGroupToMask").isJsonPrimitive()
            ? Math.max(0, o.get("captureGroupToMask").getAsInt()) : 0;
        boolean preserve = o.has("preserveEdges") && o.get("preserveEdges").isJsonPrimitive()
            && o.get("preserveEdges").getAsBoolean();

        return new MaskingRule(name, regex, category, maskChar, enabled, builtIn,
            description != null ? description : "", group, preserve);
    }

    private static String str(JsonObject o, String key) {
        JsonElement e = o.get(key);
        return e != null && e.isJsonPrimitive() ? e.getAsString() : null;
    }

    private static boolean sameDefinition(MaskingRule a, MaskingRule b) {
        return a.getRegex().equals(b.getRegex())
            && a.getCategory() == b.getCategory()
            && a.getMaskChar() == b.getMaskChar()
            && a.getCaptureGroupToMask() == b.getCaptureGroupToMask()
            && a.isPreserveEdges() == b.isPreserveEdges()
            && Objects.equals(a.getDescription(), b.getDescription());
    }

    private static Map<String, MaskingRule> defaults() {
        Map<String, MaskingRule> d = defaultsByName;
        if (d == null) {
            d = new LinkedHashMap<>();
            for (MaskingRule r : DefaultRules.createAll()) d.putIfAbsent(r.getName(), r);
            defaultsByName = d;
        }
        return d;
    }
}
