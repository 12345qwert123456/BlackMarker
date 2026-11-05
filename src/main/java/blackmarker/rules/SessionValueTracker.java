package blackmarker.rules;

import blackmarker.model.MaskMatch;
import blackmarker.model.RuleCategory;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Automatically tracks session-specific values (cookies, tokens, CSRF tokens)
 * observed during the session and masks them in subsequent requests/responses.
 *
 * Callers (the HTTP handler) feed it individual headers and small bodies; nothing here
 * ever sees or keeps a whole HTTP message. The set of tracked values is bounded.
 */
public class SessionValueTracker {

    /** Upper bound on remembered values; the oldest are evicted first. */
    public static final int MAX_TRACKED_VALUES = 1000;

    private volatile boolean enabled = true;
    private volatile int minValueLength = 8;

    /** value -> description/source, insertion ordered; guarded by {@code this}. */
    private final LinkedHashMap<String, String> trackedValues = new LinkedHashMap<>();

    /** Headers whose whole value (minus an auth scheme) is tracked. */
    private static final Set<String> TRACKED_HEADERS = Set.of(
        "authorization", "x-api-key", "x-auth-token",
        "x-csrf-token", "x-xsrf-token", "x-access-token"
    );

    /** Cookie names whose values are tracked (lowercase). */
    private static final Set<String> TRACKED_COOKIE_NAMES = Set.of(
        "jsessionid", "phpsessid", "asp.net_sessionid", "session",
        "session_id", "sid", "token", "auth_token", "access_token",
        "csrf_token", "_csrf", "xsrf-token"
    );

    /** JSON/form parameter names whose values are tracked (lowercase). */
    private static final Set<String> TRACKED_PARAM_NAMES = Set.of(
        "access_token", "refresh_token", "token", "session_token",
        "csrf_token", "authenticity_token", "api_key", "apikey", "_token"
    );

    /** Matches {@code "param_name": "value"} for every tracked parameter in one pass. */
    private static final Pattern JSON_PARAM = Pattern.compile(
        "\"(" + String.join("|", TRACKED_PARAM_NAMES) + ")\"\\s*:\\s*\"([^\"]+)\"",
        Pattern.CASE_INSENSITIVE);

    /**
     * Learn from a single header. Cheap for headers that are not interesting.
     */
    public void learnFromHeader(String name, String value) {
        if (!enabled || name == null || value == null) return;
        String lname = name.toLowerCase(Locale.ROOT);

        if (lname.equals("cookie") || lname.equals("set-cookie")) {
            learnFromCookieHeader(value);
        } else if (TRACKED_HEADERS.contains(lname)) {
            String v = value.strip();
            if (lname.equals("authorization")) {
                // Track the credential itself, not the "Bearer " / "Basic " scheme
                int sp = v.indexOf(' ');
                if (sp > 0) v = v.substring(sp + 1).strip();
            }
            trackValue(v, "Header: " + lname);
        }
    }

    private void learnFromCookieHeader(String headerValue) {
        for (String cookie : headerValue.split(";")) {
            String[] parts = cookie.trim().split("=", 2);
            if (parts.length == 2) {
                String name = parts[0].trim();
                if (TRACKED_COOKIE_NAMES.contains(name.toLowerCase(Locale.ROOT))) {
                    trackValue(parts[1].trim(), "Cookie: " + name);
                }
            }
        }
    }

    /**
     * Learn from a JSON body.
     */
    public void learnFromJson(String body) {
        if (!enabled || body == null || body.isEmpty()) return;
        Matcher m = JSON_PARAM.matcher(body);
        while (m.find()) {
            trackValue(m.group(2), "JSON param: " + m.group(1).toLowerCase(Locale.ROOT));
        }
    }

    /**
     * Learn from an application/x-www-form-urlencoded body.
     */
    public void learnFromForm(String body) {
        if (!enabled || body == null || body.isEmpty()) return;
        for (String pair : body.trim().split("&")) {
            String[] parts = pair.split("=", 2);
            if (parts.length == 2) {
                String name = parts[0].trim().toLowerCase(Locale.ROOT);
                if (TRACKED_PARAM_NAMES.contains(name)) {
                    trackValue(parts[1].trim(), "Form param: " + name);
                }
            }
        }
    }

    private void trackValue(String value, String source) {
        // Avoid tracking very common or meaningless values
        if (value.length() < minValueLength) return;
        if (value.equalsIgnoreCase("true") || value.equalsIgnoreCase("false")) return;
        if (value.equalsIgnoreCase("null") || value.equalsIgnoreCase("undefined")) return;
        put(value, source);
    }

    private synchronized void put(String value, String source) {
        // Re-insert so a value seen again counts as recent
        trackedValues.remove(value);
        trackedValues.put(value, source);
        if (trackedValues.size() > MAX_TRACKED_VALUES) {
            Iterator<String> it = trackedValues.keySet().iterator();
            it.next();
            it.remove();
        }
    }

    private synchronized List<Map.Entry<String, String>> snapshot() {
        return new ArrayList<>(trackedValues.entrySet());
    }

    /**
     * Detect tracked session values in text.
     */
    public List<MaskMatch> detect(String text) {
        List<MaskMatch> matches = new ArrayList<>();
        if (!enabled || text == null || text.isEmpty()) {
            return matches;
        }

        for (Map.Entry<String, String> entry : snapshot()) {
            String value = entry.getKey();
            if (value.length() > text.length()) continue;
            String source = entry.getValue();
            int idx = 0;
            while ((idx = text.indexOf(value, idx)) >= 0) {
                matches.add(new MaskMatch(
                    idx, idx + value.length(),
                    RuleCategory.SESSION,
                    "Auto-learned: " + source,
                    '█'
                ));
                idx += value.length();
            }
        }

        return matches;
    }

    // --- Management ---

    public synchronized void clearTrackedValues() {
        trackedValues.clear();
    }

    public synchronized int getTrackedValueCount() {
        return trackedValues.size();
    }

    /** Snapshot copy (value -> source), oldest first. */
    public synchronized Map<String, String> getTrackedValues() {
        return Collections.unmodifiableMap(new LinkedHashMap<>(trackedValues));
    }

    public synchronized void removeTrackedValue(String value) {
        trackedValues.remove(value);
    }

    /**
     * Track a value added manually by the user (right-click → Mask selection).
     */
    public void trackManualValue(String value) {
        if (value != null && value.length() >= 4) {
            put(value, "Manual mask");
        }
    }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public int getMinValueLength() { return minValueLength; }
    public void setMinValueLength(int minValueLength) { this.minValueLength = minValueLength; }
}
