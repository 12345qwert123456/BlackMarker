package blackmarker.rules;

import blackmarker.model.MaskMatch;
import blackmarker.model.RuleCategory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Automatically tracks session-specific values (cookies, tokens, CSRF tokens)
 * observed during the session and masks them in subsequent requests/responses.
 */
public class SessionValueTracker {

    private boolean enabled = true;
    private int minValueLength = 8;

    /**
     * Map of tracked values: value -> description/source.
     */
    private final Map<String, String> trackedValues = new ConcurrentHashMap<>();

    /**
     * Headers whose values should be automatically tracked.
     */
    private static final Set<String> TRACKED_HEADERS = Set.of(
        "set-cookie", "authorization", "x-api-key", "x-auth-token",
        "x-csrf-token", "x-xsrf-token", "x-access-token"
    );

    /**
     * Cookie names whose values should be automatically tracked.
     */
    private static final Set<String> TRACKED_COOKIE_NAMES = Set.of(
        "jsessionid", "phpsessid", "asp.net_sessionid", "session",
        "session_id", "sid", "token", "auth_token", "access_token",
        "csrf_token", "_csrf", "xsrf-token"
    );

    /**
     * JSON/form parameter names whose values should be tracked.
     */
    private static final Set<String> TRACKED_PARAM_NAMES = Set.of(
        "access_token", "refresh_token", "token", "session_token",
        "csrf_token", "authenticity_token", "api_key", "apikey",
        "_token", "nonce", "state", "code"
    );

    /**
     * Learn values from an HTTP message (request or response as raw text).
     * Extracts trackable session values for future masking.
     */
    public void learnFromMessage(String rawMessage) {
        if (!enabled || rawMessage == null) return;

        // Extract header values
        learnFromHeaders(rawMessage);

        // Extract cookie values
        learnFromCookies(rawMessage);

        // Extract JSON parameter values
        learnFromJsonParams(rawMessage);

        // Extract form parameter values
        learnFromFormParams(rawMessage);
    }

    private void learnFromHeaders(String raw) {
        String[] lines = raw.split("\\r?\\n");
        for (String line : lines) {
            if (line.isEmpty()) break; // End of headers
            int colonIdx = line.indexOf(':');
            if (colonIdx <= 0) continue;
            String headerName = line.substring(0, colonIdx).trim().toLowerCase();
            String headerValue = line.substring(colonIdx + 1).trim();
            if (TRACKED_HEADERS.contains(headerName) && headerValue.length() >= minValueLength) {
                trackValue(headerValue, "Header: " + headerName);
            }
        }
    }

    private void learnFromCookies(String raw) {
        String[] lines = raw.split("\\r?\\n");
        for (String line : lines) {
            if (line.isEmpty()) break;
            String lower = line.toLowerCase().trim();

            if (lower.startsWith("cookie:") || lower.startsWith("set-cookie:")) {
                String value = line.substring(line.indexOf(':') + 1).trim();
                // Parse individual cookies
                String[] cookies = value.split(";");
                for (String cookie : cookies) {
                    String[] parts = cookie.trim().split("=", 2);
                    if (parts.length == 2) {
                        String name = parts[0].trim().toLowerCase();
                        String val = parts[1].trim();
                        if (TRACKED_COOKIE_NAMES.contains(name) && val.length() >= minValueLength) {
                            trackValue(val, "Cookie: " + parts[0].trim());
                        }
                    }
                }
            }
        }
    }

    private void learnFromJsonParams(String raw) {
        // Simple JSON extraction for known parameter names
        for (String paramName : TRACKED_PARAM_NAMES) {
            // Match "param_name": "value" or "param_name":"value"
            String pattern = "\"" + paramName + "\"\\s*:\\s*\"([^\"]+)\"";
            java.util.regex.Matcher m = java.util.regex.Pattern.compile(pattern,
                java.util.regex.Pattern.CASE_INSENSITIVE).matcher(raw);
            while (m.find()) {
                String value = m.group(1);
                if (value.length() >= minValueLength) {
                    trackValue(value, "JSON param: " + paramName);
                }
            }
        }
    }

    private void learnFromFormParams(String raw) {
        // Find URL-encoded form body (after blank line)
        int bodyStart = raw.indexOf("\r\n\r\n");
        if (bodyStart < 0) bodyStart = raw.indexOf("\n\n");
        if (bodyStart < 0) return;

        String body = raw.substring(bodyStart).trim();
        // Only process if it looks like form data
        if (body.contains("=") && !body.startsWith("{") && !body.startsWith("<")) {
            String[] pairs = body.split("&");
            for (String pair : pairs) {
                String[] parts = pair.split("=", 2);
                if (parts.length == 2) {
                    String name = parts[0].trim().toLowerCase();
                    String value = parts[1].trim();
                    if (TRACKED_PARAM_NAMES.contains(name) && value.length() >= minValueLength) {
                        trackValue(value, "Form param: " + parts[0].trim());
                    }
                }
            }
        }
    }

    private void trackValue(String value, String source) {
        // Avoid tracking very common or meaningless values
        if (value.length() < minValueLength) return;
        if (value.equalsIgnoreCase("true") || value.equalsIgnoreCase("false")) return;
        if (value.equalsIgnoreCase("null") || value.equalsIgnoreCase("undefined")) return;

        trackedValues.put(value, source);
    }

    /**
     * Detect tracked session values in text.
     */
    public List<MaskMatch> detect(String text) {
        List<MaskMatch> matches = new ArrayList<>();
        if (!enabled || text == null || trackedValues.isEmpty()) {
            return matches;
        }

        for (Map.Entry<String, String> entry : trackedValues.entrySet()) {
            String value = entry.getKey();
            String source = entry.getValue();
            int idx = 0;
            while ((idx = text.indexOf(value, idx)) >= 0) {
                matches.add(new MaskMatch(
                    idx, idx + value.length(),
                    RuleCategory.SESSION,
                    "Auto-learned: " + source,
                    '\u2588'
                ));
                idx += value.length();
            }
        }

        return matches;
    }

    // --- Management ---

    public void clearTrackedValues() {
        trackedValues.clear();
    }

    public int getTrackedValueCount() {
        return trackedValues.size();
    }

    public Map<String, String> getTrackedValues() {
        return Collections.unmodifiableMap(trackedValues);
    }

    public void removeTrackedValue(String value) {
        trackedValues.remove(value);
    }

    /**
     * Track a value added manually by the user (right-click → Mask selection).
     */
    public void trackManualValue(String value) {
        if (value != null && value.length() >= 4) {
            trackedValues.put(value, "Manual mask");
        }
    }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public int getMinValueLength() { return minValueLength; }
    public void setMinValueLength(int minValueLength) { this.minValueLength = minValueLength; }
}
