package blackmarker.rules;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SessionValueTrackerTest {

    @Test
    void authorizationTracksCredentialWithoutScheme() {
        SessionValueTracker t = new SessionValueTracker();
        t.learnFromHeader("Authorization", "Bearer abcdef1234567890");
        assertTrue(t.getTrackedValues().containsKey("abcdef1234567890"));
        assertFalse(t.getTrackedValues().containsKey("Bearer abcdef1234567890"));
    }

    @Test
    void setCookieTracksOnlyKnownCookieValueNotTheWholeHeader() {
        SessionValueTracker t = new SessionValueTracker();
        t.learnFromHeader("Set-Cookie", "JSESSIONID=ABCDEF0123456789; Path=/; HttpOnly");
        assertEquals(1, t.getTrackedValueCount());
        assertTrue(t.getTrackedValues().containsKey("ABCDEF0123456789"));
    }

    @Test
    void jsonAndFormParametersAreLearnedButCommonWordsAreNot() {
        SessionValueTracker t = new SessionValueTracker();
        t.learnFromJson("{\"access_token\": \"tok_1234567890abc\", \"code\": \"ERR_NOT_FOUND\", \"state\":\"statevalue123\"}");
        t.learnFromForm("csrf_token=csrfvalue12345&name=bob");
        assertTrue(t.getTrackedValues().containsKey("tok_1234567890abc"));
        assertTrue(t.getTrackedValues().containsKey("csrfvalue12345"));
        assertFalse(t.getTrackedValues().containsKey("ERR_NOT_FOUND"));
        assertFalse(t.getTrackedValues().containsKey("statevalue123"));
    }

    @Test
    void trackedValuesAreBoundedAndOldestIsEvicted() {
        SessionValueTracker t = new SessionValueTracker();
        for (int i = 0; i < SessionValueTracker.MAX_TRACKED_VALUES + 50; i++) {
            t.learnFromHeader("X-Api-Key", "key-value-" + String.format("%06d", i));
        }
        assertEquals(SessionValueTracker.MAX_TRACKED_VALUES, t.getTrackedValueCount());
        assertFalse(t.getTrackedValues().containsKey("key-value-000000"));
        assertTrue(t.getTrackedValues().containsKey(
            "key-value-" + String.format("%06d", SessionValueTracker.MAX_TRACKED_VALUES + 49)));
    }

    @Test
    void detectFindsEveryOccurrence() {
        SessionValueTracker t = new SessionValueTracker();
        t.learnFromHeader("X-Auth-Token", "secrettoken12345");
        assertEquals(2, t.detect("a secrettoken12345 b secrettoken12345 c").size());
    }

    @Test
    void disabledTrackerLearnsNothing() {
        SessionValueTracker t = new SessionValueTracker();
        t.setEnabled(false);
        t.learnFromHeader("X-Auth-Token", "secrettoken12345");
        assertEquals(0, t.getTrackedValueCount());
    }
}
