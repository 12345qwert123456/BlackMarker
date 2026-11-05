package blackmarker.rules;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class EntropyDetectorTest {

    @Test
    void detectsRandomLookingTokenButNotOrdinaryText() {
        EntropyDetector d = new EntropyDetector();
        String text = "id=Zk39dLmQ81xYpV02aQw7rTuB5nHc and Content-Type: application/json plus plainlowercasewordsonly";
        var matches = d.detect(text);
        assertEquals(1, matches.size());
        assertEquals("Zk39dLmQ81xYpV02aQw7rTuB5nHc",
            text.substring(matches.get(0).getStart(), matches.get(0).getEnd()));
    }

    @Test
    void entropyOfUniformStringIsZeroAndGrowsWithVariety() {
        assertEquals(0.0, EntropyDetector.calculateShannonEntropy("aaaa"), 1e-9);
        assertEquals(2.0, EntropyDetector.calculateShannonEntropy("abcd"), 1e-9);
    }

    @Test
    void disabledDetectorFindsNothing() {
        EntropyDetector d = new EntropyDetector();
        d.setEnabled(false);
        assertTrue(d.detect("Zk39dLmQ81xYpV02aQw7rTuB5nHc").isEmpty());
    }
}
