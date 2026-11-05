package blackmarker.engine;

import blackmarker.model.MaskingResult;
import blackmarker.model.MaskingRule;
import blackmarker.model.RuleCategory;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MaskingEngineTest {

    private static final char BLOCK = '█';

    @Test
    void maskingKeepsLengthAndHidesCookieValueButNotName() {
        MaskingEngine engine = new MaskingEngine();
        String raw = "GET / HTTP/1.1\r\nHost: example.com\r\nCookie: theme=dark; sessionkey=Zk39dLmQ81xYpV02\r\n\r\n";

        MaskingResult result = engine.mask(raw);

        assertEquals(raw.length(), result.getMaskedText().length());
        assertTrue(result.getMaskedText().contains("sessionkey="));
        assertFalse(result.getMaskedText().contains("Zk39dLmQ81xYpV02"));
        assertTrue(result.getMaskedText().indexOf(BLOCK) > 0);
    }

    @Test
    void captureGroupRuleMasksOnlyTheValue() {
        MaskingEngine engine = new MaskingEngine();
        String raw = "{\"password\": \"SuperSecret123!\"}";

        String masked = engine.mask(raw).getMaskedText();

        assertTrue(masked.contains("password"));
        assertFalse(masked.contains("SuperSecret123"));
    }

    @Test
    void disabledEngineLeavesTextUntouched() {
        MaskingEngine engine = new MaskingEngine();
        engine.setEnabled(false);
        assertEquals("a@b.com", engine.mask("a@b.com").getMaskedText());
    }

    @Test
    void catastrophicRegexIsAbortedInsteadOfHanging() {
        MaskingEngine engine = new MaskingEngine();
        engine.addRule(new MaskingRule("evil", "(a+)+$", RuleCategory.CUSTOM, '█', true, false, ""));
        String hostile = "a".repeat(5000) + "!";

        MaskingResult[] holder = new MaskingResult[1];
        assertTimeoutPreemptively(Duration.ofSeconds(20), () -> holder[0] = engine.mask(hostile));
        assertNotNull(holder[0]);
    }

    @Test
    void clipDropsTheTailOfHugeMessages() {
        String huge = "x".repeat(MaskingEngine.MAX_DISPLAY_CHARS + 10);
        String clipped = MaskingEngine.clip(huge);
        assertTrue(clipped.length() < huge.length() + 200);
        assertTrue(clipped.contains("truncated"));
        assertEquals("short", MaskingEngine.clip("short"));
    }

    @Test
    void customRulesRoundTripIncludingTrickyRegexAndCaptureGroup() {
        MaskingEngine source = new MaskingEngine();
        source.addRule(new MaskingRule("Weird {1},{2} (rule)", "id=(\\d{1,3},{2}x)", RuleCategory.CUSTOM,
            '*', true, false, "desc \"quoted\"", 1, true));

        MaskingEngine target = new MaskingEngine();
        int before = target.getRules().size();
        MaskingEngine.ImportSummary summary = target.loadCustomRules(source.serializeCustomRules());

        assertEquals(1, summary.added());
        assertEquals(before + 1, target.getRules().size());
        MaskingRule loaded = target.getRules().get(before);
        assertEquals("Weird {1},{2} (rule)", loaded.getName());
        assertEquals("id=(\\d{1,3},{2}x)", loaded.getRegex());
        assertEquals(1, loaded.getCaptureGroupToMask());
        assertTrue(loaded.isPreserveEdges());
        assertEquals('*', loaded.getMaskChar());
        assertEquals("desc \"quoted\"", loaded.getDescription());

        // importing the same file again adds nothing
        assertEquals(1, target.loadCustomRules(source.serializeCustomRules()).duplicates());
    }

    @Test
    void importSkipsInvalidRegexAndRejectsMalformedJson() {
        MaskingEngine engine = new MaskingEngine();
        MaskingEngine.ImportSummary s = engine.loadCustomRules(
            "[{\"name\":\"bad\",\"regex\":\"(unclosed\"},{\"name\":\"ok\",\"regex\":\"foo\\\\d+\"}]");
        assertEquals(1, s.added());
        assertEquals(1, s.invalid());
        assertThrows(RuntimeException.class, () -> engine.loadCustomRules("not json"));
    }

    @Test
    void builtInStateRestoresRulesWhoseNamesContainParentheses() {
        MaskingEngine first = new MaskingEngine();
        List<MaskingRule> paren = first.getRules().stream()
            .filter(r -> r.getName().contains("(")).toList();
        assertFalse(paren.isEmpty());
        paren.forEach(r -> r.setEnabled(false));

        MaskingEngine second = new MaskingEngine();
        second.loadBuiltInState(first.serializeBuiltInState());

        for (MaskingRule r : paren) {
            MaskingRule restored = second.getRules().stream()
                .filter(x -> x.getName().equals(r.getName())).findFirst().orElseThrow();
            assertFalse(restored.isEnabled(), r.getName());
        }
    }

    @Test
    void editedAndDeletedBuiltInRulesSurviveRestart() {
        MaskingEngine first = new MaskingEngine();
        MaskingRule pwd = first.getRules().stream()
            .filter(r -> r.getName().equals("Password (Form/JSON)")).findFirst().orElseThrow();
        int idx = first.getRules().indexOf(pwd);
        first.updateRule(idx, new MaskingRule(pwd.getName(), "(?:pw)=(\\S+)", pwd.getCategory(), pwd.getMaskChar(),
            true, true, pwd.getDescription(), 1, true));
        int ssn = first.getRules().indexOf(first.getRules().stream()
            .filter(r -> r.getName().equals("SSN (US)")).findFirst().orElseThrow());
        first.removeRule(ssn);

        MaskingEngine second = new MaskingEngine();
        second.loadBuiltInOverrides(first.serializeBuiltInOverrides());

        assertEquals(first.getRules().size(), second.getRules().size());
        MaskingRule edited = second.getRules().stream()
            .filter(r -> r.getName().equals("Password (Form/JSON)")).findFirst().orElseThrow();
        assertEquals("(?:pw)=(\\S+)", edited.getRegex());
        assertEquals(1, edited.getCaptureGroupToMask());
        assertTrue(edited.isBuiltIn());
        assertTrue(second.getRules().stream().noneMatch(r -> r.getName().equals("SSN (US)")));
    }
}
