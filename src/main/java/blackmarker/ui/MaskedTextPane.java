package blackmarker.ui;

import blackmarker.model.MaskMatch;
import blackmarker.model.MaskingResult;
import blackmarker.model.PluginSettings;
import blackmarker.model.RuleCategory;
import blackmarker.rules.SessionValueTracker;

import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Custom JTextPane that displays masked text with color-coded highlights
 * for different rule categories. Read-only display component.
 *
 * Features:
 * - Burp-style HTTP syntax coloring (dark blue header names, black values)
 * - Click-to-reveal: clicking a masked region toggles original text
 * - Hide-uninteresting-headers mode
 * - Line wrapping with zero-width space insertion for long masked runs
 */
public class MaskedTextPane extends JTextPane {

    private MaskingResult lastResult;
    /** Indices of matches that have been revealed by the user. */
    private final Set<Integer> revealedMatches = new HashSet<>();
    private boolean lineWrapEnabled = true;
    private boolean hideUninterestingHeaders = false;

    // Cached display state for click-to-reveal / right-click mask when headers may be hidden
    private List<MaskMatch> currentDisplayMatches = new ArrayList<>();
    private String currentDisplayOriginal = "";
    private int[] displayToOriginalMap; // null = identity mapping (no header hiding)
    private final List<MaskMatch> manualMasks = new ArrayList<>();
    private SessionValueTracker sessionValueTracker; // optional: auto-learn on manual mask

    /** Dark blue for header names — matches Burp Suite's style. */
    private static final Color HEADER_NAME_COLOR = new Color(0, 0, 160);
    /** Orange for request method / HTTP version on the first line. */
    private static final Color HTTP_METHOD_COLOR = new Color(116, 0, 0);

    /** Headers considered "uninteresting" (lowercase). */
    private static final Set<String> UNINTERESTING_HEADERS = Set.of(
        "accept", "accept-encoding", "accept-language", "cache-control",
        "connection", "content-length", "content-type", "dnt",
        "pragma", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
        "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
        "sec-gpc", "te", "upgrade-insecure-requests", "user-agent",
        "priority", "access-control-allow-origin", "origin",
        "x-requested-with", "vary", "etag", "date", "via",
        "x-content-type-options", "x-frame-options", "x-xss-protection",
        "strict-transport-security", "expect-ct", "feature-policy",
        "permissions-policy", "cross-origin-opener-policy",
        "cross-origin-embedder-policy", "cross-origin-resource-policy",
        "referrer-policy", "nel", "report-to", "server-timing",
        "timing-allow-origin", "transfer-encoding"
    );

    /**
     * Enable line wrapping: track viewport width so long lines wrap.
     */
    @Override
    public boolean getScrollableTracksViewportWidth() {
        if (!lineWrapEnabled) {
            return super.getScrollableTracksViewportWidth();
        }
        return true;
    }

    public boolean isLineWrapEnabled() { return lineWrapEnabled; }

    public void setLineWrapEnabled(boolean enabled) {
        this.lineWrapEnabled = enabled;
        revalidate();
        repaint();
    }

    public boolean isHideUninterestingHeaders() { return hideUninterestingHeaders; }

    public void setHideUninterestingHeaders(boolean hide) {
        this.hideUninterestingHeaders = hide;
        this.revealedMatches.clear();
        if (lastResult != null) {
            renderResult();
        } else {
            // For plain text mode, re-display
            String text = getText();
            if (text != null && !text.isEmpty()) {
                displayPlainTextInternal(text);
            }
        }
    }

    public void setSessionValueTracker(SessionValueTracker tracker) {
        this.sessionValueTracker = tracker;
    }

    public MaskedTextPane() {
        // Use a custom editor kit that breaks lines at any character, not just whitespace.
        // This is needed because the mask char █ forms one long unbreakable "word".
        setEditorKit(new WrapEditorKit());

        setEditable(false);
        setFont(new Font("Monospaced", Font.PLAIN, 13));
        setBackground(Color.WHITE);
        setForeground(Color.BLACK);
        setCaretColor(Color.BLACK);
        setSelectionColor(new Color(173, 214, 255));
        setSelectedTextColor(Color.BLACK);
        setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));

        // Click-to-reveal handler (uses currentDisplayMatches for correct positions)
        addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) return;
                if (lastResult == null || currentDisplayMatches.isEmpty()) return;

                int clickPos = viewToModel2D(e.getPoint());
                if (clickPos < 0) return;

                for (int i = 0; i < currentDisplayMatches.size(); i++) {
                    MaskMatch match = currentDisplayMatches.get(i);
                    if (clickPos >= match.getStart() && clickPos < match.getEnd()) {
                        if (revealedMatches.contains(i)) {
                            revealedMatches.remove(i);
                        } else {
                            revealedMatches.add(i);
                        }
                        renderResult();
                        return;
                    }
                }
            }
        });

        // Cursor changes over masked regions (uses currentDisplayMatches)
        addMouseMotionListener(new java.awt.event.MouseMotionAdapter() {
            @Override
            public void mouseMoved(MouseEvent e) {
                if (lastResult == null || currentDisplayMatches.isEmpty()) {
                    setCursor(Cursor.getDefaultCursor());
                    return;
                }
                int pos = viewToModel2D(e.getPoint());
                boolean overMatch = false;
                if (pos >= 0) {
                    for (MaskMatch match : currentDisplayMatches) {
                        if (pos >= match.getStart() && pos < match.getEnd()) {
                            overMatch = true;
                            break;
                        }
                    }
                }
                setCursor(overMatch ? Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
                                    : Cursor.getDefaultCursor());
            }
        });

        // Right-click context menu for manual masking
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem maskSelectionItem = new JMenuItem("\u2588 Mask selection");
        maskSelectionItem.addActionListener(ev -> maskSelection());
        popupMenu.add(maskSelectionItem);
        JMenuItem clearManualItem = new JMenuItem("\u2716 Clear manual masks");
        clearManualItem.addActionListener(ev -> clearManualMasks());
        popupMenu.add(clearManualItem);
        popupMenu.addPopupMenuListener(new javax.swing.event.PopupMenuListener() {
            @Override public void popupMenuWillBecomeVisible(javax.swing.event.PopupMenuEvent e) {
                maskSelectionItem.setEnabled(getSelectionStart() != getSelectionEnd() && lastResult != null);
                clearManualItem.setEnabled(!manualMasks.isEmpty());
            }
            @Override public void popupMenuWillBecomeInvisible(javax.swing.event.PopupMenuEvent e) {}
            @Override public void popupMenuCanceled(javax.swing.event.PopupMenuEvent e) {}
        });
        setComponentPopupMenu(popupMenu);
    }

    /**
     * Display a masking result with colored highlights for masked regions.
     */
    public void displayMaskedResult(MaskingResult result) {
        this.lastResult = result;
        this.revealedMatches.clear();
        this.manualMasks.clear();
        renderResult();
    }

    /**
     * Internal: render the current result respecting revealed matches and header hiding.
     */
    private void renderResult() {
        StyledDocument doc = getStyledDocument();

        try {
            doc.remove(0, doc.getLength());
        } catch (BadLocationException ignored) {}

        if (lastResult == null || lastResult.getMaskedText() == null) return;

        String originalText = lastResult.getOriginalText();
        String maskedText = lastResult.getMaskedText();

        // Apply manual masks to the masked text
        if (!manualMasks.isEmpty()) {
            char[] maskedChars = maskedText.toCharArray();
            for (MaskMatch manual : manualMasks) {
                for (int j = manual.getStart(); j < manual.getEnd() && j < maskedChars.length; j++) {
                    maskedChars[j] = manual.getMaskChar();
                }
            }
            maskedText = new String(maskedChars);
        }

        // Combine engine matches with manual masks
        List<MaskMatch> allMatches = new ArrayList<>(lastResult.getMatches());
        allMatches.addAll(manualMasks);

        // Optionally filter out uninteresting headers
        String displayOriginal = originalText;
        String displayMasked = maskedText;
        List<MaskMatch> displayMatches = allMatches;
        displayToOriginalMap = null; // identity by default

        if (hideUninterestingHeaders) {
            FilteredText filtered = filterUninterestingHeaders(originalText, maskedText, allMatches);
            displayOriginal = filtered.originalText;
            displayMasked = filtered.maskedText;
            displayMatches = filtered.matches;
            displayToOriginalMap = filtered.reverseMap;
        }

        // Build display text: use masked text but swap in original for revealed matches
        char[] displayChars = displayMasked.toCharArray();
        for (int i : revealedMatches) {
            if (i >= 0 && i < displayMatches.size()) {
                MaskMatch match = displayMatches.get(i);
                int end = Math.min(match.getEnd(), displayOriginal.length());
                for (int j = match.getStart(); j < end && j < displayChars.length; j++) {
                    displayChars[j] = displayOriginal.charAt(j);
                }
            }
        }
        String displayText = new String(displayChars);

        // Apply visual truncation if enabled (only shortens mask-char runs, not revealed text)
        PluginSettings pluginSettings = PluginSettings.getInstance();
        if (pluginSettings.isTruncationEnabled()) {
            TruncatedText truncated = applyDisplayTruncation(displayText, displayMatches,
                pluginSettings.getMaxMaskedLength(), pluginSettings.getGlobalMaskChar());
            if (truncated != null) {
                displayText = truncated.text;
                displayMatches = truncated.matches;
                // Compose truncation reverse map with existing header-hide map
                if (displayToOriginalMap != null) {
                    int[] composed = new int[truncated.reverseMap.length];
                    for (int idx = 0; idx < composed.length; idx++) {
                        int preTrunc = (idx < truncated.reverseMap.length) ? truncated.reverseMap[idx] : -1;
                        composed[idx] = (preTrunc >= 0 && preTrunc < displayToOriginalMap.length)
                            ? displayToOriginalMap[preTrunc] : -1;
                    }
                    displayToOriginalMap = composed;
                } else {
                    displayToOriginalMap = truncated.reverseMap;
                }
            }
        }

        // Update cached display data for click/hover handlers
        currentDisplayMatches = displayMatches;
        currentDisplayOriginal = displayOriginal;

        // Default style
        Style defaultStyle = addStyle("default", null);
        StyleConstants.setFontFamily(defaultStyle, "Monospaced");
        StyleConstants.setFontSize(defaultStyle, 13);
        StyleConstants.setForeground(defaultStyle, Color.BLACK);
        StyleConstants.setBackground(defaultStyle, Color.WHITE);

        try {
            doc.insertString(0, displayText, defaultStyle);
        } catch (BadLocationException ignored) {
            return;
        }

        // Apply HTTP syntax coloring (header names in dark blue, first line in dark red)
        applyHttpSyntaxColoring(doc, displayText);

        // Apply colored styles to masked regions
        for (int i = 0; i < displayMatches.size(); i++) {
            MaskMatch match = displayMatches.get(i);
            int start = match.getStart();
            int end = Math.min(match.getEnd(), displayText.length());
            if (start >= end || start < 0) continue;

            RuleCategory category = match.getCategory();

            if (revealedMatches.contains(i)) {
                Style revealedStyle = addStyle("revealed_" + i, null);
                StyleConstants.setFontFamily(revealedStyle, "Monospaced");
                StyleConstants.setFontSize(revealedStyle, 13);
                StyleConstants.setForeground(revealedStyle, ColorScheme.getCategoryForegroundColor(category));
                StyleConstants.setBackground(revealedStyle, new Color(255, 255, 230));
                StyleConstants.setUnderline(revealedStyle, true);
                doc.setCharacterAttributes(start, end - start, revealedStyle, true);
            } else {
                Style maskStyle = addStyle("mask_" + i, null);
                StyleConstants.setFontFamily(maskStyle, "Monospaced");
                StyleConstants.setFontSize(maskStyle, 13);
                StyleConstants.setForeground(maskStyle, ColorScheme.getCategoryForegroundColor(category));
                StyleConstants.setBackground(maskStyle, ColorScheme.getCategoryBackgroundColor(category));
                StyleConstants.setBold(maskStyle, true);
                doc.setCharacterAttributes(start, end - start, maskStyle, true);
            }
        }

        setCaretPosition(0);
    }

    /**
     * Apply Burp-style HTTP syntax coloring:
     * - First line (request line / status line) → dark red/brown
     * - Header names (up to the colon) → dark blue
     * - Header values → default black
     */
    private void applyHttpSyntaxColoring(StyledDocument doc, String text) {
        String[] lines = text.split("\n", -1);
        int pos = 0;

        for (int lineIdx = 0; lineIdx < lines.length; lineIdx++) {
            String line = lines[lineIdx];

            if (lineIdx == 0) {
                // First line: request line (GET /path HTTP/1.1) or status line (HTTP/1.1 200 OK)
                Style firstLineStyle = addStyle("firstLine", null);
                StyleConstants.setFontFamily(firstLineStyle, "Monospaced");
                StyleConstants.setFontSize(firstLineStyle, 13);
                StyleConstants.setForeground(firstLineStyle, HTTP_METHOD_COLOR);
                StyleConstants.setBold(firstLineStyle, true);
                doc.setCharacterAttributes(pos, line.length(), firstLineStyle, false);
            } else if (line.isEmpty()) {
                // Blank line = end of headers, stop coloring headers
                pos += line.length() + 1; // +1 for \n
                break;
            } else {
                // Header line: color the name part (before the colon) in dark blue
                int colonIdx = line.indexOf(':');
                if (colonIdx > 0) {
                    Style headerNameStyle = addStyle("hdrName_" + lineIdx, null);
                    StyleConstants.setFontFamily(headerNameStyle, "Monospaced");
                    StyleConstants.setFontSize(headerNameStyle, 13);
                    StyleConstants.setForeground(headerNameStyle, HEADER_NAME_COLOR);
                    StyleConstants.setBold(headerNameStyle, true);
                    // Color "HeaderName:" including the colon
                    doc.setCharacterAttributes(pos, colonIdx + 1, headerNameStyle, false);
                }
            }

            pos += line.length() + 1; // +1 for \n
        }
    }

    /**
     * Filter out lines whose header name is in the UNINTERESTING set.
     * Returns new text and remapped matches.
     */
    private FilteredText filterUninterestingHeaders(String originalText, String maskedText,
                                                     List<MaskMatch> matches) {
        String[] origLines = originalText.split("\n", -1);
        String[] maskLines = maskedText.split("\n", -1);

        StringBuilder newOrig = new StringBuilder();
        StringBuilder newMask = new StringBuilder();
        // Map from old char position to new char position
        int[] posMap = new int[originalText.length() + 1];
        Arrays.fill(posMap, -1);

        int oldPos = 0;
        int newPos = 0;
        boolean inHeaders = true;
        boolean pastFirstLine = false;

        for (int i = 0; i < origLines.length; i++) {
            String origLine = origLines[i];
            String maskLine = i < maskLines.length ? maskLines[i] : "";
            boolean keep = true;

            if (inHeaders) {
                if (!pastFirstLine) {
                    pastFirstLine = true; // Always keep the first line
                } else if (origLine.isEmpty()) {
                    inHeaders = false; // Blank line = end of headers
                } else {
                    int colon = origLine.indexOf(':');
                    if (colon > 0) {
                        String headerName = origLine.substring(0, colon).trim().toLowerCase();
                        if (UNINTERESTING_HEADERS.contains(headerName)) {
                            keep = false;
                        }
                    }
                }
            }

            if (keep) {
                // Map positions
                for (int j = 0; j < origLine.length(); j++) {
                    posMap[oldPos + j] = newPos + j;
                }
                newOrig.append(origLine);
                newMask.append(maskLine);
                if (i < origLines.length - 1) {
                    posMap[oldPos + origLine.length()] = newPos + origLine.length();
                    newOrig.append('\n');
                    newMask.append('\n');
                    newPos += origLine.length() + 1;
                } else {
                    newPos += origLine.length();
                }
            }

            oldPos += origLine.length() + (i < origLines.length - 1 ? 1 : 0);
        }

        // Remap matches
        List<MaskMatch> newMatches = new ArrayList<>();
        for (MaskMatch m : matches) {
            int newStart = m.getStart() < posMap.length ? posMap[m.getStart()] : -1;
            int newEnd = m.getEnd() < posMap.length ? posMap[m.getEnd()] :
                         (m.getEnd() - 1 < posMap.length && posMap[m.getEnd() - 1] >= 0 ?
                          posMap[m.getEnd() - 1] + 1 : -1);
            if (newStart >= 0 && newEnd > newStart) {
                newMatches.add(new MaskMatch(
                    newStart, newEnd,
                    m.getCategory(), m.getRuleName(),
                    m.getMaskChar(), m.isPreserveEdges()
                ));
            }
        }

        // Build reverse map: display position → original position
        int[] reverseMap = new int[newPos + 1];
        Arrays.fill(reverseMap, -1);
        for (int oldIdx = 0; oldIdx < posMap.length; oldIdx++) {
            if (posMap[oldIdx] >= 0 && posMap[oldIdx] < reverseMap.length) {
                reverseMap[posMap[oldIdx]] = oldIdx;
            }
        }

        return new FilteredText(newOrig.toString(), newMask.toString(), newMatches, reverseMap);
    }

    private static class FilteredText {
        final String originalText;
        final String maskedText;
        final List<MaskMatch> matches;
        final int[] reverseMap; // display position → original position

        FilteredText(String originalText, String maskedText, List<MaskMatch> matches, int[] reverseMap) {
            this.originalText = originalText;
            this.maskedText = maskedText;
            this.matches = matches;
            this.reverseMap = reverseMap;
        }
    }

    // =========================================================================
    // Visual truncation — shortens long mask-char runs for display only.
    // Positions are remapped so click-to-reveal still works correctly.
    // =========================================================================

    /**
     * Truncate long consecutive mask-char runs in the display text.
     * Returns null if no truncation was needed.
     */
    private TruncatedText applyDisplayTruncation(String displayText, List<MaskMatch> matches,
                                                  int maxLen, char globalChar) {
        if (maxLen <= 0) return null;

        boolean needsTruncation = false;
        // Quick check: any mask-char run longer than maxLen?
        int runLen = 0;
        for (int i = 0; i < displayText.length(); i++) {
            if (isTruncMaskChar(displayText.charAt(i), globalChar)) {
                runLen++;
                if (runLen > maxLen) { needsTruncation = true; break; }
            } else {
                runLen = 0;
            }
        }
        if (!needsTruncation) return null;

        StringBuilder sb = new StringBuilder();
        int[] posMap = new int[displayText.length() + 1]; // old pos → new pos
        Arrays.fill(posMap, -1);

        int newPos = 0;
        int i = 0;
        while (i < displayText.length()) {
            char c = displayText.charAt(i);
            if (isTruncMaskChar(c, globalChar)) {
                int runStart = i;
                while (i < displayText.length() && isTruncMaskChar(displayText.charAt(i), globalChar)) {
                    i++;
                }
                int run = i - runStart;

                if (run > maxLen) {
                    int half = maxLen / 2;
                    // Keep first half
                    for (int j = 0; j < half; j++) {
                        posMap[runStart + j] = newPos;
                        sb.append(displayText.charAt(runStart + j));
                        newPos++;
                    }
                    // Ellipsis (does not map to any old position)
                    sb.append('\u2026');
                    newPos++;
                    // Keep last half
                    for (int j = run - half; j < run; j++) {
                        posMap[runStart + j] = newPos;
                        sb.append(displayText.charAt(runStart + j));
                        newPos++;
                    }
                } else {
                    for (int j = runStart; j < i; j++) {
                        posMap[j] = newPos;
                        sb.append(displayText.charAt(j));
                        newPos++;
                    }
                }
            } else {
                posMap[i] = newPos;
                sb.append(c);
                newPos++;
                i++;
            }
        }
        posMap[displayText.length()] = newPos;

        // Remap match positions
        List<MaskMatch> newMatches = new ArrayList<>();
        for (MaskMatch m : matches) {
            int ns = m.getStart() < posMap.length ? posMap[m.getStart()] : -1;
            int ne = m.getEnd() < posMap.length ? posMap[m.getEnd()] :
                     (m.getEnd() - 1 < posMap.length && posMap[m.getEnd() - 1] >= 0
                         ? posMap[m.getEnd() - 1] + 1 : -1);
            if (ns >= 0 && ne > ns) {
                newMatches.add(new MaskMatch(ns, ne, m.getCategory(), m.getRuleName(),
                    m.getMaskChar(), m.isPreserveEdges()));
            }
        }

        // Build reverse map: truncated pos → pre-truncation pos
        int[] reverseMap = new int[newPos + 1];
        Arrays.fill(reverseMap, -1);
        for (int oldIdx = 0; oldIdx < posMap.length; oldIdx++) {
            if (posMap[oldIdx] >= 0 && posMap[oldIdx] < reverseMap.length) {
                reverseMap[posMap[oldIdx]] = oldIdx;
            }
        }

        return new TruncatedText(sb.toString(), newMatches, reverseMap);
    }

    private static boolean isTruncMaskChar(char c, char globalChar) {
        return c == '\u2588' || c == globalChar;
    }

    private static class TruncatedText {
        final String text;
        final List<MaskMatch> matches;
        final int[] reverseMap; // truncated pos → pre-truncation pos

        TruncatedText(String text, List<MaskMatch> matches, int[] reverseMap) {
            this.text = text;
            this.matches = matches;
            this.reverseMap = reverseMap;
        }
    }

    /**
     * Display plain (unmasked) text with HTTP syntax coloring.
     */
    public void displayPlainText(String text) {
        this.lastResult = null;
        this.revealedMatches.clear();
        displayPlainTextInternal(text);
    }

    private void displayPlainTextInternal(String text) {
        StyledDocument doc = getStyledDocument();
        try {
            doc.remove(0, doc.getLength());
        } catch (BadLocationException ignored) {}

        if (text == null || text.isEmpty()) return;

        String display = text;
        if (hideUninterestingHeaders) {
            display = filterPlainHeaders(text);
        }

        Style defaultStyle = addStyle("plainDefault", null);
        StyleConstants.setFontFamily(defaultStyle, "Monospaced");
        StyleConstants.setFontSize(defaultStyle, 13);
        StyleConstants.setForeground(defaultStyle, Color.BLACK);
        StyleConstants.setBackground(defaultStyle, Color.WHITE);

        try {
            doc.insertString(0, display, defaultStyle);
        } catch (BadLocationException ignored) {
            return;
        }

        applyHttpSyntaxColoring(doc, display);
        setCaretPosition(0);
    }

    private String filterPlainHeaders(String text) {
        String[] lines = text.split("\n", -1);
        StringBuilder sb = new StringBuilder();
        boolean inHeaders = true;
        boolean pastFirstLine = false;

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            boolean keep = true;

            if (inHeaders) {
                if (!pastFirstLine) {
                    pastFirstLine = true;
                } else if (line.isEmpty()) {
                    inHeaders = false;
                } else {
                    int colon = line.indexOf(':');
                    if (colon > 0) {
                        String headerName = line.substring(0, colon).trim().toLowerCase();
                        if (UNINTERESTING_HEADERS.contains(headerName)) {
                            keep = false;
                        }
                    }
                }
            }

            if (keep) {
                sb.append(line);
                if (i < lines.length - 1) sb.append('\n');
            }
        }
        return sb.toString();
    }

    /**
     * Reveal all masked matches at once.
     */
    public void revealAll() {
        if (lastResult != null) {
            for (int i = 0; i < currentDisplayMatches.size(); i++) {
                revealedMatches.add(i);
            }
            renderResult();
        }
    }

    /**
     * Hide all revealed matches (re-mask everything).
     */
    public void hideAll() {
        revealedMatches.clear();
        if (lastResult != null) {
            renderResult();
        }
    }

    /**
     * Get the currently displayed masked text.
     */
    public String getMaskedText() {
        if (lastResult != null) {
            return lastResult.getMaskedText();
        }
        return getText();
    }

    /**
     * Get the last masking result.
     */
    public MaskingResult getLastResult() {
        return lastResult;
    }

    /**
     * Get selected text (from the masked view).
     */
    public String getSelectedMaskedText() {
        return getSelectedText();
    }

    /**
     * Mask the currently selected text range (right-click → Mask selection).
     * Stores the mask in original-text coordinates so it survives header toggling.
     */
    private void maskSelection() {
        int selStart = getSelectionStart();
        int selEnd = getSelectionEnd();
        if (selStart >= selEnd || lastResult == null) return;

        // Trim whitespace/newlines from edges of selection (use document model, not getText())
        String selText;
        try {
            selText = getDocument().getText(selStart, selEnd - selStart);
        } catch (BadLocationException e) {
            return;
        }
        int ltrim = 0;
        while (ltrim < selText.length() && Character.isWhitespace(selText.charAt(ltrim))) ltrim++;
        int rtrim = selText.length();
        while (rtrim > ltrim && Character.isWhitespace(selText.charAt(rtrim - 1))) rtrim--;
        if (ltrim >= rtrim) return;
        selStart += ltrim;
        selEnd = selStart + (rtrim - ltrim);

        // Map display positions back to original text positions
        int origStart, origEnd;
        if (displayToOriginalMap != null) {
            origStart = (selStart < displayToOriginalMap.length) ? displayToOriginalMap[selStart] : -1;
            int lastIdx = selEnd - 1;
            origEnd = (lastIdx >= 0 && lastIdx < displayToOriginalMap.length)
                ? displayToOriginalMap[lastIdx] + 1 : -1;
            if (origStart < 0 || origEnd <= origStart) return;
        } else {
            origStart = selStart;
            origEnd = selEnd;
        }

        manualMasks.add(new MaskMatch(origStart, origEnd, RuleCategory.CUSTOM, "Manual mask", '\u2588', false));

        // Add the stripped value to auto-learn so it's masked across all messages
        if (sessionValueTracker != null) {
            String originalText = lastResult.getOriginalText();
            if (origEnd <= originalText.length()) {
                String value = originalText.substring(origStart, origEnd).strip();
                if (value.length() >= 4) {
                    sessionValueTracker.trackManualValue(value);
                }
            }
        }

        renderResult();
    }

    /**
     * Remove all manually added masks.
     */
    public void clearManualMasks() {
        if (!manualMasks.isEmpty()) {
            manualMasks.clear();
            if (lastResult != null) {
                renderResult();
            }
        }
    }

    /**
     * Create a status label showing match summary.
     */
    public static JLabel createStatusLabel(MaskingResult result) {
        JLabel label = new JLabel();
        label.setFont(new Font("SansSerif", Font.PLAIN, 11));
        if (result != null && result.hasMatches()) {
            label.setText(" " + result.getSummary() + "  [click masked text to reveal]");
            label.setForeground(new Color(200, 140, 0));
        } else {
            label.setText(" No sensitive data detected");
            label.setForeground(new Color(120, 120, 120));
        }
        return label;
    }

    // =========================================================================
    // Custom EditorKit that wraps at any character (not just whitespace).
    // Without this, long runs of █ chars never break because the default
    // LabelView only breaks at whitespace boundaries.
    // =========================================================================

    private static class WrapEditorKit extends StyledEditorKit {
        private final ViewFactory defaultFactory = new WrapColumnFactory();

        @Override
        public ViewFactory getViewFactory() {
            return defaultFactory;
        }
    }

    private static class WrapColumnFactory implements ViewFactory {
        @Override
        public View create(Element elem) {
            String kind = elem.getName();
            if (kind != null) {
                switch (kind) {
                    case AbstractDocument.ContentElementName:
                        return new WrapLabelView(elem);
                    case AbstractDocument.ParagraphElementName:
                        return new ParagraphView(elem);
                    case AbstractDocument.SectionElementName:
                        return new BoxView(elem, View.Y_AXIS);
                    case StyleConstants.ComponentElementName:
                        return new ComponentView(elem);
                    case StyleConstants.IconElementName:
                        return new IconView(elem);
                }
            }
            return new LabelView(elem);
        }
    }

    /**
     * A LabelView that allows breaking at any character position.
     */
    private static class WrapLabelView extends LabelView {
        public WrapLabelView(Element elem) {
            super(elem);
        }

        @Override
        public float getMinimumSpan(int axis) {
            if (axis == View.X_AXIS) {
                return 0;
            }
            return super.getMinimumSpan(axis);
        }
    }
}
