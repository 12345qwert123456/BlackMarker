package blackmarker.export;

import blackmarker.engine.MaskingEngine;
import blackmarker.model.MaskMatch;
import blackmarker.model.MaskingResult;
import blackmarker.model.RuleCategory;
import blackmarker.ui.ColorScheme;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import javax.swing.*;
import java.awt.Color;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Exports Burp proxy history as masked text or HTML files.
 * Supports plain text and styled HTML with colored category markers.
 */
public class SessionExporter {

    private final MontoyaApi api;
    private final MaskingEngine engine;

    public SessionExporter(MontoyaApi api, MaskingEngine engine) {
        this.api = api;
        this.engine = engine;
    }

    /**
     * Show export dialog and perform export.
     */
    public void showExportDialog(JComponent parent) {
        String[] options = {"HTML (Colored)", "Plain Text", "Cancel"};
        int choice = JOptionPane.showOptionDialog(parent,
            "Select export format for masked proxy history:",
            "BlackMarker - Export Masked Session",
            JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE,
            null, options, options[0]);

        if (choice == 0 || choice == 1) {
            JFileChooser fc = new JFileChooser();
            fc.setDialogTitle("Save Masked Session");
            fc.setSelectedFile(new File("blackmarker_session_" +
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss")) +
                (choice == 0 ? ".html" : ".txt")));

            if (fc.showSaveDialog(parent) == JFileChooser.APPROVE_OPTION) {
                File file = fc.getSelectedFile();
                try {
                    if (choice == 0) {
                        exportHtml(file);
                    } else {
                        exportPlainText(file);
                    }
                    JOptionPane.showMessageDialog(parent,
                        "Session exported successfully to:\n" + file.getAbsolutePath(),
                        "Export Complete", JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception e) {
                    JOptionPane.showMessageDialog(parent,
                        "Export failed: " + e.getMessage(),
                        "Export Error", JOptionPane.ERROR_MESSAGE);
                    api.logging().logToError("Export failed: " + e.getMessage());
                }
            }
        }
    }

    /**
     * Export proxy history as masked plain text.
     */
    public void exportPlainText(File file) throws IOException {
        List<ProxyHttpRequestResponse> history = api.proxy().history();

        try (BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8))) {

            writer.write("========================================\n");
            writer.write("  BlackMarker - Masked Session Export\n");
            writer.write("  Date: " + LocalDateTime.now().format(
                DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")) + "\n");
            writer.write("  Total Messages: " + history.size() + "\n");
            writer.write("========================================\n\n");

            int messageNum = 0;
            for (ProxyHttpRequestResponse item : history) {
                messageNum++;

                writer.write("--- Message #" + messageNum + " ---\n\n");

                // Request
                try {
                    HttpRequest req = item.request();
                    if (req != null) {
                        String rawReq = req.toString();
                        MaskingResult result = engine.mask(rawReq);
                        writer.write("[REQUEST] (" + result.getMatchCount() + " items masked)\n");
                        writer.write(result.getMaskedText());
                        writer.write("\n\n");
                    }
                } catch (Exception ignored) {}

                // Response
                try {
                    HttpResponse res = item.response();
                    if (res != null) {
                        String rawRes = res.toString();
                        MaskingResult result = engine.mask(rawRes);
                        writer.write("[RESPONSE] (" + result.getMatchCount() + " items masked)\n");
                        writer.write(result.getMaskedText());
                        writer.write("\n\n");
                    }
                } catch (Exception ignored) {}

                writer.write("---\n\n");
            }

            writer.write("=== End of Export ===\n");
        }

        api.logging().logToOutput("[BlackMarker] Exported " + history.size() +
            " messages to " + file.getAbsolutePath());
    }

    /**
     * Export proxy history as masked HTML with colored category highlights.
     */
    public void exportHtml(File file) throws IOException {
        List<ProxyHttpRequestResponse> history = api.proxy().history();

        try (BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8))) {

            // HTML Header
            writer.write("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
            writer.write("<meta charset=\"UTF-8\">\n");
            writer.write("<title>BlackMarker - Masked Session Export</title>\n");
            writer.write("<style>\n");
            writer.write("body { font-family: 'Segoe UI', Tahoma, sans-serif; " +
                "background: #1e1e1e; color: #d4d4d4; margin: 20px; }\n");
            writer.write("h1 { color: #4169E1; }\n");
            writer.write("h2 { color: #888; border-bottom: 1px solid #444; " +
                "padding-bottom: 5px; }\n");
            writer.write("pre { background: #2d2d2d; padding: 12px; border-radius: 6px; " +
                "overflow-x: auto; font-size: 13px; line-height: 1.4; " +
                "font-family: 'Cascadia Code', 'Fira Code', monospace; }\n");
            writer.write(".label { display: inline-block; padding: 2px 8px; " +
                "border-radius: 3px; font-size: 11px; font-weight: bold; margin: 2px; }\n");
            writer.write(".stats { color: #888; font-size: 12px; margin-bottom: 5px; }\n");
            writer.write(".message { margin-bottom: 30px; border: 1px solid #333; " +
                "border-radius: 8px; padding: 15px; }\n");

            // Category color classes
            for (RuleCategory cat : RuleCategory.values()) {
                Color fg = ColorScheme.getCategoryForegroundColor(cat);
                Color bg = ColorScheme.getCategoryBackgroundColor(cat);
                writer.write(String.format(
                    ".mask-%s { color: rgb(%d,%d,%d); background: rgba(%d,%d,%d,0.3); " +
                    "font-weight: bold; }\n",
                    cat.name().toLowerCase(),
                    fg.getRed(), fg.getGreen(), fg.getBlue(),
                    bg.getRed(), bg.getGreen(), bg.getBlue()
                ));
            }

            writer.write("</style>\n</head>\n<body>\n");
            writer.write("<h1>&#x2588; BlackMarker — Masked Session Export</h1>\n");
            writer.write("<p>Date: " + LocalDateTime.now().format(
                DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")) +
                " | Messages: " + history.size() + "</p>\n");

            // Legend
            writer.write("<p><strong>Color Legend:</strong> ");
            for (RuleCategory cat : RuleCategory.values()) {
                writer.write(String.format(
                    "<span class=\"label mask-%s\">%s</span> ",
                    cat.name().toLowerCase(), cat.getDisplayName()
                ));
            }
            writer.write("</p>\n<hr>\n\n");

            // Messages
            int messageNum = 0;
            for (ProxyHttpRequestResponse item : history) {
                messageNum++;

                writer.write("<div class=\"message\">\n");
                writer.write("<h2>Message #" + messageNum + "</h2>\n");

                // Request
                try {
                    HttpRequest req = item.request();
                    if (req != null) {
                        String rawReq = req.toString();
                        MaskingResult result = engine.mask(rawReq);
                        writer.write("<p class=\"stats\">Request — " +
                            result.getMatchCount() + " items masked</p>\n");
                        writer.write("<pre>");
                        writer.write(toColoredHtml(result));
                        writer.write("</pre>\n");
                    }
                } catch (Exception ignored) {}

                // Response
                try {
                    HttpResponse res = item.response();
                    if (res != null) {
                        String rawRes = res.toString();
                        MaskingResult result = engine.mask(rawRes);
                        writer.write("<p class=\"stats\">Response — " +
                            result.getMatchCount() + " items masked</p>\n");
                        writer.write("<pre>");
                        writer.write(toColoredHtml(result));
                        writer.write("</pre>\n");
                    }
                } catch (Exception ignored) {}

                writer.write("</div>\n\n");
            }

            writer.write("<hr>\n<p style=\"color:#666\">Generated by BlackMarker v1.0.0</p>\n");
            writer.write("</body>\n</html>\n");
        }

        api.logging().logToOutput("[BlackMarker] Exported " + history.size() +
            " messages (HTML) to " + file.getAbsolutePath());
    }

    /**
     * Convert a MaskingResult to HTML with colored spans for masked regions.
     */
    private String toColoredHtml(MaskingResult result) {
        String masked = result.getMaskedText();
        List<MaskMatch> matches = result.getMatches();

        if (matches.isEmpty()) {
            return escapeHtml(masked);
        }

        StringBuilder html = new StringBuilder();
        int lastEnd = 0;

        for (MaskMatch match : matches) {
            // Add non-masked text before this match
            if (match.getStart() > lastEnd) {
                html.append(escapeHtml(masked.substring(lastEnd, match.getStart())));
            }

            // Add masked text with colored span
            int end = Math.min(match.getEnd(), masked.length());
            String maskedChunk = masked.substring(match.getStart(), end);
            String cssClass = "mask-" + match.getCategory().name().toLowerCase();
            html.append("<span class=\"").append(cssClass)
                .append("\" title=\"").append(escapeHtml(match.getRuleName()))
                .append("\">").append(escapeHtml(maskedChunk)).append("</span>");

            lastEnd = end;
        }

        // Add remaining text
        if (lastEnd < masked.length()) {
            html.append(escapeHtml(masked.substring(lastEnd)));
        }

        return html.toString();
    }

    private static String escapeHtml(String text) {
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;");
    }
}
