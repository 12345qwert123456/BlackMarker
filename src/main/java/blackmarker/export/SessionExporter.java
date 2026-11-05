package blackmarker.export;

import blackmarker.Version;
import blackmarker.engine.MaskingEngine;
import blackmarker.model.MaskMatch;
import blackmarker.model.MaskingResult;
import blackmarker.model.RuleCategory;
import blackmarker.ui.ColorScheme;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.CancellationException;

/**
 * Exports Burp proxy history as masked text or HTML files.
 * Supports plain text and styled HTML with colored category markers.
 *
 * The export runs in a {@link SwingWorker}: loading the history, masking every message and
 * writing the file never block the Swing event thread. A progress dialog allows cancelling.
 */
public class SessionExporter {

    private enum Format { HTML, TEXT }

    /** Outcome of a finished export. */
    private record ExportStats(int total, int failed) {}

    private static final DateTimeFormatter TIMESTAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final String FAILED_PLACEHOLDER =
        "[BlackMarker: this message could not be masked and was omitted]";

    private final MontoyaApi api;
    private final MaskingEngine engine;

    /** The export in progress, if any. Only touched on the EDT, except by {@link #shutdown()}. */
    private volatile ExportWorker running;

    public SessionExporter(MontoyaApi api, MaskingEngine engine) {
        this.api = api;
        this.engine = engine;
    }

    /**
     * Ask for format and target file, then export in the background. Must be called on the EDT.
     *
     * @param trigger the button that started the export; disabled while an export runs
     */
    public void showExportDialog(JButton trigger) {
        Frame parent = api.userInterface().swingUtils().suiteFrame();

        if (running != null) {
            JOptionPane.showMessageDialog(parent, "An export is already in progress.",
                "BlackMarker - Export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        if (!engine.isEnabled()) {
            int proceed = JOptionPane.showConfirmDialog(parent,
                "Masking is currently OFF. The export would contain the raw, unmasked data.\n\n"
                    + "Export anyway?",
                "BlackMarker - Masking is off", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (proceed != JOptionPane.YES_OPTION) return;
        }

        String[] options = {"HTML (Colored)", "Plain Text", "Cancel"};
        int choice = JOptionPane.showOptionDialog(parent,
            "Select export format for masked proxy history:",
            "BlackMarker - Export Masked Session",
            JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE,
            null, options, options[0]);
        if (choice != 0 && choice != 1) return;
        Format format = choice == 0 ? Format.HTML : Format.TEXT;

        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Save Masked Session");
        fc.setSelectedFile(new File("blackmarker_session_" +
            LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss")) +
            (format == Format.HTML ? ".html" : ".txt")));
        if (fc.showSaveDialog(parent) != JFileChooser.APPROVE_OPTION) return;

        File file = fc.getSelectedFile();
        if (file.exists()) {
            int overwrite = JOptionPane.showConfirmDialog(parent,
                file.getName() + " already exists. Overwrite it?",
                "Confirm overwrite", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (overwrite != JOptionPane.YES_OPTION) return;
        }

        start(file, format, parent, trigger);
    }

    /** Cancel any export in progress (called when the extension unloads). */
    public void shutdown() {
        ExportWorker worker = running;
        if (worker != null) worker.cancel(true);
    }

    // =====================================================================
    // Background export
    // =====================================================================

    private void start(File file, Format format, Frame parent, JButton trigger) {
        ExportWorker worker = new ExportWorker(file, format);

        JProgressBar bar = new JProgressBar();
        bar.setIndeterminate(true);
        JLabel label = new JLabel("Loading proxy history...");
        JButton cancel = new JButton("Cancel");

        JDialog dialog = new JDialog(parent, "BlackMarker - Exporting", false);
        JPanel content = new JPanel(new BorderLayout(8, 8));
        content.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        content.add(label, BorderLayout.NORTH);
        content.add(bar, BorderLayout.CENTER);
        JPanel south = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        south.add(cancel);
        content.add(south, BorderLayout.SOUTH);
        dialog.setContentPane(content);
        dialog.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
        dialog.addWindowListener(new java.awt.event.WindowAdapter() {
            @Override public void windowClosing(java.awt.event.WindowEvent e) { worker.cancel(true); }
        });
        cancel.addActionListener(e -> {
            cancel.setEnabled(false);
            worker.cancel(true);
        });
        dialog.setSize(380, 140);
        dialog.setLocationRelativeTo(parent);

        worker.bind(bar, label, dialog, trigger, parent);
        running = worker;
        if (trigger != null) trigger.setEnabled(false);
        dialog.setVisible(true);
        worker.execute();
    }

    private final class ExportWorker extends SwingWorker<ExportStats, Integer> {

        private final File file;
        private final Format format;
        private volatile int total;

        private JProgressBar bar;
        private JLabel label;
        private JDialog dialog;
        private JButton trigger;
        private Frame parent;

        ExportWorker(File file, Format format) {
            this.file = file;
            this.format = format;
        }

        void bind(JProgressBar bar, JLabel label, JDialog dialog, JButton trigger, Frame parent) {
            this.bar = bar;
            this.label = label;
            this.dialog = dialog;
            this.trigger = trigger;
            this.parent = parent;
        }

        @Override
        protected ExportStats doInBackground() throws Exception {
            // Burp does not report exceptions thrown on extension threads, so log them here
            try {
                List<ProxyHttpRequestResponse> history = api.proxy().history();
                total = history.size();
                publish(0);
                return write(history);
            } catch (CancellationException | InterruptedIOException e) {
                throw e;
            } catch (Throwable t) {
                api.logging().logToError("[BlackMarker] Export failed: " + t);
                throw t;
            }
        }

        private ExportStats write(List<ProxyHttpRequestResponse> history) throws IOException {
            int failed = 0;
            try (BufferedWriter w = new BufferedWriter(
                    new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8))) {

                writeHeader(w, history.size());
                int num = 0;
                for (ProxyHttpRequestResponse item : history) {
                    if (isCancelled() || Thread.currentThread().isInterrupted()) {
                        throw new CancellationException();
                    }
                    num++;
                    if (!writeMessage(w, num, item)) failed++;
                    if (num % 25 == 0 || num == history.size()) publish(num);
                }
                writeFooter(w);
            } catch (CancellationException e) {
                // Do not leave a partial file behind
                //noinspection ResultOfMethodCallIgnored
                file.delete();
                throw e;
            }

            api.logging().logToOutput("[BlackMarker] Exported " + history.size() +
                " messages to " + file.getAbsolutePath() + (failed > 0 ? " (" + failed + " failed)" : ""));
            return new ExportStats(history.size(), failed);
        }

        @Override
        protected void process(List<Integer> chunks) {
            int done = chunks.get(chunks.size() - 1);
            int t = total;
            if (t > 0) {
                bar.setIndeterminate(false);
                bar.setMaximum(t);
                bar.setValue(done);
                label.setText("Exporting message " + done + " of " + t + "...");
            } else {
                label.setText("No proxy history to export...");
            }
        }

        @Override
        protected void done() {
            running = null;
            if (trigger != null) trigger.setEnabled(true);
            dialog.dispose();

            try {
                ExportStats stats = get();
                String detail = stats.failed() > 0
                    ? "\n" + stats.failed() + " message(s) could not be masked and were omitted (see Errors log)."
                    : "";
                JOptionPane.showMessageDialog(parent,
                    "Exported " + stats.total() + " message(s) to:\n" + file.getAbsolutePath() + detail,
                    "Export Complete", JOptionPane.INFORMATION_MESSAGE);
            } catch (CancellationException e) {
                api.logging().logToOutput("[BlackMarker] Export cancelled");
            } catch (java.util.concurrent.ExecutionException e) {
                Throwable cause = e.getCause() != null ? e.getCause() : e;
                if (cause instanceof CancellationException || cause instanceof InterruptedIOException) {
                    api.logging().logToOutput("[BlackMarker] Export cancelled");
                    return;
                }
                JOptionPane.showMessageDialog(parent, "Export failed: " + cause.getMessage(),
                    "Export Error", JOptionPane.ERROR_MESSAGE);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        // ----- file content -----

        private void writeHeader(BufferedWriter w, int count) throws IOException {
            String now = LocalDateTime.now().format(TIMESTAMP);
            if (format == Format.TEXT) {
                w.write("========================================\n");
                w.write("  BlackMarker - Masked Session Export\n");
                w.write("  Date: " + now + "\n");
                w.write("  Total Messages: " + count + "\n");
                w.write("========================================\n\n");
                return;
            }

            w.write("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
            w.write("<meta charset=\"UTF-8\">\n");
            w.write("<title>BlackMarker - Masked Session Export</title>\n");
            w.write("<style>\n");
            w.write("body { font-family: 'Segoe UI', Tahoma, sans-serif; " +
                "background: #1e1e1e; color: #d4d4d4; margin: 20px; }\n");
            w.write("h1 { color: #4169E1; }\n");
            w.write("h2 { color: #888; border-bottom: 1px solid #444; padding-bottom: 5px; }\n");
            w.write("pre { background: #2d2d2d; padding: 12px; border-radius: 6px; " +
                "overflow-x: auto; font-size: 13px; line-height: 1.4; " +
                "font-family: 'Cascadia Code', 'Fira Code', monospace; }\n");
            w.write(".label { display: inline-block; padding: 2px 8px; " +
                "border-radius: 3px; font-size: 11px; font-weight: bold; margin: 2px; }\n");
            w.write(".stats { color: #888; font-size: 12px; margin-bottom: 5px; }\n");
            w.write(".message { margin-bottom: 30px; border: 1px solid #333; " +
                "border-radius: 8px; padding: 15px; }\n");

            // Category color classes
            for (RuleCategory cat : RuleCategory.values()) {
                Color fg = ColorScheme.getCategoryForegroundColor(cat);
                Color bg = ColorScheme.getCategoryBackgroundColor(cat);
                w.write(String.format(
                    ".mask-%s { color: rgb(%d,%d,%d); background: rgba(%d,%d,%d,0.3); font-weight: bold; }\n",
                    cat.name().toLowerCase(),
                    fg.getRed(), fg.getGreen(), fg.getBlue(),
                    bg.getRed(), bg.getGreen(), bg.getBlue()));
            }

            w.write("</style>\n</head>\n<body>\n");
            w.write("<h1>&#x2588; BlackMarker — Masked Session Export</h1>\n");
            w.write("<p>Date: " + now + " | Messages: " + count + "</p>\n");

            w.write("<p><strong>Color Legend:</strong> ");
            for (RuleCategory cat : RuleCategory.values()) {
                w.write(String.format("<span class=\"label mask-%s\">%s</span> ",
                    cat.name().toLowerCase(), cat.getDisplayName()));
            }
            w.write("</p>\n<hr>\n\n");
        }

        /** @return false if the message could not be masked (a placeholder is written instead) */
        private boolean writeMessage(BufferedWriter w, int num, ProxyHttpRequestResponse item) throws IOException {
            boolean html = format == Format.HTML;
            if (html) {
                w.write("<div class=\"message\">\n<h2>Message #" + num + "</h2>\n");
            } else {
                w.write("--- Message #" + num + " ---\n\n");
            }

            boolean ok = true;
            try {
                writePart(w, html, "Request", item.request() == null ? null : item.request().toString());
            } catch (RuntimeException e) {
                ok = false;
                api.logging().logToError("[BlackMarker] Message #" + num + " request: " + e);
                writePlaceholder(w, html, "Request");
            }
            try {
                writePart(w, html, "Response",
                    item.response() == null ? null : item.response().toString());
            } catch (RuntimeException e) {
                ok = false;
                api.logging().logToError("[BlackMarker] Message #" + num + " response: " + e);
                writePlaceholder(w, html, "Response");
            }

            w.write(html ? "</div>\n\n" : "---\n\n");
            return ok;
        }

        private void writePart(BufferedWriter w, boolean html, String title, String raw) throws IOException {
            if (raw == null) return;
            MaskingResult result = engine.mask(MaskingEngine.clip(raw));
            if (html) {
                w.write("<p class=\"stats\">" + title + " — " + result.getMatchCount() + " items masked</p>\n");
                w.write("<pre>");
                w.write(toColoredHtml(result));
                w.write("</pre>\n");
            } else {
                w.write("[" + title.toUpperCase() + "] (" + result.getMatchCount() + " items masked)\n");
                w.write(result.getMaskedText());
                w.write("\n\n");
            }
        }

        private void writePlaceholder(BufferedWriter w, boolean html, String title) throws IOException {
            if (html) {
                w.write("<p class=\"stats\">" + title + " — " + escapeHtml(FAILED_PLACEHOLDER) + "</p>\n");
            } else {
                w.write("[" + title.toUpperCase() + "] " + FAILED_PLACEHOLDER + "\n\n");
            }
        }

        private void writeFooter(BufferedWriter w) throws IOException {
            if (format == Format.TEXT) {
                w.write("=== End of Export ===\n");
            } else {
                w.write("<hr>\n<p style=\"color:#666\">Generated by BlackMarker v" + Version.get() + "</p>\n");
                w.write("</body>\n</html>\n");
            }
        }
    }

    /**
     * Convert a MaskingResult to HTML with colored spans for masked regions.
     */
    private static String toColoredHtml(MaskingResult result) {
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
