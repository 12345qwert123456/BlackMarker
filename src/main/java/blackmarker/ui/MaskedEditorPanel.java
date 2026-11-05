package blackmarker.ui;

import blackmarker.engine.MaskingEngine;
import blackmarker.model.MaskingResult;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.concurrent.ExecutionException;

/**
 * UI shared by the request and response "BlackMarker" editor tabs: toolbar, masked text pane,
 * status line and legend. The editor providers only supply the raw message text.
 *
 * Masking of large messages runs in a background worker so the Burp UI stays responsive;
 * until it finishes the pane shows a placeholder, never the raw text.
 */
final class MaskedEditorPanel {

    /** Messages longer than this are masked off the EDT. */
    private static final int ASYNC_THRESHOLD_CHARS = 200_000;

    private final MontoyaApi api;
    private final MaskingEngine engine;
    private final JPanel mainPanel;
    private final MaskedTextPane textPane;
    private final JLabel statusLabel;

    private String currentRaw;
    private boolean maskingActive = true;
    /** Incremented on every refresh; stale background results are discarded. */
    private int generation;

    MaskedEditorPanel(MontoyaApi api, MaskingEngine engine) {
        this.api = api;
        this.engine = engine;

        mainPanel = new JPanel(new BorderLayout());

        // Main text pane
        textPane = new MaskedTextPane();
        textPane.setSessionValueTracker(engine.getSessionValueTracker());

        // Top toolbar
        JPanel toolbar = new JPanel(new BorderLayout());
        toolbar.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));

        JPanel leftToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));

        JToggleButton toggleBtn = new JToggleButton("Masking ON", true);
        toggleBtn.setFont(new Font("SansSerif", Font.BOLD, 11));
        toggleBtn.setForeground(ColorScheme.STATUS_ENABLED);
        toggleBtn.addActionListener(e -> {
            maskingActive = toggleBtn.isSelected();
            toggleBtn.setText(maskingActive ? "Masking ON" : "Masking OFF");
            toggleBtn.setForeground(maskingActive ?
                ColorScheme.STATUS_ENABLED : ColorScheme.STATUS_DISABLED);
            refreshDisplay();
        });
        leftToolbar.add(toggleBtn);

        JButton copyMaskedBtn = new JButton("Copy Masked");
        copyMaskedBtn.addActionListener(e -> copyMaskedToClipboard());
        leftToolbar.add(copyMaskedBtn);

        JToggleButton wrapBtn = new JToggleButton("Wrap", true);
        wrapBtn.setFont(new Font("SansSerif", Font.PLAIN, 11));
        wrapBtn.addActionListener(e -> textPane.setLineWrapEnabled(wrapBtn.isSelected()));
        leftToolbar.add(wrapBtn);

        JToggleButton hideHeadersBtn = new JToggleButton("▼ Hide uninteresting", false);
        hideHeadersBtn.setFont(new Font("SansSerif", Font.PLAIN, 11));
        hideHeadersBtn.addActionListener(e -> {
            textPane.setHideUninterestingHeaders(hideHeadersBtn.isSelected());
            hideHeadersBtn.setText(hideHeadersBtn.isSelected()
                ? "▲ Show all headers" : "▼ Hide uninteresting");
        });
        leftToolbar.add(hideHeadersBtn);

        toolbar.add(leftToolbar, BorderLayout.WEST);

        statusLabel = new JLabel("");
        statusLabel.setFont(new Font("SansSerif", Font.PLAIN, 11));
        toolbar.add(statusLabel, BorderLayout.EAST);

        mainPanel.add(toolbar, BorderLayout.NORTH);
        mainPanel.add(new JScrollPane(textPane), BorderLayout.CENTER);

        // Bottom legend
        JPanel legendPanel = ColorScheme.createLegendPanel();
        legendPanel.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));
        mainPanel.add(legendPanel, BorderLayout.SOUTH);

        // Apply Burp's theme (colors, fonts, dark/light mode) to the whole panel
        api.userInterface().applyThemeToComponent(mainPanel);
    }

    Component component() {
        return mainPanel;
    }

    String selectedMaskedText() {
        return textPane.getSelectedMaskedText();
    }

    /** Show a new message; {@code null} clears the view. */
    void setRaw(String raw) {
        this.currentRaw = raw;
        refreshDisplay();
    }

    private void refreshDisplay() {
        final int gen = ++generation;
        final String raw = currentRaw;

        if (raw == null) {
            textPane.displayPlainText("");
            statusLabel.setText("");
            return;
        }

        if (!(maskingActive && engine.isEnabled())) {
            textPane.displayPlainText(MaskingEngine.clip(raw));
            statusLabel.setText("Masking disabled ");
            statusLabel.setForeground(ColorScheme.TEXT_SECONDARY);
            return;
        }

        if (raw.length() <= ASYNC_THRESHOLD_CHARS) {
            showResult(engine.mask(raw));
            return;
        }

        // Large message: mask in the background, show a placeholder meanwhile
        textPane.displayPlainText("Masking large message...");
        statusLabel.setText("Masking... ");
        statusLabel.setForeground(ColorScheme.TEXT_SECONDARY);
        new SwingWorker<MaskingResult, Void>() {
            @Override
            protected MaskingResult doInBackground() {
                return engine.mask(MaskingEngine.clip(raw));
            }

            @Override
            protected void done() {
                if (gen != generation) return; // a newer message was selected meanwhile
                try {
                    showResult(get());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } catch (ExecutionException e) {
                    api.logging().logToError("[BlackMarker] Masking failed: " + e.getCause());
                    textPane.displayPlainText("BlackMarker could not mask this message.");
                    statusLabel.setText("Masking failed ");
                }
            }
        }.execute();
    }

    private void showResult(MaskingResult result) {
        textPane.displayMaskedResult(result);
        statusLabel.setText(result.getSummary() + " ");
        statusLabel.setForeground(result.hasMatches() ?
            ColorScheme.WARNING : ColorScheme.TEXT_SECONDARY);
    }

    private void copyMaskedToClipboard() {
        String text = textPane.getMaskedText();
        if (text != null && !text.isEmpty()) {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        }
    }
}
