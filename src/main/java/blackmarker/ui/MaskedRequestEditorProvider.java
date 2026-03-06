package blackmarker.ui;

import blackmarker.engine.MaskingEngine;
import blackmarker.model.MaskingResult;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;

import javax.swing.*;
import java.awt.*;

/**
 * Provides a custom "BlackMarker" tab in every HTTP request editor
 * (Proxy, Repeater, Intruder, etc.) that shows the masked version of the request.
 * Uses MaskedTextPane for click-to-reveal and correct mask-char rendering,
 * with Burp theme applied via applyThemeToComponent for native look&feel.
 */
public class MaskedRequestEditorProvider implements HttpRequestEditorProvider {

    private final MontoyaApi api;
    private final MaskingEngine engine;

    public MaskedRequestEditorProvider(MontoyaApi api, MaskingEngine engine) {
        this.api = api;
        this.engine = engine;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext creationContext) {
        return new MaskedRequestEditor();
    }

    private class MaskedRequestEditor implements ExtensionProvidedHttpRequestEditor {

        private final JPanel mainPanel;
        private final MaskedTextPane textPane;
        private final JLabel statusLabel;
        private HttpRequestResponse currentRequestResponse;
        private boolean maskingActive = true;

        MaskedRequestEditor() {
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

            JToggleButton hideHeadersBtn = new JToggleButton("\u25bc Hide uninteresting", false);
            hideHeadersBtn.setFont(new Font("SansSerif", Font.PLAIN, 11));
            hideHeadersBtn.addActionListener(e -> {
                textPane.setHideUninterestingHeaders(hideHeadersBtn.isSelected());
                hideHeadersBtn.setText(hideHeadersBtn.isSelected()
                    ? "\u25b2 Show all headers" : "\u25bc Hide uninteresting");
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

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            this.currentRequestResponse = requestResponse;
            refreshDisplay();
        }

        private void refreshDisplay() {
            if (currentRequestResponse == null || currentRequestResponse.request() == null) {
                textPane.displayPlainText("");
                statusLabel.setText("");
                return;
            }

            String rawRequest = currentRequestResponse.request().toString();

            if (maskingActive && engine.isEnabled()) {
                MaskingResult result = engine.mask(rawRequest);
                textPane.displayMaskedResult(result);
                statusLabel.setText(result.getSummary() + " ");
                statusLabel.setForeground(result.hasMatches() ?
                    ColorScheme.WARNING : ColorScheme.TEXT_SECONDARY);
            } else {
                textPane.displayPlainText(rawRequest);
                statusLabel.setText("Masking disabled ");
                statusLabel.setForeground(ColorScheme.TEXT_SECONDARY);
            }
        }

        private void copyMaskedToClipboard() {
            String text = textPane.getMaskedText();
            if (text != null && !text.isEmpty()) {
                java.awt.datatransfer.StringSelection sel =
                    new java.awt.datatransfer.StringSelection(text);
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, null);
            }
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse requestResponse) {
            return requestResponse != null && requestResponse.request() != null;
        }

        @Override
        public String caption() {
            return "BlackMarker";
        }

        @Override
        public Component uiComponent() {
            return mainPanel;
        }

        @Override
        public Selection selectedData() {
            String selected = textPane.getSelectedMaskedText();
            if (selected == null || selected.isEmpty()) {
                return null;
            }
            return Selection.selection(
                burp.api.montoya.core.ByteArray.byteArray(selected)
            );
        }

        @Override
        public boolean isModified() {
            return false;
        }

        @Override
        public HttpRequest getRequest() {
            if (currentRequestResponse != null) {
                return currentRequestResponse.request();
            }
            return null;
        }
    }
}
