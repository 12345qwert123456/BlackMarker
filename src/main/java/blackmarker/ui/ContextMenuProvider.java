package blackmarker.ui;

import blackmarker.engine.MaskingEngine;
import blackmarker.model.MaskingResult;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Provides "Copy Masked Request" and "Copy Masked Response" context menu items
 * in all Burp tools. Copies the masked version to the system clipboard.
 */
public class ContextMenuProvider implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final MaskingEngine engine;

    public ContextMenuProvider(MontoyaApi api, MaskingEngine engine) {
        this.api = api;
        this.engine = engine;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();

        if (!engine.isEnabled()) {
            return items;
        }

        // Try to get the request/response from the message editor first
        Optional<MessageEditorHttpRequestResponse> editorMsg =
            event.messageEditorRequestResponse();

        if (editorMsg.isPresent()) {
            HttpRequestResponse reqRes = editorMsg.get().requestResponse();

            if (reqRes.request() != null) {
                JMenuItem copyRequest = new JMenuItem("BlackMarker: Copy Masked Request");
                copyRequest.addActionListener(e -> {
                    String raw = reqRes.request().toString();
                    MaskingResult result = engine.mask(raw);
                    copyToClipboard(result.getMaskedText());
                    showNotification("Masked request copied to clipboard (" +
                        result.getMatchCount() + " items masked)");
                });
                items.add(copyRequest);
            }

            if (reqRes.response() != null) {
                JMenuItem copyResponse = new JMenuItem("BlackMarker: Copy Masked Response");
                copyResponse.addActionListener(e -> {
                    String raw = reqRes.response().toString();
                    MaskingResult result = engine.mask(raw);
                    copyToClipboard(result.getMaskedText());
                    showNotification("Masked response copied to clipboard (" +
                        result.getMatchCount() + " items masked)");
                });
                items.add(copyResponse);
            }

            // Add "Copy Both Masked" option
            if (reqRes.request() != null && reqRes.response() != null) {
                JMenuItem copyBoth = new JMenuItem("BlackMarker: Copy Both Masked");
                copyBoth.addActionListener(e -> {
                    StringBuilder sb = new StringBuilder();
                    sb.append("=== REQUEST ===\n\n");
                    MaskingResult reqResult = engine.mask(reqRes.request().toString());
                    sb.append(reqResult.getMaskedText());
                    sb.append("\n\n=== RESPONSE ===\n\n");
                    MaskingResult resResult = engine.mask(reqRes.response().toString());
                    sb.append(resResult.getMaskedText());
                    copyToClipboard(sb.toString());
                    showNotification("Masked request+response copied (" +
                        (reqResult.getMatchCount() + resResult.getMatchCount()) + " items masked)");
                });
                items.add(copyBoth);
            }

        } else {
            // Fallback: try selected request/responses from proxy history etc.
            List<HttpRequestResponse> selectedMessages = event.selectedRequestResponses();
            if (!selectedMessages.isEmpty()) {
                JMenuItem copyAll = new JMenuItem("BlackMarker: Copy " +
                    selectedMessages.size() + " Masked Message(s)");
                copyAll.addActionListener(e -> {
                    StringBuilder sb = new StringBuilder();
                    int totalMasked = 0;
                    for (int i = 0; i < selectedMessages.size(); i++) {
                        HttpRequestResponse rr = selectedMessages.get(i);
                        sb.append("=== Message ").append(i + 1).append(" ===\n\n");
                        if (rr.request() != null) {
                            sb.append("--- Request ---\n");
                            MaskingResult result = engine.mask(rr.request().toString());
                            sb.append(result.getMaskedText());
                            totalMasked += result.getMatchCount();
                            sb.append("\n\n");
                        }
                        if (rr.response() != null) {
                            sb.append("--- Response ---\n");
                            MaskingResult result = engine.mask(rr.response().toString());
                            sb.append(result.getMaskedText());
                            totalMasked += result.getMatchCount();
                            sb.append("\n\n");
                        }
                    }
                    copyToClipboard(sb.toString());
                    showNotification("Copied " + selectedMessages.size() +
                        " masked message(s) (" + totalMasked + " items masked)");
                });
                items.add(copyAll);
            }
        }

        return items;
    }

    private void copyToClipboard(String text) {
        StringSelection selection = new StringSelection(text);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
    }

    private void showNotification(String message) {
        api.logging().logToOutput("[BlackMarker] " + message);
    }
}
