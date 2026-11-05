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
import java.util.concurrent.ExecutionException;

/**
 * Provides "Copy Masked Request" and "Copy Masked Response" context menu items
 * in all Burp tools. Copies the masked version to the system clipboard.
 *
 * Masking happens in a background worker (selections can be large); only the clipboard
 * write runs on the event thread.
 */
public class ContextMenuProvider implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final MaskingEngine engine;

    public ContextMenuProvider(MontoyaApi api, MaskingEngine engine) {
        this.api = api;
        this.engine = engine;
    }

    /** Masked text plus how many items were masked, for the log message. */
    private record Copied(String text, int maskedItems) {}

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
                copyRequest.addActionListener(e -> copyMasked("Masked request copied to clipboard", () -> {
                    MaskingResult result = engine.mask(MaskingEngine.clip(reqRes.request().toString()));
                    return new Copied(result.getMaskedText(), result.getMatchCount());
                }));
                items.add(copyRequest);
            }

            if (reqRes.response() != null) {
                JMenuItem copyResponse = new JMenuItem("BlackMarker: Copy Masked Response");
                copyResponse.addActionListener(e -> copyMasked("Masked response copied to clipboard", () -> {
                    MaskingResult result = engine.mask(MaskingEngine.clip(reqRes.response().toString()));
                    return new Copied(result.getMaskedText(), result.getMatchCount());
                }));
                items.add(copyResponse);
            }

            // Add "Copy Both Masked" option
            if (reqRes.request() != null && reqRes.response() != null) {
                JMenuItem copyBoth = new JMenuItem("BlackMarker: Copy Both Masked");
                copyBoth.addActionListener(e -> copyMasked("Masked request+response copied", () -> {
                    MaskingResult reqResult = engine.mask(MaskingEngine.clip(reqRes.request().toString()));
                    MaskingResult resResult = engine.mask(MaskingEngine.clip(reqRes.response().toString()));
                    String text = "=== REQUEST ===\n\n" + reqResult.getMaskedText()
                        + "\n\n=== RESPONSE ===\n\n" + resResult.getMaskedText();
                    return new Copied(text, reqResult.getMatchCount() + resResult.getMatchCount());
                }));
                items.add(copyBoth);
            }

        } else {
            // Fallback: try selected request/responses from proxy history etc.
            List<HttpRequestResponse> selectedMessages = event.selectedRequestResponses();
            if (!selectedMessages.isEmpty()) {
                JMenuItem copyAll = new JMenuItem("BlackMarker: Copy " +
                    selectedMessages.size() + " Masked Message(s)");
                copyAll.addActionListener(e -> copyMasked(
                    "Copied " + selectedMessages.size() + " masked message(s)", () -> {
                        StringBuilder sb = new StringBuilder();
                        int totalMasked = 0;
                        for (int i = 0; i < selectedMessages.size(); i++) {
                            HttpRequestResponse rr = selectedMessages.get(i);
                            sb.append("=== Message ").append(i + 1).append(" ===\n\n");
                            if (rr.request() != null) {
                                sb.append("--- Request ---\n");
                                MaskingResult result = engine.mask(MaskingEngine.clip(rr.request().toString()));
                                sb.append(result.getMaskedText());
                                totalMasked += result.getMatchCount();
                                sb.append("\n\n");
                            }
                            if (rr.response() != null) {
                                sb.append("--- Response ---\n");
                                MaskingResult result = engine.mask(MaskingEngine.clip(rr.response().toString()));
                                sb.append(result.getMaskedText());
                                totalMasked += result.getMatchCount();
                                sb.append("\n\n");
                            }
                        }
                        return new Copied(sb.toString(), totalMasked);
                    }));
                items.add(copyAll);
            }
        }

        return items;
    }

    /** Run {@code job} off the EDT, then put its text on the clipboard. */
    private void copyMasked(String message, java.util.concurrent.Callable<Copied> job) {
        new SwingWorker<Copied, Void>() {
            @Override
            protected Copied doInBackground() throws Exception {
                return job.call();
            }

            @Override
            protected void done() {
                try {
                    Copied copied = get();
                    Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(new StringSelection(copied.text()), null);
                    api.logging().logToOutput("[BlackMarker] " + message
                        + " (" + copied.maskedItems() + " items masked)");
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } catch (ExecutionException e) {
                    api.logging().logToError("[BlackMarker] Copy masked failed: " + e.getCause());
                }
            }
        }.execute();
    }
}
