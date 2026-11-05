package blackmarker;

import blackmarker.engine.MaskingEngine;
import blackmarker.export.SessionExporter;
import blackmarker.persistence.StateStore;
import blackmarker.rules.SessionValueTracker;
import blackmarker.ui.*;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpHeader;

import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * BlackMarker — Burp Suite extension for visual masking of sensitive data.
 *
 * Automatically masks PII, tokens, passwords, domains, and other confidential
 * information in the Burp UI for safe screen sharing and screenshots.
 *
 * Features:
 * - Custom "BlackMarker" tab in every HTTP message editor (Proxy, Repeater, etc.)
 * - 60+ built-in regex rules organized by category
 * - Smart entropy-based detection of secrets
 * - Auto-learning of session values (cookies, tokens)
 * - Color-coded masking by data type (PII=blue, Auth=red, Infra=orange, etc.)
 * - Context menu "Copy Masked" for clipboard operations
 * - Export masked sessions to HTML/Text (runs in the background)
 * - Custom rule editor with live regex testing
 * - Rule categories: PII, Auth, Infrastructure, Crypto, Session, Custom
 *
 * Architecture:
 * - MaskingEngine: core engine with regex rules + entropy + session tracking
 * - EditorProviders: register "BlackMarker" tab in all message editors
 * - BlackMarkerTab: main configuration/management tab
 * - ContextMenuProvider: right-click copy masked content
 * - SessionExporter: export proxy history with masking applied
 * - StateStore: persistence of rules and settings
 */
public class BlackMarkerExtension implements BurpExtension {

    /** Tools whose traffic feeds auto-learn. Scanner/Sequencer/etc. are high volume and skipped. */
    private static final Set<ToolType> LEARN_TOOLS =
        EnumSet.of(ToolType.PROXY, ToolType.REPEATER, ToolType.INTRUDER, ToolType.EXTENSIONS);

    /** Bodies larger than this are not inspected for tokens (headers still are). */
    private static final int MAX_LEARN_BODY_BYTES = 64 * 1024;

    private MontoyaApi api;
    private MaskingEngine engine;
    private SessionExporter exporter;
    private StateStore stateStore;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName(Version.EXTENSION_NAME);

        // Initialize masking engine
        engine = new MaskingEngine();
        engine.setErrorSink(msg -> api.logging().logToError("[BlackMarker] " + msg));

        // Load persisted state, then keep it saved in the background
        stateStore = new StateStore(api, engine);
        stateStore.load();
        stateStore.startAutosave();

        // Initialize exporter
        exporter = new SessionExporter(api, engine);

        // Register HTTP request editor provider (adds "BlackMarker" tab to request viewers)
        api.userInterface().registerHttpRequestEditorProvider(
            new MaskedRequestEditorProvider(api, engine)
        );

        // Register HTTP response editor provider (adds "BlackMarker" tab to response viewers)
        api.userInterface().registerHttpResponseEditorProvider(
            new MaskedResponseEditorProvider(api, engine)
        );

        // Register context menu items ("Copy Masked Request/Response")
        api.userInterface().registerContextMenuItemsProvider(
            new ContextMenuProvider(api, engine)
        );

        // Register main BlackMarker configuration tab
        BlackMarkerTab mainTab = new BlackMarkerTab(api, engine);
        mainTab.setExporter(exporter);
        api.userInterface().registerSuiteTab(Version.SHORT_NAME, mainTab);

        // Register HTTP handler for auto-learning session values
        api.http().registerHttpHandler(new AutoLearnHttpHandler());

        // Register unload handler: stop background work and persist state
        api.extension().registerUnloadingHandler(this::onUnload);

        // Log startup
        api.logging().logToOutput("========================================");
        api.logging().logToOutput("  " + Version.EXTENSION_NAME + " v" + Version.get() + " loaded");
        api.logging().logToOutput("  Rules: " + engine.getRules().size() + " loaded");
        api.logging().logToOutput("  Entropy detection: " +
            (engine.getEntropyDetector().isEnabled() ? "ON" : "OFF"));
        api.logging().logToOutput("  Session auto-learn: " +
            (engine.getSessionValueTracker().isEnabled() ? "ON" : "OFF"));
        api.logging().logToOutput("========================================");
    }

    /**
     * HTTP Handler that feeds traffic to the session value tracker
     * for automatic learning of session-specific tokens and cookies.
     *
     * It runs on Burp's traffic threads, so it exits early for tools and content it does not
     * care about, never converts a whole message to a string, and keeps no reference to the
     * message after returning.
     */
    private class AutoLearnHttpHandler implements HttpHandler {

        private volatile boolean errorLogged;

        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
            if (shouldLearn(requestToBeSent.toolSource().toolType())) {
                try {
                    learn(requestToBeSent.headers(), requestToBeSent.body());
                } catch (RuntimeException e) {
                    logOnce(e);
                }
            }
            // Never modify the request
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
            if (shouldLearn(responseReceived.toolSource().toolType())) {
                try {
                    learn(responseReceived.headers(), responseReceived.body());
                } catch (RuntimeException e) {
                    logOnce(e);
                }
            }
            // Never modify the response
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        private boolean shouldLearn(ToolType tool) {
            return engine.getSessionValueTracker().isEnabled() && LEARN_TOOLS.contains(tool);
        }

        private void learn(List<HttpHeader> headers, ByteArray body) {
            SessionValueTracker tracker = engine.getSessionValueTracker();

            String contentType = null;
            for (HttpHeader header : headers) {
                String name = header.name();
                if (name.equalsIgnoreCase("Content-Type")) contentType = header.value();
                tracker.learnFromHeader(name, header.value());
            }

            if (contentType == null) return;
            int length = body.length();
            if (length == 0 || length > MAX_LEARN_BODY_BYTES) return;

            String type = contentType.toLowerCase(Locale.ROOT);
            if (type.contains("json")) {
                tracker.learnFromJson(body.toString());
            } else if (type.contains("x-www-form-urlencoded")) {
                tracker.learnFromForm(body.toString());
            }
        }

        private void logOnce(RuntimeException e) {
            if (!errorLogged) {
                errorLogged = true;
                api.logging().logToError("[BlackMarker] Auto-learn error (further errors suppressed): " + e);
            }
        }
    }

    /**
     * Stop background work and persist state when the extension is unloaded.
     */
    private void onUnload() {
        if (exporter != null) exporter.shutdown();
        if (stateStore != null) stateStore.shutdown();
        api.logging().logToOutput("[BlackMarker] Extension unloaded");
    }
}
