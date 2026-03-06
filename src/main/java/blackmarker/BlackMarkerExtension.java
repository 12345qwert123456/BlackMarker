package blackmarker;

import blackmarker.engine.MaskingEngine;
import blackmarker.export.SessionExporter;
import blackmarker.model.PluginSettings;
import blackmarker.ui.*;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.persistence.PersistedObject;

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
 * - Export masked sessions to HTML/Text
 * - Custom rule editor with live regex testing
 * - Rule categories: PII, Auth, Infrastructure, Crypto, Session, Custom
 *
 * Architecture:
 * - MaskingEngine: core engine with regex rules + entropy + session tracking
 * - EditorProviders: register "BlackMarker" tab in all message editors
 * - BlackMarkerTab: main configuration/management tab
 * - ContextMenuProvider: right-click copy masked content
 * - SessionExporter: export proxy history with masking applied
 *
 * @version 1.0.0
 */
public class BlackMarkerExtension implements BurpExtension {

    private static final String EXTENSION_NAME = "BlackMarker";
    private static final String PERSIST_KEY_CUSTOM_RULES = "blackmarker.custom_rules";
    private static final String PERSIST_KEY_BUILTIN_STATE = "blackmarker.builtin_state";
    private static final String PERSIST_KEY_SETTINGS = "blackmarker.settings";
    private static final String PERSIST_KEY_PLUGIN_SETTINGS = "blackmarker.plugin_settings";

    private MontoyaApi api;
    private MaskingEngine engine;
    private SessionExporter exporter;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName(EXTENSION_NAME);

        // Initialize masking engine
        engine = new MaskingEngine();

        // Load persisted settings
        loadPersistedState();

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
        BlackMarkerTab mainTab = new BlackMarkerTab(engine);
        mainTab.setExporter(exporter);
        api.userInterface().registerSuiteTab(EXTENSION_NAME, mainTab);

        // Register HTTP handler for auto-learning session values
        api.http().registerHttpHandler(new AutoLearnHttpHandler());

        // Register unload handler to persist state
        api.extension().registerUnloadingHandler(this::onUnload);

        // Log startup
        api.logging().logToOutput("========================================");
        api.logging().logToOutput("  BlackMarker v1.0.0 loaded successfully");
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
     */
    private class AutoLearnHttpHandler implements HttpHandler {

        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
            // Learn session values from outgoing requests
            if (engine.getSessionValueTracker().isEnabled()) {
                try {
                    String rawRequest = requestToBeSent.toString();
                    engine.learnFromMessage(rawRequest);
                } catch (Exception e) {
                    // Silently ignore errors in auto-learn
                }
            }
            // Never modify the request
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
            // Learn session values from incoming responses
            if (engine.getSessionValueTracker().isEnabled()) {
                try {
                    String rawResponse = responseReceived.toString();
                    engine.learnFromMessage(rawResponse);
                } catch (Exception e) {
                    // Silently ignore errors in auto-learn
                }
            }
            // Never modify the response
            return ResponseReceivedAction.continueWith(responseReceived);
        }
    }

    /**
     * Load persisted rules and settings from Burp's persistence store.
     */
    private void loadPersistedState() {
        try {
            PersistedObject persistence = api.persistence().extensionData();

            // Load custom rules
            String customRulesJson = persistence.getString(PERSIST_KEY_CUSTOM_RULES);
            if (customRulesJson != null && !customRulesJson.isEmpty()) {
                engine.loadCustomRules(customRulesJson);
                api.logging().logToOutput("[BlackMarker] Loaded persisted custom rules");
            }

            // Load built-in rule states
            String builtInStateJson = persistence.getString(PERSIST_KEY_BUILTIN_STATE);
            if (builtInStateJson != null && !builtInStateJson.isEmpty()) {
                engine.loadBuiltInState(builtInStateJson);
                api.logging().logToOutput("[BlackMarker] Restored built-in rule states");
            }

            // Load settings
            String settingsJson = persistence.getString(PERSIST_KEY_SETTINGS);
            if (settingsJson != null && !settingsJson.isEmpty()) {
                loadSettings(settingsJson);
            }

            // Load plugin settings (monochrome, mask char, truncation, custom categories, colors)
            String pluginSettingsJson = persistence.getString(PERSIST_KEY_PLUGIN_SETTINGS);
            if (pluginSettingsJson != null && !pluginSettingsJson.isEmpty()) {
                PluginSettings.getInstance().deserialize(pluginSettingsJson);
                api.logging().logToOutput("[BlackMarker] Restored plugin settings");
            }
        } catch (Exception e) {
            api.logging().logToError("[BlackMarker] Failed to load persisted state: " + e.getMessage());
        }
    }

    /**
     * Persist current state before extension unload.
     */
    private void onUnload() {
        try {
            PersistedObject persistence = api.persistence().extensionData();

            // Save custom rules
            persistence.setString(PERSIST_KEY_CUSTOM_RULES, engine.serializeCustomRules());

            // Save built-in rule states
            persistence.setString(PERSIST_KEY_BUILTIN_STATE, engine.serializeBuiltInState());

            // Save settings
            persistence.setString(PERSIST_KEY_SETTINGS, serializeSettings());

            // Save plugin settings
            persistence.setString(PERSIST_KEY_PLUGIN_SETTINGS, PluginSettings.getInstance().serialize());

            api.logging().logToOutput("[BlackMarker] State persisted successfully");
        } catch (Exception e) {
            api.logging().logToError("[BlackMarker] Failed to persist state: " + e.getMessage());
        }

        api.logging().logToOutput("[BlackMarker] Extension unloaded");
    }

    /**
     * Serialize current settings to JSON.
     */
    private String serializeSettings() {
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"enabled\":").append(engine.isEnabled()).append(",");
        sb.append("\"entropyEnabled\":").append(engine.getEntropyDetector().isEnabled()).append(",");
        sb.append("\"entropyThreshold\":").append(engine.getEntropyDetector().getEntropyThreshold()).append(",");
        sb.append("\"entropyMinLength\":").append(engine.getEntropyDetector().getMinLength()).append(",");
        sb.append("\"sessionAutoLearn\":").append(engine.getSessionValueTracker().isEnabled());
        sb.append("}");
        return sb.toString();
    }

    /**
     * Load settings from JSON.
     */
    private void loadSettings(String json) {
        try {
            // Simple parsing for our known format
            if (json.contains("\"enabled\":false")) engine.setEnabled(false);
            if (json.contains("\"entropyEnabled\":false")) engine.getEntropyDetector().setEnabled(false);
            if (json.contains("\"sessionAutoLearn\":false")) engine.getSessionValueTracker().setEnabled(false);

            // Extract numeric values
            java.util.regex.Matcher m;

            m = java.util.regex.Pattern.compile("\"entropyThreshold\":(\\d+\\.?\\d*)").matcher(json);
            if (m.find()) engine.getEntropyDetector().setEntropyThreshold(Double.parseDouble(m.group(1)));

            m = java.util.regex.Pattern.compile("\"entropyMinLength\":(\\d+)").matcher(json);
            if (m.find()) engine.getEntropyDetector().setMinLength(Integer.parseInt(m.group(1)));
        } catch (Exception e) {
            // Use defaults on parse error
        }
    }
}
