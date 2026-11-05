package blackmarker.ui;

import blackmarker.engine.MaskingEngine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;

import java.awt.Component;

/**
 * Provides a custom "BlackMarker" tab in every HTTP request editor
 * (Proxy, Repeater, Intruder, etc.) that shows the masked version of the request.
 * The UI itself lives in {@link MaskedEditorPanel}.
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

        private final MaskedEditorPanel panel = new MaskedEditorPanel(api, engine);
        private HttpRequestResponse currentRequestResponse;

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            this.currentRequestResponse = requestResponse;
            boolean hasRequest = requestResponse != null && requestResponse.request() != null;
            panel.setRaw(hasRequest ? requestResponse.request().toString() : null);
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
            return panel.component();
        }

        @Override
        public Selection selectedData() {
            String selected = panel.selectedMaskedText();
            if (selected == null || selected.isEmpty()) {
                return null;
            }
            return Selection.selection(ByteArray.byteArray(selected));
        }

        @Override
        public boolean isModified() {
            return false;
        }

        @Override
        public HttpRequest getRequest() {
            return currentRequestResponse != null ? currentRequestResponse.request() : null;
        }
    }
}
