package blackmarker.ui;

import blackmarker.engine.MaskingEngine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;

import java.awt.Component;

/**
 * Provides a custom "BlackMarker" tab in every HTTP response editor
 * that shows the masked version of the response.
 * The UI itself lives in {@link MaskedEditorPanel}.
 */
public class MaskedResponseEditorProvider implements HttpResponseEditorProvider {

    private final MontoyaApi api;
    private final MaskingEngine engine;

    public MaskedResponseEditorProvider(MontoyaApi api, MaskingEngine engine) {
        this.api = api;
        this.engine = engine;
    }

    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext creationContext) {
        return new MaskedResponseEditor();
    }

    private class MaskedResponseEditor implements ExtensionProvidedHttpResponseEditor {

        private final MaskedEditorPanel panel = new MaskedEditorPanel(api, engine);
        private HttpRequestResponse currentRequestResponse;

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            this.currentRequestResponse = requestResponse;
            boolean hasResponse = requestResponse != null && requestResponse.response() != null;
            panel.setRaw(hasResponse ? requestResponse.response().toString() : null);
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse requestResponse) {
            return requestResponse != null && requestResponse.response() != null;
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
        public HttpResponse getResponse() {
            return currentRequestResponse != null ? currentRequestResponse.response() : null;
        }
    }
}
