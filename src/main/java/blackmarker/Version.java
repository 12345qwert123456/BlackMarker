package blackmarker;

/**
 * Single source of truth for the extension's name and version.
 * The version comes from the jar manifest (Implementation-Version, set in build.gradle).
 */
public final class Version {

    /** Name shown in Burp's Extensions list (descriptive, as required by BApp Store review). */
    public static final String EXTENSION_NAME = "BlackMarker, Sensitive Data Redactor";

    /** Short name used for the suite tab and log prefixes. */
    public static final String SHORT_NAME = "BlackMarker";

    private static final String FALLBACK_VERSION = "1.1";

    private Version() {}

    public static String get() {
        String v = Version.class.getPackage() != null
            ? Version.class.getPackage().getImplementationVersion() : null;
        return v != null && !v.isBlank() ? v : FALLBACK_VERSION;
    }
}
