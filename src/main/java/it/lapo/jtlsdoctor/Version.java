package it.lapo.jtlsdoctor;

/** Static build metadata, shown by --help and in the JSON "about" node. */
public final class Version {

    static final String URL = "https://github.com/lapo-luchini/jtls-doctor";

    private Version() { }

    public static String url() {
        return URL;
    }

    /**
     * Reads the version injected by the build (jar manifest); builds executed
     * directly on classes without packaging report a generic "dev".
     */
    public static String version() {
        String v = Version.class.getPackage().getImplementationVersion();
        return v == null ? "dev" : v;
    }
}
