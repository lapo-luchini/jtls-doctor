package it.lapo.jtlsdoctor;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * HTTP proxy configuration for reaching a probe target through a CONNECT
 * tunnel. Mirrors the standard JVM system properties: when not set explicitly
 * the tool behaves like a regular client with {@code -Dhttps.proxyHost} /
 * {@code -Dhttp.proxyHost} (and {@code https.nonProxyHosts}).
 */
final class HttpProxy {

    private final String host;
    private final int port;
    private final List<Pattern> nonProxy;

    HttpProxy(String host, int port, String nonProxyHosts) {
        this.host = host;
        this.port = port;
        this.nonProxy = patterns(nonProxyHosts);
    }

    String host() {
        return host;
    }

    int port() {
        return port;
    }

    /** Parses a {@code --proxy} value: {@code [http://]host[:port]} (IPv6 in brackets). */
    static HttpProxy parse(String spec) {
        String t = spec.trim();
        if (t.startsWith("http://")) {
            t = t.substring(7);
        } else if (t.startsWith("https://")) {
            t = t.substring(8);
        }
        while (t.endsWith("/")) {
            t = t.substring(0, t.length() - 1);
        }
        if (t.isEmpty()) {
            throw new IllegalArgumentException("missing proxy host: " + spec);
        }
        String host;
        String port = "8080";
        if (t.startsWith("[")) {
            int end = t.indexOf(']');
            if (end < 0) {
                throw new IllegalArgumentException("invalid proxy address: " + spec);
            }
            host = t.substring(1, end);
            if (end + 1 < t.length()) {
                if (t.charAt(end + 1) != ':') {
                    throw new IllegalArgumentException("invalid proxy address: " + spec);
                }
                port = t.substring(end + 2);
            }
        } else {
            int colon = t.indexOf(':');
            if (colon == 0) {
                throw new IllegalArgumentException("missing proxy host: " + spec);
            } else if (colon > 0) {
                host = t.substring(0, colon);
                port = t.substring(colon + 1);
            } else {
                host = t;
            }
        }
        if (host.trim().isEmpty()) {
            throw new IllegalArgumentException("missing proxy host: " + spec);
        }
        int p;
        try {
            p = Integer.parseInt(port.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("invalid proxy port: " + port);
        }
        if (p < 1 || p > 65535) {
            throw new IllegalArgumentException("invalid proxy port: " + port);
        }
        return new HttpProxy(host, p, null);
    }

    /**
     * Proxy derived from the same system properties a regular Java client
     * would honor ({@code -Dhttps.proxyHost=... -Dhttps.proxyPort=...}),
     * falling back to {@code http.proxyHost}/{@code http.proxyPort}.
     * Returns {@code null} when no proxy is configured.
     */
    static HttpProxy fromSystemProperties() {
        String host = trimToEmpty(System.getProperty("https.proxyHost"));
        if (host.isEmpty()) {
            host = trimToEmpty(System.getProperty("http.proxyHost"));
        }
        if (host.isEmpty()) {
            return null;
        }
        String port = trimToEmpty(System.getProperty("https.proxyPort"));
        if (port.isEmpty()) {
            port = trimToEmpty(System.getProperty("http.proxyPort"));
        }
        if (port.isEmpty()) {
            port = "8080";
        }
        String nonProxy = System.getProperty("https.nonProxyHosts",
                System.getProperty("http.nonProxyHosts"));
        try {
            return new HttpProxy(host, Integer.parseInt(port), nonProxy);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("invalid proxy port: " + port);
        }
    }

    /**
     * Whether the proxy is used for this target host, honoring
     * {@code nonProxyHosts} patterns ({@code |}-separated, {@code *} wildcard,
     * a leading dot matches the domain and all its subdomains).
     */
    boolean appliesTo(String host) {
        if (nonProxy.isEmpty()) {
            return true;
        }
        String h = host.toLowerCase(Locale.ROOT);
        for (Pattern p : nonProxy) {
            if (p.matcher(h).matches()) {
                return false;
            }
        }
        return true;
    }

    String description() {
        return host + ":" + port;
    }

    private static List<Pattern> patterns(String nonProxyHosts) {
        List<Pattern> list = new ArrayList<>();
        if (nonProxyHosts == null || nonProxyHosts.trim().isEmpty()) {
            return list;
        }
        List<String> raw = new ArrayList<>();
        for (String entry : nonProxyHosts.trim().split("\\|")) {
            String p = entry.trim().toLowerCase(Locale.ROOT);
            if (p.isEmpty()) {
                continue;
            }
            if (p.startsWith(".")) {
                // dot-prefixed pattern ("*.example.com" style): excludes the
                // domain itself and all its subdomains
                raw.add(p.substring(1)); // example.com (exact)
                raw.add(".*" + p);       // anything . followed by the domain
            } else {
                raw.add(p);
            }
        }
        for (String p : raw) {
            String regex = p.replace("!", "\\!").replace("$", "\\$")
                    .replace(".", "\\.").replace("*", ".*");
            list.add(Pattern.compile("^" + regex + "$"));
        }
        return list;
    }

    private static String trimToEmpty(String s) {
        return s == null ? "" : s.trim();
    }
}
