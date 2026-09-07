package jtlsdoctor;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public record TrustStore(KeyStore keyStore, String description, Set<TrustAnchor> anchors,
        List<X509Certificate> certificates) {

    public static TrustStore defaultJvm() throws IOException, GeneralSecurityException {
        String file = System.getProperty("javax.net.ssl.trustStore");
        if (file == null || file.isBlank()) {
            file = System.getProperty("java.home") + "/lib/security/cacerts";
        }
        String password = System.getProperty("javax.net.ssl.trustStorePassword", "changeit");
        return load(Path.of(file), password.toCharArray(), "default JVM cacerts");
    }

    public static TrustStore load(Path path, char[] password, String description)
            throws IOException, GeneralSecurityException {
        if (!Files.isRegularFile(path)) {
            throw new IOException("truststore not found: " + path);
        }
        KeyStore ks;
        try {
            ks = KeyStore.getInstance(path.toFile(), password);
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("cannot load truststore " + path + ": " + e.getMessage(), e);
        } catch (IOException e) {
            throw new IOException("cannot load truststore " + path + ": " + e.getMessage(), e);
        }
        Set<TrustAnchor> anchors = new HashSet<>();
        List<X509Certificate> certs = new ArrayList<>();
        for (Enumeration<String> e = ks.aliases(); e.hasMoreElements(); ) {
            Certificate c = ks.getCertificate(e.nextElement());
            if (c instanceof X509Certificate x) {
                anchors.add(new TrustAnchor(x, null));
                certs.add(x);
            }
        }
        if (anchors.isEmpty()) {
            throw new GeneralSecurityException("truststore contains no certificates: " + path);
        }
        return new TrustStore(ks, description, anchors, certs);
    }
}
