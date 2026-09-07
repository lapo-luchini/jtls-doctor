package jtlsdoctor;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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

public final class TrustStore {

    private final KeyStore keyStore;
    private final String description;
    private final Set<TrustAnchor> anchors;
    private final List<X509Certificate> certificates;

    public TrustStore(KeyStore keyStore, String description, Set<TrustAnchor> anchors,
            List<X509Certificate> certificates) {
        this.keyStore = keyStore;
        this.description = description;
        this.anchors = anchors;
        this.certificates = certificates;
    }

    public KeyStore keyStore() {
        return keyStore;
    }

    public String description() {
        return description;
    }

    public Set<TrustAnchor> anchors() {
        return anchors;
    }

    public List<X509Certificate> certificates() {
        return certificates;
    }

    public static TrustStore defaultJvm() throws IOException, GeneralSecurityException {
        String file = System.getProperty("javax.net.ssl.trustStore");
        if (file == null || file.trim().isEmpty()) {
            file = System.getProperty("java.home") + "/lib/security/cacerts";
        }
        String password = System.getProperty("javax.net.ssl.trustStorePassword", "changeit");
        return load(Paths.get(file), password.toCharArray(), "default JVM cacerts");
    }

    public static TrustStore load(Path path, char[] password, String description)
            throws IOException, GeneralSecurityException {
        if (!Files.isRegularFile(path)) {
            throw new IOException("truststore not found: " + path);
        }
        KeyStore ks;
        try {
            ks = KeyStore.getInstance(storeType(path));
            InputStream in = new BufferedInputStream(new FileInputStream(path.toFile()));
            try {
                ks.load(in, password);
            } finally {
                in.close();
            }
        } catch (IOException e) {
            throw new IOException("cannot load truststore " + path + ": " + e.getMessage(), e);
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("cannot load truststore " + path + ": " + e.getMessage(), e);
        }
        Set<TrustAnchor> anchors = new HashSet<TrustAnchor>();
        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        for (Enumeration<String> e = ks.aliases(); e.hasMoreElements(); ) {
            Certificate c = ks.getCertificate(e.nextElement());
            if (c instanceof X509Certificate) {
                X509Certificate x = (X509Certificate) c;
                anchors.add(new TrustAnchor(x, null));
                certs.add(x);
            }
        }
        if (anchors.isEmpty()) {
            throw new GeneralSecurityException("truststore contains no certificates: " + path);
        }
        return new TrustStore(ks, description, anchors, certs);
    }

    /**
     * Detects the truststore type from its magic bytes instead of relying on the
     * file name, so both JKS and PKCS12 stores work whatever their extension is.
     */
    private static String storeType(Path path) throws IOException {
        byte[] magic = new byte[4];
        DataInputStream in = new DataInputStream(new BufferedInputStream(new FileInputStream(path.toFile())));
        try {
            in.readFully(magic);
        } finally {
            in.close();
        }
        if (magic[0] == (byte) 0xFE && magic[1] == (byte) 0xED && magic[2] == (byte) 0xFE
                && magic[3] == (byte) 0xED) {
            return "JKS";
        }
        return "PKCS12";
    }
}
