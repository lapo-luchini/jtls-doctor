package jtlsdoctor;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public final class TlsDoctor {

    private static final int CONNECT_TIMEOUT_MS = 10_000;
    private static final int READ_TIMEOUT_MS = 10_000;

    private final TrustStore trustStore;

    public TlsDoctor(TrustStore trustStore) {
        this.trustStore = trustStore;
    }

    public Report check(String host, int port) {
        List<CheckResult> checks = new ArrayList<>();

        Handshake hs = handshake(host, port);
        checks.add(hs.connected()
                ? CheckResult.ok("connect", hs.protocol() + ", " + hs.cipher())
                : CheckResult.fail("connect", hs.error()));

        String target = host + ":" + port;
        X509Certificate[] sent = hs.chain();
        if (sent == null || sent.length == 0) {
            String why = hs.connected() ? "server sent no certificates" : "no certificate chain received";
            for (String n : Arrays.asList("trust", "chain-order", "intermediates", "extras")) {
                checks.add(CheckResult.skip(n, why));
            }
            return new Report(target, trustStore.description(), checks);
        }

        List<X509Certificate> chain = Arrays.asList(sent);
        X509Certificate leaf = chain.get(0);

        String invalidMessage = validityProblem(chain);
        Build r1 = invalidMessage == null
                ? build(leaf, trustStore.anchors(), pool(chain, Collections.<X509Certificate>emptyList()))
                : null;

        int rootIndex = -1;
        String orderProblem = null;
        for (int i = 0; i < chain.size(); i++) {
            X509Certificate c = chain.get(i);
            if (c.getSubjectX500Principal().equals(c.getIssuerX500Principal())) {
                rootIndex = i;
                break;
            }
            if (i == chain.size() - 1) {
                break;
            }
            X509Certificate next = chain.get(i + 1);
            boolean namesMatch = c.getIssuerX500Principal().equals(next.getSubjectX500Principal());
            boolean signed = false;
            if (namesMatch) {
                try {
                    c.verify(next.getPublicKey());
                    signed = true;
                } catch (GeneralSecurityException ignored) {
                    // fall through: reported as a broken link
                }
            }
            if (!namesMatch || !signed) {
                orderProblem = "'" + name(c) + "' is not signed by the next sent certificate '" + name(next) + "'";
                break;
            }
        }
        checks.add(orderProblem == null
                ? CheckResult.ok("chain-order", chain.size() + " certificate(s) sent, leaf-to-root order valid")
                : CheckResult.fail("chain-order", orderProblem));

        String last = name(chain.get(chain.size() - 1));
        CheckResult intermediates;
        if (invalidMessage != null) {
            intermediates = CheckResult.skip("intermediates", "cannot evaluate (" + invalidMessage + ")");
        } else if (rootIndex >= 0) {
            intermediates = CheckResult.ok("intermediates", "complete chain sent (leaf to root)");
        } else if (r1 != null && r1.result() != null) {
            intermediates = CheckResult.ok("intermediates", "all required intermediates sent");
        } else {
            intermediates = CheckResult.fail("intermediates",
                    "missing intermediate certificate(s) between '" + last + "' and a trusted root");
        }
        checks.add(intermediates);

        CheckResult trust;
        if (r1 != null && r1.result() != null) {
            trust = CheckResult.ok("trust",
                    "root CA '" + name(r1.result().getTrustAnchor().getTrustedCert())
                    + "' trusted via " + trustStore.description());
        } else if (invalidMessage != null) {
            trust = CheckResult.fail("trust", invalidMessage);
        } else if (rootIndex >= 0 && orderProblem == null) {
            trust = CheckResult.fail("trust",
                    "root CA '" + name(chain.get(rootIndex)) + "' is not in " + trustStore.description());
        } else {
            trust = CheckResult.fail("trust",
                    "cannot build a trusted certification path: "
                    + (r1 != null && r1.error() != null ? r1.error() : "chain incomplete"));
        }
        checks.add(trust);

        checks.add(extrasCheck(chain, rootIndex, r1));

        return new Report(target, trustStore.description(), checks);
    }

    private CheckResult extrasCheck(List<X509Certificate> chain, int rootIndex, Build r1) {
        List<String> extra = new ArrayList<>();
        Set<String> pathFingerprints = new HashSet<>();
        if (r1 != null && r1.result() != null) {
            for (Certificate c : r1.result().getCertPath().getCertificates()) {
                pathFingerprints.add(fingerprint((X509Certificate) c));
            }
            pathFingerprints.add(fingerprint(r1.result().getTrustAnchor().getTrustedCert()));
        }
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < chain.size(); i++) {
            X509Certificate c = chain.get(i);
            String f = fingerprint(c);
            boolean duplicate = !seen.add(f);
            boolean selfIssued = c.getSubjectX500Principal().equals(c.getIssuerX500Principal());
            if (i > 0 && selfIssued) {
                extra.add("root CA sent: '" + name(c) + "' (must be omitted)");
            } else if (duplicate) {
                extra.add("duplicate certificate: '" + name(c) + "'");
            } else if (rootIndex >= 0 && i > rootIndex) {
                extra.add("certificate sent after the root: '" + name(c) + "'");
            } else if (r1 != null && r1.result() != null && !pathFingerprints.contains(f)) {
                extra.add("unneeded certificate: '" + name(c) + "'");
            }
        }
        return extra.isEmpty()
                ? CheckResult.ok("extras", "no extra certificates")
                : CheckResult.fail("extras", String.join("; ", extra));
    }

    private Handshake handshake(String host, int port) {
        InetAddress address;
        try {
            address = InetAddress.getByName(host);
        } catch (UnknownHostException e) {
            return Handshake.fail("unknown host: " + host);
        }

        TrustManagerFactory tmf;
        try {
            tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore.keyStore());
        } catch (GeneralSecurityException e) {
            return Handshake.fail("cannot initialize trust manager: " + e.getMessage());
        }
        X509TrustManager delegate = null;
        for (TrustManager t : tmf.getTrustManagers()) {
            if (t instanceof X509TrustManager) {
                delegate = (X509TrustManager) t;
                break;
            }
        }
        if (delegate == null) {
            return Handshake.fail("no X509 trust manager available");
        }

        SSLContext ctx;
        CapturingTrustManager capturing = new CapturingTrustManager(delegate);
        try {
            ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[] { capturing }, null);
        } catch (GeneralSecurityException e) {
            return Handshake.fail("cannot initialize SSL context: " + e.getMessage());
        }

        SSLSocket socket;
        try {
            socket = (SSLSocket) ctx.getSocketFactory().createSocket();
        } catch (IOException e) {
            return Handshake.fail("cannot create socket: " + e.getMessage());
        }
        try {
            socket.connect(new InetSocketAddress(address, port), CONNECT_TIMEOUT_MS);
            socket.setSoTimeout(READ_TIMEOUT_MS);
            SSLParameters params = socket.getSSLParameters();
            params.setEndpointIdentificationAlgorithm("HTTPS");
            try {
                params.setServerNames(Collections.singletonList(new SNIHostName(host)));
            } catch (IllegalArgumentException ignored) {
                // host is an IP address: no SNI possible
            }
            socket.setSSLParameters(params);
            socket.startHandshake();
            return new Handshake(true, socket.getSession().getProtocol(),
                    socket.getSession().getCipherSuite(), capturing.chain(), null);
        } catch (IOException e) {
            return new Handshake(false, null, null, capturing.chain(), describe(e));
        } finally {
            try {
                socket.close();
            } catch (IOException ignored) {
                // socket cleanup is best-effort
            }
        }
    }

    private static final class Handshake {

        private final boolean connected;
        private final String protocol;
        private final String cipher;
        private final X509Certificate[] chain;
        private final String error;

        Handshake(boolean connected, String protocol, String cipher, X509Certificate[] chain, String error) {
            this.connected = connected;
            this.protocol = protocol;
            this.cipher = cipher;
            this.chain = chain;
            this.error = error;
        }

        static Handshake fail(String error) {
            return new Handshake(false, null, null, null, error);
        }

        boolean connected() {
            return connected;
        }

        String protocol() {
            return protocol;
        }

        String cipher() {
            return cipher;
        }

        X509Certificate[] chain() {
            return chain;
        }

        String error() {
            return error;
        }
    }

    private static final class Build {

        private final PKIXCertPathBuilderResult result;
        private final String error;

        Build(PKIXCertPathBuilderResult result, String error) {
            this.result = result;
            this.error = error;
        }

        PKIXCertPathBuilderResult result() {
            return result;
        }

        String error() {
            return error;
        }
    }

    private static Build build(X509Certificate leaf, Set<TrustAnchor> anchors, List<X509Certificate> pool) {
        try {
            X509CertSelector selector = new X509CertSelector();
            selector.setCertificate(leaf);
            PKIXBuilderParameters params = new PKIXBuilderParameters(anchors, selector);
            params.setRevocationEnabled(false);
            params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(pool)));
            PKIXCertPathBuilderResult result =
                    (PKIXCertPathBuilderResult) CertPathBuilder.getInstance("PKIX").build(params);
            return new Build(result, null);
        } catch (GeneralSecurityException e) {
            return new Build(null, e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
        }
    }

    private static String validityProblem(List<X509Certificate> chain) {
        for (X509Certificate c : chain) {
            try {
                c.checkValidity();
            } catch (CertificateExpiredException e) {
                return "certificate expired: '" + name(c) + "' (" + e.getMessage() + ")";
            } catch (CertificateNotYetValidException e) {
                return "certificate not yet valid: '" + name(c) + "' (" + e.getMessage() + ")";
            }
        }
        return null;
    }

    private static List<X509Certificate> pool(List<X509Certificate> sent, List<X509Certificate> extra) {
        List<X509Certificate> all = new ArrayList<>(sent);
        all.addAll(extra);
        return all;
    }

    private static String describe(Throwable t) {
        Throwable cur = t;
        while (cur.getCause() != null && cur.getCause() != cur) {
            cur = cur.getCause();
        }
        String msg = cur.getMessage();
        if (msg == null || msg.trim().isEmpty()) {
            msg = cur.getClass().getSimpleName();
        }
        if (cur instanceof CertificateExpiredException) {
            return "certificate expired (" + msg + ")";
        }
        if (cur instanceof CertificateNotYetValidException) {
            return "certificate not yet valid (" + msg + ")";
        }
        return msg;
    }

    private static String name(X509Certificate c) {
        String n = c.getSubjectX500Principal().getName();
        if (n.startsWith("CN=")) {
            int comma = n.indexOf(',');
            return comma > 0 ? n.substring(0, comma) : n;
        }
        return n;
    }

    private static String fingerprint(X509Certificate c) {
        return c.getSubjectX500Principal().getName() + "#" + c.getSerialNumber();
    }

    private static final class CapturingTrustManager implements X509TrustManager {

        private final         X509TrustManager delegate;
        private X509Certificate[] chain;

        CapturingTrustManager(X509TrustManager delegate) {
            this.delegate = delegate;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            delegate.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            this.chain = chain == null ? null : chain.clone();
            delegate.checkServerTrusted(chain, authType);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return delegate.getAcceptedIssuers();
        }

        X509Certificate[] chain() {
            return chain;
        }
    }
}
