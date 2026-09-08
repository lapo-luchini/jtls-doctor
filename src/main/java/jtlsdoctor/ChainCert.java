package jtlsdoctor;

import java.time.Instant;

/** One certificate of the chain as sent by the server, with its metadata. */
public final class ChainCert {

    private final String subject;
    private final String issuer;
    private final Instant notBefore;
    private final Instant notAfter;
    private final String pem;

    public ChainCert(String subject, String issuer, Instant notBefore, Instant notAfter, String pem) {
        this.subject = subject;
        this.issuer = issuer;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
        this.pem = pem;
    }

    public String subject() {
        return subject;
    }

    public String issuer() {
        return issuer;
    }

    public Instant notBefore() {
        return notBefore;
    }

    public Instant notAfter() {
        return notAfter;
    }

    public String pem() {
        return pem;
    }

    /**
     * Short description followed by the PEM block, as written by --dump-chain.
     */
    public String dumpBlock() {
        return "Subject: " + subject + "\n"
                + "Issuer:  " + issuer + "\n"
                + "Valid:   " + iso(notBefore) + " / " + iso(notAfter) + "\n"
                + pem;
    }

    private static String iso(Instant when) {
        return java.time.format.DateTimeFormatter.ISO_INSTANT.format(when);
    }
}
