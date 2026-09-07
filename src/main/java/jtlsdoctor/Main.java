package jtlsdoctor;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;

public final class Main {

    public static void main(String[] args) {
        try {
            run(args);
        } catch (UsageException e) {
            System.err.println("error: " + e.getMessage());
            System.err.println();
            printUsage(System.err);
            System.exit(2);
        } catch (IOException | GeneralSecurityException e) {
            System.err.println("error: " + e.getMessage());
            System.exit(2);
        }
    }

    private static void run(String[] args) throws IOException, GeneralSecurityException {
        String targetArg = null;
        Path truststorePath = null;
        char[] truststorePassword = "changeit".toCharArray();

        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if (a.equals("-h") || a.equals("--help")) {
                printUsage(System.out);
                return;
            } else if (a.equals("--truststore")) {
                truststorePath = Paths.get(value(args, ++i, a));
            } else if (a.equals("--truststore-password")) {
                truststorePassword = value(args, ++i, a).toCharArray();
            } else {
                if (a.startsWith("-")) {
                    throw new UsageException("unknown option: " + a);
                }
                if (targetArg != null) {
                    throw new UsageException("unexpected extra argument: " + a);
                }
                targetArg = a;
            }
        }
        if (targetArg == null) {
            throw new UsageException("missing target host");
        }

        String[] hp = parseTarget(targetArg);
        String host = hp[0];
        int port = Integer.parseInt(hp[1]);

        TrustStore trustStore = truststorePath == null
                ? TrustStore.defaultJvm()
                : TrustStore.load(truststorePath, truststorePassword, truststorePath.toString());

        Report report = new TlsDoctor(trustStore).check(host, port);
        print(report);
        System.exit(report.overall() == CheckResult.Status.FAIL ? 1 : 0);
    }

    private static String value(String[] args, int index, String option) {
        if (index >= args.length) {
            throw new UsageException("missing value for " + option);
        }
        return args[index];
    }

    private static String[] parseTarget(String s) {
        String t = s;
        if (t.startsWith("https://")) {
            t = t.substring(8);
        } else if (t.startsWith("http://")) {
            t = t.substring(7);
        }
        while (t.endsWith("/")) {
            t = t.substring(0, t.length() - 1);
        }
        String host;
        String port = "443";
        if (t.startsWith("[")) {
            int end = t.indexOf(']');
            if (end < 0) {
                throw new UsageException("invalid target: " + s);
            }
            host = t.substring(1, end);
            if (end + 1 < t.length()) {
                if (t.charAt(end + 1) != ':') {
                    throw new UsageException("invalid target: " + s);
                }
                port = t.substring(end + 2);
            }
        } else {
            int colon = t.lastIndexOf(':');
            if (colon >= 0) {
                host = t.substring(0, colon);
                port = t.substring(colon + 1);
            } else {
                host = t;
            }
        }
        if (host.trim().isEmpty()) {
            throw new UsageException("missing host in target: " + s);
        }
        int p;
        try {
            p = Integer.parseInt(port);
        } catch (NumberFormatException e) {
            throw new UsageException("invalid port: " + port);
        }
        if (p < 1 || p > 65535) {
            throw new UsageException("invalid port: " + port);
        }
        return new String[] { host, String.valueOf(p) };
    }

    private static void print(Report report) {
        System.out.println(report.target() + "  (truststore: " + report.trustStoreDescription() + ")");
        for (CheckResult c : report.checks()) {
            System.out.printf("  %-14s %-4s %s%n", c.name(), c.status(), c.detail() == null ? "" : c.detail());
        }
        StringBuilder line = new StringBuilder("RESULT: ");
        CheckResult.Status overall = report.overall();
        if (overall == CheckResult.Status.FAIL) {
            line.append("FAIL");
        } else if (overall == CheckResult.Status.WARN) {
            line.append("WARN");
        } else {
            line.append("PASS");
        }
        long errors = report.count(CheckResult.Status.FAIL);
        long warnings = report.count(CheckResult.Status.WARN);
        if (errors > 0 || warnings > 0) {
            line.append(" (");
            if (errors > 0) {
                line.append(errors).append(errors == 1 ? " error" : " errors");
            }
            if (warnings > 0) {
                if (errors > 0) {
                    line.append(", ");
                }
                line.append(warnings).append(warnings == 1 ? " warning" : " warnings");
            }
            line.append(")");
        }
        System.out.println(line);
    }

    private static void printUsage(PrintStream out) {
        out.println("Usage: jtls-doctor <host>[:port] [options]");
        out.println();
        out.println("Checks that a TLS server presents a correct certificate chain:");
        out.println("  - the root CA is trusted (JVM cacerts or a custom truststore)");
        out.println("  - all required intermediate certificates are sent by the server");
        out.println("  - certificates are sent leaf-to-root, in the correct order");
        out.println("  - no extra certificates (e.g. the root CA) are sent");
        out.println();
        out.println("Options:");
        out.println("  --truststore <file>         use <file> as truststore instead of the JVM default");
        out.println("  --truststore-password <pw>  truststore password (default: changeit)");
        out.println("  -h, --help                  show this help");
        out.println();
        out.println("Exit codes: 0 all checks passed, 1 checks failed, 2 usage error");
    }

    private static final class UsageException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        UsageException(String message) {
            super(message);
        }
    }
}
