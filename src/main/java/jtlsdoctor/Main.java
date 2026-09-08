package jtlsdoctor;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.List;

public final class Main {

    // ANSI escape sequences for the colored summary output
    private static final String ANSI_START = "\u001B["; // Control Sequence Introducer
    private static final String SET_COLOR_GREEN = "32"; // ...+ "m" starts a green span
    private static final String SET_COLOR_RED = "31";
    private static final String SET_COLOR_YELLOW = "33";
    private static final String SET_COLOR_GRAY = "90";
    private static final String ANSI_RESET = "\u001B[0m"; // back to default attributes

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
        } catch (InterruptedException e) {
            System.exit(0); // server stopped (Ctrl+C)
        }
    }

    private static void run(String[] args) throws IOException, GeneralSecurityException, InterruptedException {
        String targetArg = null;
        String httpBind = null;
        boolean jsonOutput = false;
        boolean dumpChain = false;
        Path chainDumpFile = null;
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
            } else if (a.equals("--http")) {
                httpBind = value(args, ++i, a);
            } else if (a.equals("--json")) {
                jsonOutput = true;
            } else if (a.equals("--dump-chain")) {
                dumpChain = true;
                if (i + 1 < args.length && !args[i + 1].startsWith("-")) {
                    chainDumpFile = Paths.get(args[++i]);
                }
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

        if (targetArg != null && httpBind != null) {
            throw new UsageException("--http cannot be combined with a target host");
        }
        if (jsonOutput && httpBind != null) {
            throw new UsageException("--json cannot be combined with --http");
        }
        if (dumpChain && httpBind != null) {
            throw new UsageException("--dump-chain cannot be combined with --http");
        }
        if (dumpChain && chainDumpFile == null && !jsonOutput) {
            throw new UsageException("--dump-chain needs a filename (it is printed to stdout only with --json)");
        }

        TrustStore trustStore = truststorePath == null
                ? TrustStore.defaultJvm()
                : TrustStore.load(truststorePath, truststorePassword, truststorePath.toString());

        if (httpBind != null) {
            String[] bind = parseBind(httpBind);
            new HttpApi(bind[0], Integer.parseInt(bind[1]), trustStore).start();
            return;
        }

        if (targetArg == null) {
            throw new UsageException("missing target host");
        }

        String[] hp = parseTarget(targetArg);
        String host = hp[0];
        int port = Integer.parseInt(hp[1]);

        Report report = new TlsDoctor(trustStore).check(host, port);
        if (dumpChain && chainDumpFile != null) {
            writeChain(report, chainDumpFile);
        }
        if (jsonOutput) {
            System.out.println(Json.write(report.json(dumpChain)));
        } else {
            print(report);
        }
        System.exit(report.overall() == CheckResult.Status.FAIL ? 1 : 0);
    }

    private static void writeChain(Report report, Path file) throws IOException {
        BufferedWriter out = Files.newBufferedWriter(file);
        try {
            for (ChainCert cert : report.chain()) {
                out.write(cert.dumpBlock());
                out.write('\n');
            }
        } finally {
            out.close();
        }
    }

    private static String value(String[] args, int index, String option) {
        if (index >= args.length) {
            throw new UsageException("missing value for " + option);
        }
        return args[index];
    }

    private static String[] parseBind(String s) {
        String host = "127.0.0.1";
        String port = s;
        if (s.startsWith("[")) {
            int end = s.indexOf(']');
            if (end < 0) {
                throw new UsageException("invalid bind address: " + s);
            }
            host = s.substring(1, end);
            if (end + 1 < s.length()) {
                if (s.charAt(end + 1) != ':') {
                    throw new UsageException("invalid bind address: " + s);
                }
                port = s.substring(end + 2);
            } else {
                port = "8080";
            }
        } else {
            int colon = s.lastIndexOf(':');
            if (colon == 0) {
                host = "0.0.0.0";
                port = s.substring(1);
            } else if (colon > 0) {
                host = s.substring(0, colon);
                port = s.substring(colon + 1);
            }
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
        boolean color = System.console() != null && System.getenv("NO_COLOR") == null;
        System.out.println(report.target() + "  (truststore: " + report.trustStoreDescription() + ")");
        for (CheckResult c : report.checks()) {
            System.out.printf("  %-14s %s %s%n", c.name(), mark(c.status(), color),
                    c.detail() == null ? "" : c.detail());
        }
        StringBuilder line = new StringBuilder("RESULT: ");
        CheckResult.Status overall = report.overall();
        if (overall == CheckResult.Status.FAIL) {
            line.append(colored("FAIL", SET_COLOR_RED, color));
        } else if (overall == CheckResult.Status.WARN) {
            line.append(colored("WARN", SET_COLOR_YELLOW, color));
        } else {
            line.append(colored("PASS", SET_COLOR_GREEN, color));
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

    /**
     * Colored status token, kept 4 characters wide from the uncolored text so
     * the detail column stays aligned whether or not colors are in use.
     */
    private static String mark(CheckResult.Status status, boolean color) {
        String code;
        if (status == CheckResult.Status.FAIL) {
            code = SET_COLOR_RED;
        } else if (status == CheckResult.Status.WARN) {
            code = SET_COLOR_YELLOW;
        } else if (status == CheckResult.Status.SKIP) {
            code = SET_COLOR_GRAY;
        } else {
            code = SET_COLOR_GREEN;
        }
        return colored(String.format("%-4s", status.name()), code, color);
    }

    private static String colored(String text, String code, boolean color) {
        if (!color) {
            return text;
        }
        return ANSI_START + code + "m" + text + ANSI_RESET;
    }

    private static void printUsage(PrintStream out) {
        out.println("Usage: jtls-doctor <host>[:port] [options]");
        out.println();
        out.println("Checks that a TLS server presents a correct certificate chain:");
        out.println("  - the root CA is trusted (JVM cacerts or a custom truststore)");
        out.println("  - all required intermediate certificates are sent by the server");
        out.println("  - certificates are sent leaf-to-root, in the correct order");
        out.println("  - no extra certificates (e.g. the root CA) are sent");
        out.println("  - the same certificate is served when the client omits SNI");
        out.println();
        out.println("Options:");
        out.println("  --truststore <file>         use <file> as truststore instead of the JVM default");
        out.println("  --truststore-password <pw>  truststore password (default: changeit)");
        out.println("  --http <[host:]port>        run the JSON API instead of checking one target");
        out.println("                              (single endpoint: POST /check)");
        out.println("  --json                      output the result as JSON (requires a target; always");
        out.println("                              identical to the equivalent HTTP API response)");
        out.println("  --dump-chain [file]         write the certificate chain sent by the server in PEM");
        out.println("                              form to <file>; without a filename, and only with");
        out.println("                              --json, it is included as the \"certificatePEMs\"");
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
