package jtlsdoctor;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;

/**
 * Minimal JSON API: a single endpoint, POST (or GET) /check.
 *
 * Request body (all fields optional except host):
 *   {"host": "example.com", "port": 443,
 *    "truststorePem": "-----BEGIN CERTIFICATE-----..."}
 * Query parameters (?host=&port=) work identically for GET.
 */
public final class HttpApi {

    private final String bindHost;
    private final int port;
    private final TrustStore defaultTrustStore;
    private final CountDownLatch stopped = new CountDownLatch(1);

    private static final class BadRequest extends RuntimeException {
        private static final long serialVersionUID = 1L;

        private final int status;

        BadRequest(String message, int status) {
            super(message);
            this.status = status;
        }

        int status() {
            return status;
        }
    }

    private static BadRequest badRequest(String message) {
        return new BadRequest(message, 400);
    }

    public HttpApi(String bindHost, int port, TrustStore defaultTrustStore) {
        this.bindHost = bindHost;
        this.port = port;
        this.defaultTrustStore = defaultTrustStore;
    }

    /** Starts the server and blocks until the process is interrupted. */
    public void start() throws IOException, InterruptedException {
        HttpServer server = HttpServer.create(new InetSocketAddress(bindHost, port), 0);
        com.sun.net.httpserver.HttpHandler h = handler();
        server.createContext("/", h); // one root context: /check handled, everything else -> JSON 404
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println("listening on http://" + bindHost + ":" + port + "/check");
        stopped.await();
    }

    private com.sun.net.httpserver.HttpHandler handler() {
        return new com.sun.net.httpserver.HttpHandler() {
            public void handle(HttpExchange exchange) {
                handleRequest(exchange);
            }
        };
    }

    private void handleRequest(HttpExchange exchange) {
        int status;
        String json;
        try {
            json = Json.write(reportJson(check(exchange)));
            status = 200;
        } catch (BadRequest e) {
            json = errorJson(e.getMessage());
            status = e.status();
        } catch (IllegalArgumentException e) {
            json = errorJson(e.getMessage() == null ? e.toString() : e.getMessage());
            status = 400;
        } catch (IOException e) {
            json = errorJson(e.getMessage() == null ? e.toString() : e.getMessage());
            status = 400;
        } catch (Exception e) {
            json = errorJson("internal error: " + e.getMessage());
            status = 500;
        }
        try {
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
            exchange.sendResponseHeaders(status, bytes.length);
            OutputStream out = exchange.getResponseBody();
            out.write(bytes);
            out.close();
        } catch (IOException ignored) {
            // client is gone; nothing to do
        }
    }

    private Report check(HttpExchange exchange) throws IOException, GeneralSecurityException {
        String uriPath = exchange.getRequestURI().getPath();
        if (!uriPath.equals("/check") && !uriPath.equals("/check/")) {
            throw new BadRequest("unknown path " + uriPath + ": use POST /check", 404);
        }
        String method = exchange.getRequestMethod();
        if (!method.equals("GET") && !method.equals("POST")) {
            throw new BadRequest("method " + method + " not allowed: use POST /check", 405);
        }

        Map<String, Object> params = parameters(exchange);

        Object hostValue = params.get("host");
        if (!(hostValue instanceof String) || ((String) hostValue).trim().isEmpty()) {
            throw badRequest("missing required field: host");
        }
        String host = ((String) hostValue).trim();

        int port = 443;
        Object portValue = params.get("port");
        if (portValue instanceof Number) {
            int p = ((Number) portValue).intValue();
            if (p < 1 || p > 65535) {
                throw badRequest("invalid port: " + portValue);
            }
            port = p;
        } else if (portValue instanceof String) {
            try {
                int p = Integer.parseInt(((String) portValue).trim());
                if (p < 1 || p > 65535) {
                    throw badRequest("invalid port: " + portValue);
                }
                port = p;
            } catch (NumberFormatException e) {
                throw badRequest("invalid port: " + portValue);
            }
        } else if (portValue != null) {
            throw badRequest("invalid port: " + portValue);
        }

        TrustStore trustStore = defaultTrustStore;
        Object pem = params.get("truststorePem");
        if (pem instanceof String && !((String) pem).trim().isEmpty()) {
            trustStore = TrustStore.fromPem((String) pem);
        }

        return new TlsDoctor(trustStore).check(host, port);
    }

    /** Query parameters, overridden by a JSON request body object if present. */
    private Map<String, Object> parameters(HttpExchange exchange) throws BadRequest {
        Map<String, Object> params = new LinkedHashMap<String, Object>();
        String query = exchange.getRequestURI().getRawQuery();
        if (query != null && !query.isEmpty()) {
            for (String pair : query.split("&")) {
                int eq = pair.indexOf('=');
                String key = eq < 0 ? pair : pair.substring(0, eq);
                String value = eq < 0 ? "" : pair.substring(eq + 1);
                try {
                    params.put(URLDecoder.decode(key, "UTF-8"), URLDecoder.decode(value, "UTF-8"));
                } catch (UnsupportedEncodingException e) {
                    throw new AssertionError(e); // UTF-8 always exists
                }
            }
        }
        String body = readBody(exchange);
        if (!body.isEmpty()) {
            Object parsed = Json.parse(body);
            if (!(parsed instanceof Map)) {
                throw badRequest("JSON body must be an object");
            }
            for (Map.Entry<?, ?> e : ((Map<?, ?>) parsed).entrySet()) {
                params.put(String.valueOf(e.getKey()), e.getValue());
            }
        }
        return params;
    }

    private static String readBody(HttpExchange exchange) throws BadRequest {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        InputStream in = exchange.getRequestBody();
        try {
            int n;
            while ((n = in.read(buffer)) > 0) {
                out.write(buffer, 0, n);
                if (out.size() > 1_000_000) {
                    throw badRequest("request body too large");
                }
            }
        } catch (BadRequest e) {
            throw e;
        } catch (IOException e) {
            throw badRequest("cannot read request body: " + e.getMessage());
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8).trim();
    }

    private static Map<String, Object> reportJson(Report report) {
        Map<String, Object> m = new LinkedHashMap<String, Object>();
        m.put("target", report.target());
        m.put("truststore", report.trustStoreDescription());
        CheckResult.Status overall = report.overall();
        m.put("result", overall == CheckResult.Status.FAIL ? "FAIL"
                : overall == CheckResult.Status.WARN ? "WARN" : "PASS");
        m.put("errors", Long.valueOf(report.count(CheckResult.Status.FAIL)));
        m.put("warnings", Long.valueOf(report.count(CheckResult.Status.WARN)));
        List<Object> checks = new ArrayList<Object>();
        for (CheckResult c : report.checks()) {
            Map<String, Object> cj = new LinkedHashMap<String, Object>();
            cj.put("name", c.name());
            cj.put("status", c.status().name());
            cj.put("detail", c.detail());
            checks.add(cj);
        }
        m.put("checks", checks);
        return m;
    }

    private static String errorJson(String message) {
        Map<String, Object> m = new LinkedHashMap<String, Object>();
        m.put("error", message == null ? "internal error" : message);
        return Json.write(m);
    }
}
