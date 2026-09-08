# jtls-doctor

jtls-doctor checks that a TLS server is configured correctly. It connects the same
way a regular TLS client (e.g. Java, browsers, curl) would, and if the certificate
chain is broken it tells you exactly what is wrong — in plain text, with a
pass/fail exit code that is easy to use in scripts and CI.

## What it checks

- **connect** — a TLS connection can be established (this also catches expired
  certificates and hostname mismatches)
- **chain-order** — the certificates are sent leaf-to-root, in the order Java expects
- **intermediates** — the server sends every intermediate certificate that is needed
- **trust** — the root CA is trusted: the JVM default truststore (`cacerts`) by
  default, or a custom truststore via `--truststore`
- **extras** — no unnecessary certificates are sent: the root CA must be omitted,
  and there must be no duplicates or unneeded certificates
- **sni** — the server serves the same certificate even when the client omits
  SNI (servers that only present their certificate to SNI-aware clients will
  fail here; skipped for IP targets)

`extras` and `sni` problems are warnings (yellow, exit code 0): the costly
errors are a broken or untrusted chain, while extra/missing certificates and
SNI-only deployments usually keep working for standard clients.

The plain-text summary is colored when written to a terminal
(never when redirected, never with `NO_COLOR` set, never with `--json`).

## Building & contributing

Basic file formatting rules (charset, indentation, final newlines) are defined
in the plain `.editorconfig`, which most editors apply automatically — no
extra tooling needed.

## Requirements

- Java 8 or newer to run the tool
- Java 17 or newer to build (the Gradle wrapper needs it)

Note: the reported protocol depends on what the running JVM supports. Very old
Java 8 releases only speak TLS 1.2; TLS 1.3 requires Java 11+ (or 8u261+).

## Build

No Gradle installation is needed: use the bundled wrapper
(`gradlew.bat` on Windows).

```bash
./gradlew build          # produces build/libs/jtls-doctor-<version>.jar
./gradlew installDist    # produces a start script in build/install/jtls-doctor/bin/
```

## Run

```bash
java -jar build/libs/jtls-doctor-0.1.0.jar example.com:443

# or, after `./gradlew installDist`:
build/install/jtls-doctor/bin/jtls-doctor example.com
```

The port defaults to 443. An `https://` prefix and trailing slashes are ignored,
so URLs like `https://example.com/` work too. IPv6 targets are written as
`[2001:db8::1]:443`.

## Options

```
Usage: jtls-doctor <host>[:port] [options]

Options:
  --truststore <file>         use <file> as truststore instead of the JVM default
  --truststore-password <pw>  truststore password (default: changeit)
  --http <[host:]port>        run the JSON API instead of checking one target
                              (single endpoint: POST /check)
  --json                      output the result as JSON instead of the plain-text
                              summary; this is always byte-identical to what the
                              HTTP API would answer for the same request
  --dump-chain [file]         dump the certificate chain as sent by the server in PEM
                              form to <file>, each block preceded by subject/issuer/
                              validity; without a filename, and only with --json, each
                              "certificates" entry in the output gains a "pem" field
  -h, --help                  show this help
```

The truststore can be JKS or PKCS12. Use a custom truststore to check servers
that chain to an internal or private CA.

## Exit codes

| Code | Meaning                                              |
|------|------------------------------------------------------|
| 0    | all checks passed (warnings allowed)                 |
| 1    | at least one check failed                            |
| 2    | usage error (bad arguments, unreadable truststore, …) |

## Examples

A correctly configured server:

```
$ jtls-doctor www.lapo.it
www.lapo.it:443  (truststore: default JVM cacerts)
  connect        OK   TLSv1.3, TLS_AES_256_GCM_SHA384
  chain-order    OK   4 certificate(s) sent, leaf-to-root order valid
  intermediates  OK   all required intermediates sent
  trust          OK   root CA 'CN=ISRG Root X1' trusted via default JVM cacerts
  extras         OK   no extra certificates
  sni            OK   same certificate served without SNI
RESULT: PASS
```

A server that does not send its intermediate certificate (and also serves
its fallback certificate to clients without SNI):

```
$ jtls-doctor incomplete-chain.badssl.com
incomplete-chain.badssl.com:443  (truststore: default JVM cacerts)
  connect        FAIL unable to find valid certification path to requested target
  chain-order    OK   1 certificate(s) sent, leaf-to-root order valid
  intermediates  FAIL missing intermediate certificate(s) between 'CN=*.badssl.com' and a trusted root
  trust          FAIL cannot build a trusted certification path: unable to find valid certification path to requested target
  extras         OK   no extra certificates
  sni            FAIL server sent a different certificate without SNI: 'CN=badssl-fallback-unknown-subdomain-or-no-sni'
RESULT: FAIL (4 errors)
```

A server whose root CA is not trusted, checked against a private CA's
truststore instead of `cacerts`:

```
$ jtls-doctor internal.example.org:8443 --truststore /etc/pki/company-ca.p12
```

With `--json`, the same data as the HTTP API is printed as JSON
(exit codes are unchanged):

```bash
$ jtls-doctor badssl.com --json
{"target":"badssl.com:443","truststore":"default JVM cacerts","result":"PASS",
 "errors":0,"warnings":0,"checks":[{"name":"connect","status":"OK","detail":"..."},...]}
```

## HTTP API

Instead of checking a single target, jtls-doctor can serve a minimal JSON API
plus a small single-page web interface:

- `http://host:port/` (or `/index.html`) — browser UI: enter a host, run the
  check and browse the report; certificates can be viewed in a modal,
  downloaded as PEM or opened in the [asn1js.eu](https://asn1js.eu) viewer
- `POST /check` (`GET /check?host=…`) — the same checks as JSON

```bash
jtls-doctor --http :8080                      # listen on all interfaces
jtls-doctor --http 8080                       # listen on localhost only
jtls-doctor --http 127.0.0.1:8080 --truststore /etc/pki/company-ca.p12
```

It runs until interrupted and exposes a single endpoint, `POST /check`
(`GET /check?host=...` also works). Request fields:

| Field           | Type   | Meaning                                            |
|-----------------|--------|----------------------------------------------------|
| `host`          | string | required, hostname of the server to check          |
| `port`          | number | optional, defaults to 443                           |
| `truststorePem` | string | optional: PEM certificate(s) used as truststore    |
|                 |        | instead of the server's default truststore          |
| `dumpChain`     | bool   | optional: when `true`, each element of `certificates`|
|                 |        | gains a `pem` field with the PEM block of that       |
|                 |        | certificate                                          |

The response always includes a `certificates` array describing the chain in
the order the server sent it; each element is an object with `subject`,
`issuer` and `notbefore`/`notafter` (ISO 8601 instants). The PEM blocks are
only added (as a `pem` field of each element) when requested.
`jtls-doctor --json` returns exactly the same JSON.

The result is always HTTP `200` if a check ran; `result` carries the verdict.
HTTP `400` is returned for malformed requests (bad JSON, missing/invalid host
or port, invalid PEM), `405` for other methods, and `404` for other paths.

```bash
$ curl -s -X POST http://localhost:8080/check -d '{"host":"badssl.com"}'
{"target":"badssl.com:443","truststore":"default JVM cacerts","result":"PASS",
 "errors":0,"warnings":0,"checks":[
   {"name":"connect","status":"OK","detail":"TLSv1.2, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
   {"name":"chain-order","status":"OK","detail":"3 certificate(s) sent, leaf-to-root order valid"},
   {"name":"intermediates","status":"OK","detail":"all required intermediates sent"},
   {"name":"trust","status":"OK","detail":"root CA 'CN=ISRG Root X1' trusted via default JVM cacerts"},
   {"name":"extras","status":"OK","detail":"no extra certificates"}]}
```

Custom trust certificates (e.g. a private CA) can be supplied per request:

```bash
curl -s -X POST http://localhost:8080/check \
     -d '{"host":"internal.example.org","truststorePem":"-----BEGIN CERTIFICATE-----
MIIB..."}'
```

## License

ISC — see [LICENSE](LICENSE).
