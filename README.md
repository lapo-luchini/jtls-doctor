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

## Requirements

- Java 8 or newer to run the tool
- Gradle 8 or newer to build

Note: the reported protocol depends on what the running JVM supports. Very old
Java 8 releases only speak TLS 1.2; TLS 1.3 requires Java 11+ (or 8u261+).

## Build

```bash
gradle build          # produces build/libs/jtls-doctor-<version>.jar
gradle installDist    # produces a start script in build/install/jtls-doctor/bin/
```

## Run

```bash
java -jar build/libs/jtls-doctor-0.1.0.jar example.com:443

# or, after `gradle installDist`:
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
  -h, --help                  show this help
```

The truststore can be JKS or PKCS12. Use a custom truststore to check servers
that chain to an internal or private CA.

## Exit codes

| Code | Meaning                                              |
|------|------------------------------------------------------|
| 0    | all checks passed                                    |
| 1    | at least one check failed                            |
| 2    | usage error (bad arguments, unreadable truststore, …) |

## Examples

A correctly configured server:

```
$ jtls-doctor badssl.com
badssl.com:443  (truststore: default JVM cacerts)
  connect        OK   TLSv1.2, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  chain-order    OK   3 certificate(s) sent, leaf-to-root order valid
  intermediates  OK   all required intermediates sent
  trust          OK   root CA 'CN=ISRG Root X1' trusted via default JVM cacerts
  extras         OK   no extra certificates
RESULT: PASS
```

A server that does not send its intermediate certificate:

```
$ jtls-doctor incomplete-chain.badssl.com
incomplete-chain.badssl.com:443  (truststore: default JVM cacerts)
  connect        FAIL unable to find valid certification path to requested target
  chain-order    OK   1 certificate(s) sent, leaf-to-root order valid
  intermediates  FAIL missing intermediate certificate(s) between 'CN=*.badssl.com' and a trusted root
  trust          FAIL cannot build a trusted certification path: unable to find valid certification path to requested target
  extras         OK   no extra certificates
RESULT: FAIL (3 errors)
```

A server whose root CA is not trusted, checked against a private CA's
truststore instead of `cacerts`:

```
$ jtls-doctor internal.example.org:8443 --truststore /etc/pki/company-ca.p12
```

## License

ISC — see [LICENSE](LICENSE).

A minimal HTTP API exposing the same checks via a single `GET` endpoint is planned.
