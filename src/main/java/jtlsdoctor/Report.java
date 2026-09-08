package jtlsdoctor;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Report {

    private final String target;
    private final String trustStoreDescription;
    private final List<CheckResult> checks;
    private final List<String> chainPem;

    public Report(String target, String trustStoreDescription, List<CheckResult> checks, List<String> chainPem) {
        this.target = target;
        this.trustStoreDescription = trustStoreDescription;
        this.checks = Collections.unmodifiableList(new ArrayList<CheckResult>(checks));
        this.chainPem = Collections.unmodifiableList(new ArrayList<String>(chainPem));
    }

    public String target() {
        return target;
    }

    public String trustStoreDescription() {
        return trustStoreDescription;
    }

    public List<CheckResult> checks() {
        return checks;
    }

    /** Raw sent chain as PEM, in the order received (empty when none was received). */
    public List<String> chainPem() {
        return chainPem;
    }

    public CheckResult.Status overall() {
        boolean warn = false;
        for (CheckResult c : checks) {
            if (c.status() == CheckResult.Status.FAIL) {
                return CheckResult.Status.FAIL;
            }
            if (c.status() == CheckResult.Status.WARN) {
                warn = true;
            }
        }
        return warn ? CheckResult.Status.WARN : CheckResult.Status.OK;
    }

    public long count(CheckResult.Status status) {
        return checks.stream().filter(c -> c.status() == status).count();
    }

    /**
     * Report as JSON-ready data: same structure as the HTTP API response.
     * When withChainPem is true, the sent certificates are added as a
     * "certificates" array of PEM blocks (in the order they were sent).
     */
    public Map<String, Object> json(boolean withChainPem) {
        Map<String, Object> m = new LinkedHashMap<String, Object>();
        m.put("target", target);
        m.put("truststore", trustStoreDescription);
        m.put("result", overall() == CheckResult.Status.FAIL ? "FAIL"
                : overall() == CheckResult.Status.WARN ? "WARN" : "PASS");
        m.put("errors", Long.valueOf(count(CheckResult.Status.FAIL)));
        m.put("warnings", Long.valueOf(count(CheckResult.Status.WARN)));
        List<Object> list = new ArrayList<Object>();
        for (CheckResult c : checks) {
            Map<String, Object> cj = new LinkedHashMap<String, Object>();
            cj.put("name", c.name());
            cj.put("status", c.status().name());
            cj.put("detail", c.detail());
            list.add(cj);
        }
        m.put("checks", list);
        if (withChainPem) {
            m.put("certificates", chainPem);
        }
        return m;
    }
}
