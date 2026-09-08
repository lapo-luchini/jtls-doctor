package jtlsdoctor;

import java.util.ArrayList;
import java.util.Collections;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Report {

    private final String target;
    private final String trustStoreDescription;
    private final List<CheckResult> checks;

    public Report(String target, String trustStoreDescription, List<CheckResult> checks) {
        this.target = target;
        this.trustStoreDescription = trustStoreDescription;
        this.checks = Collections.unmodifiableList(new ArrayList<CheckResult>(checks));
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
     */
    public Map<String, Object> json() {
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
        return m;
    }
}
