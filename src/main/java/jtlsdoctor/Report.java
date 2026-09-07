package jtlsdoctor;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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
}
