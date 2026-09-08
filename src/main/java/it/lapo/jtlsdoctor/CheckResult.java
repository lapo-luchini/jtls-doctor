package it.lapo.jtlsdoctor;

public final class CheckResult {

    public enum Status { OK, WARN, FAIL, SKIP }

    private final String name;
    private final Status status;
    private final String detail;

    public CheckResult(String name, Status status, String detail) {
        this.name = name;
        this.status = status;
        this.detail = detail;
    }

    public String name() {
        return name;
    }

    public Status status() {
        return status;
    }

    public String detail() {
        return detail;
    }

    public static CheckResult ok(String name, String detail) {
        return new CheckResult(name, Status.OK, detail);
    }

    public static CheckResult fail(String name, String detail) {
        return new CheckResult(name, Status.FAIL, detail);
    }

    public static CheckResult warn(String name, String detail) {
        return new CheckResult(name, Status.WARN, detail);
    }

    public static CheckResult skip(String name, String detail) {
        return new CheckResult(name, Status.SKIP, detail);
    }
}
