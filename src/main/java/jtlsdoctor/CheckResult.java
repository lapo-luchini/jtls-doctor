package jtlsdoctor;

public record CheckResult(String name, Status status, String detail) {

    public enum Status { OK, WARN, FAIL, SKIP }

    public static CheckResult ok(String name, String detail) {
        return new CheckResult(name, Status.OK, detail);
    }

    public static CheckResult fail(String name, String detail) {
        return new CheckResult(name, Status.FAIL, detail);
    }

    public static CheckResult skip(String name, String detail) {
        return new CheckResult(name, Status.SKIP, detail);
    }
}
