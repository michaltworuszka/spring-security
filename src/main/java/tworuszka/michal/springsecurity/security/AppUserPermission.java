package tworuszka.michal.springsecurity.security;

public enum AppUserPermission {
    STUDENT_READ ("s:read"),
    STUDENT_WRITE("s:write"),
    COURSE_READ("c:read"),
    COURSE_WRITE("c:write");

    private final String permission;

    AppUserPermission(String permission) {
        this.permission = permission;
    }
    public String getPermission() {
        return permission;
    }
}
