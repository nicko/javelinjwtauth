package server.application;

public class Session {

    private final String jwt;

    public Session(String jwt) {
        this.jwt = jwt;
    }

    public String getJwt() {
        return jwt;
    }
}
