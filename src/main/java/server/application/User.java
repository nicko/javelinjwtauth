package server.application;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

public class User {
    private final UUID uid;
    private final String username;
    private String passwordHash;
    private Set<String> roles;

    public User(String username, String password) {
        this.username = username;
        this.uid = UUID.randomUUID();
        // TODO: Clearly need to actually encrypt this.
        this.passwordHash = password;
        this.roles = new HashSet<>();
    }

    public String getUsername() {
        return username;
    }

    public UUID getUid() {
        return uid;
    }

    public Boolean authenticate(String password) {
        return password.equals(this.passwordHash);
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void addRole(String roleName) {
        roles.add(roleName);
    }
}
