package client;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

class User {
    private final UUID uid;
    private final String username;
    private Set<String> permissions;

    public User(String username, String uid, String[] permissions) {
        this.username = username;
        this.uid = UUID.fromString(uid);
        this.permissions = new HashSet<>(Arrays.asList(permissions));
    }

    public String getUsername() {
        return username;
    }

    public UUID getUid() {
        return uid;
    }

    public Set<String> getPermissions() {
        return permissions;
    }
}
