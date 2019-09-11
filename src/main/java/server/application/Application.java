package server.application;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;
import java.util.stream.Collectors;

public class Application {

    private final String name;
    private final UUID uid;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    private Map<String, User> users = new HashMap<>();
    private Map<String, List<String>> roles = new HashMap<>();

    public Application(UUID uid, String name) {
        this.name = name;
        KeyPair pair = Keys.keyPairFor(SignatureAlgorithm.ES512);
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
        this.uid = uid;
    }

    public String getName() {
        return name;
    }

    public UUID getUid() {
        return uid;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public User createUser(String username, String password) {
        if (users.containsKey(username)) {
            throw new RuntimeException("User already exists");
        }
        User user = new User(username, password);
        users.put(username, user);
        return user;
    }

    public Optional<User> getUser(String username) {
        if (users.containsKey(username)) {
            return Optional.of(users.get(username));
        } else {
            return Optional.empty();
        }
    }

    public Session createSession(User user) {
        String scope = user.getRoles()
                .stream().flatMap(role -> roles.get(role).stream()).collect(Collectors.joining(" "));

        Date now = new Date();
        Date expiration = new Date(now.getTime() + 1000 * 60 * 30);
        String jws = Jwts.builder()
                .setSubject(user.getUid().toString())
                .setIssuedAt(now)
                .setExpiration(expiration)
                .setIssuer(getName())
                .claim("username", user.getUsername())
                .claim("scope", scope)
                .signWith(this.privateKey)
                .compact();

        return new Session(jws);
    }

    public void createRoleWithPermissions(String roleName, List<String> permissions) {
        if (roles.containsKey(roleName)) {
            throw new RuntimeException("Role already exists");
        }

        roles.put(roleName, permissions);
    }

    public Boolean hasRole(String roleName) {
        return roles.containsKey(roleName);
    }

    public List<String> getPermissions(String roleName) {
        if (!roles.containsKey(roleName)) {
            throw new RuntimeException("Role with name " + roleName + " not found");
        }

        return roles.get(roleName);
    }
}
