package server;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import server.application.Application;
import server.application.Session;
import server.application.User;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuthServerTests {

    private Application app;

    @BeforeEach
    void setup() {
        app = new Application(UUID.randomUUID(), "My App");
    }

    @Test
    void createNonExistingUser() {
        String username = "billy@kid.com";
        String password = "aSeCuRePaSsW0rd.";

        User user = app.createUser(username, password);

        assertThat(user.getUsername()).isEqualTo(username);
        assertThat(user.getUid()).isNotNull();
    }

    @Test
    void createDuplicateUser() {
        String username = "billy@kid.com";
        app.createUser(username, "password 1");

        Exception e = assertThrows(RuntimeException.class,
                () -> app.createUser(username, "password 2"));
        assertThat(e).hasMessageThat().contains("exists");
    }

    @Test
    void getExistingUser() {
        String username = "billy@kid.com";
        String password = "aSeCuRePaSsW0rd.";

        User createdUser = app.createUser(username, password);

        Optional<User> retrievedUser = app.getUser(username);

        assertThat(retrievedUser.isPresent()).isTrue();
        assertThat(createdUser.getUsername()).isEqualTo(retrievedUser.get().getUsername());
    }

    @Test
    void getNonExistingUser() {
        String username = "billy@kid.com";

        Optional<User> retrievedUser = app.getUser(username);

        assertThat(retrievedUser.isEmpty()).isTrue();
    }

    @Test
    void authenticateUser() {
        String username = "billy@kid.com";
        String password = "aSeCuRePaSsW0rd.";
        final User user = app.createUser(username, password);

        assertThat(user.authenticate(password)).isTrue();
    }

    @Test
    void createSession() {
        String username = "billy@kid.com";
        String password = "aSeCuRePaSsW0rd.";
        final User user = app.createUser(username, password);

        Session session = app.createSession(user);
        String tokenUsername = Jwts.parser()
                .setSigningKey(app.getPublicKey())
                .parseClaimsJws(session.getJwt())
                .getBody().get("username", String.class);

        assertThat(username).isEqualTo(tokenUsername);
    }

    @Test
    void createRole() {
        List<String> permissions = new ArrayList<>();
        permissions.add("APPLICATIONS_ALL");
        permissions.add("USERS_ALL");
        app.createRoleWithPermissions("admin", permissions);

        assertThat(app.hasRole("admin")).isTrue();
    }

    @Test
    void retrieveRole() {
        List<String> permissions = new ArrayList<>();
        permissions.add("APPLICATIONS_ALL");
        permissions.add("USERS_ALL");
        app.createRoleWithPermissions("admin", permissions);

        assertThat(app.getPermissions("admin")).containsExactlyElementsIn(permissions);
    }

    @Test
    void retrieveNonExistantRole() {
        Exception e = assertThrows(RuntimeException.class,
                () -> app.getPermissions("admin"));
        assertThat(e).hasMessageThat().contains("not found");
    }

    @Test
    void addRoleToUser() {
        List<String> permissions = new ArrayList<>();
        permissions.add("APPLICATIONS_ALL");
        permissions.add("USERS_ALL");
        app.createRoleWithPermissions("admin", permissions);

        assertThat(app.hasRole("admin")).isTrue();
    }

    @Test
    void jwtContainsUserRolesAndPermissions() {
        app.createRoleWithPermissions("basic", List.of("PROFILE_VIEW"));
        app.createRoleWithPermissions("super_admin", List.of("EVERYTHING"));

        User user = app.createUser("username", "password");
        user.addRole("basic");
        user.addRole("super_admin");

        Session session = app.createSession(user);
        String jws = session.getJwt();
        Claims claims = Jwts.parser().setSigningKey(app.getPublicKey())
                .parseClaimsJws(jws)
                .getBody();

        String scope = claims.get("scope", String.class);

        assertThat(scope).isNotNull();
        assertThat(scope.split(" ")).asList().containsExactly("PROFILE_VIEW", "EVERYTHING");
    }

}
