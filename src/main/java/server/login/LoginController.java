package server.login;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import server.AuthServer;
import server.application.Session;
import server.application.User;

import java.util.Base64;
import java.util.Optional;

public class LoginController {

    private static final Logger logger = LoggerFactory.getLogger(LoginController.class);

    public static AuthServer.WithApplicationHandler publicKeys = (ctx, app) -> {
        String encodedKey = Base64.getEncoder()
                .encodeToString(app.getPublicKey().getEncoded());
        ctx.result(encodedKey);
    };

    public static AuthServer.WithApplicationHandler login = (ctx, app) -> {
        LoginRequest body = ctx.bodyAsClass(LoginRequest.class);
        String username = body.username;
        String password = body.password;

        // Of course you would never do this in production code!
        logger.info("Authenticating user {} {}", username, password);

        Optional<User> user = app.getUser(username);
        if (user.isEmpty()) {
            ctx.status(403);
            ctx.result("Unable to authenticate user");
        } else if (user.get().authenticate(password)) {
            Session session = app.createSession(user.get());
            ctx.status(200);
            ctx.header("x-authentication", session.getJwt());
        }
    };
}
