package server;

import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.Handler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import server.application.Application;
import server.application.User;
import server.login.LoginController;

import java.util.*;

public class AuthServer {

    private static final Logger logger = LoggerFactory.getLogger(AuthServer.class);
    private static final int PORT = 7000;

    private Map<String, Application> appByAccountKey = new HashMap<>();

    private AuthServer() {
        Javalin server = Javalin.create(config -> {
            config.requestLogger((ctx, ms) -> {
                String message = String.format("[%d] %s Completed in %d ms.\n\t%s", ctx.status(), ctx.req.getRequestURI(), ms.intValue(), ctx.resultString());
                if (ctx.status() == 200) {
                    logger.info(message);
                } else {
                    logger.warn(message);
                }
            });
        }).start(PORT);

        logger.info("Auth server started and listening on port " + PORT);

        server.get("/public-keys", withApplication(LoginController.publicKeys));

        server.post("/login", withApplication(LoginController.login));

        registerDefaultApplications();
    }

    private Handler withApplication(WithApplicationHandler handler) {
        return ctx -> {
            String apiKey = ctx.req.getHeader("x-api-key");
            if (apiKey == null || !appByAccountKey.containsKey(apiKey)) {
                ctx.status(403);
                ctx.result("API Key invalid or application not found");
            } else {
                handler.handle(ctx, appByAccountKey.get(apiKey));
            }
        };
    }

    public interface WithApplicationHandler {
        void handle(Context context, Application app) throws Exception;
    }

    private void registerDefaultApplications() {
        Application app1 = new Application(UUID.fromString("01dbf181-9d74-4684-8a5d-c8db8937f719"), "client-app-1");
        appByAccountKey.put(app1.getUid().toString(), app1);
        logger.info("Added app with API Key " + app1.getUid());

        app1.createRoleWithPermissions("site_admin", List.of("create_page", "update_page", "delete_page"));
        app1.createRoleWithPermissions("stock_admin", List.of("add_stock", "update_stock", "delete_stock"));

        User user1 = app1.createUser("alice", "password123");
        user1.addRole("site_admin");
        User user2 = app1.createUser("bill", "password456");
        user2.addRole("stock_admin");
    }

    public static void main(String[] args) {
        new AuthServer();
    }
}
