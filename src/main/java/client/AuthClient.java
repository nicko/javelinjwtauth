package client;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

public class AuthClient {

    private static Logger logger = LoggerFactory.getLogger(AuthClient.class);
    private static final String HOST = "http://localhost:7000";
    private static final String HEADER_API_KEY = "x-api-key";
    private static final String API_KEY = "01dbf181-9d74-4684-8a5d-c8db8937f719";
    private static final String KEY_PATH = "/public-keys";
    private static final String LOGIN_PATH = "/login";

    public static void main(String[] args) {
        String username = args[0];
        String password = args[1];
        AuthClient client = new AuthClient(HOST, HttpClient.newHttpClient());

        client.getPublicKey()
                .flatMap(key -> client.login(key, username, password))
                .ifPresent(client::printUser);
    }

    private HttpClient httpClient;
    private String host;

    AuthClient(String host, HttpClient httpClient) {
        this.httpClient = httpClient;
        this.host = host;
    }

    public Optional<PublicKey> getPublicKey() {
        try {
            HttpRequest request = HttpRequest
                    .newBuilder(URI.create(this.host + KEY_PATH))
                    .header(HEADER_API_KEY, API_KEY)
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            byte[] publicKeyBytes = Base64.getDecoder().decode(response.body());

            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            AtomicReference<KeyFactory> keyFactory
                    = new AtomicReference<>(KeyFactory.getInstance("EC"));

            PublicKey key = keyFactory.get().generatePublic(pubKeySpec);
            logger.info("Retrieved public key {}", key);
            return Optional.of(key);
        } catch (Exception e) {
            logger.error("Unable to retrieve key: {}", e.getMessage());
        }
        return Optional.empty();
    }

    public Optional<User> login(PublicKey publicKey, String username, String password) {
        String json = String.format("{\"username\":\"%s\",\"password\": \"%s\"}", username, password);
        HttpRequest request = HttpRequest
                .newBuilder(URI.create(this.host + LOGIN_PATH))
                .header(HEADER_API_KEY, API_KEY)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            Optional<String> header = response.headers().firstValue("x-authentication");

            if (header.isEmpty()) {
                logger.error("Unable to authorise user");
            } else {
                String jws = header.get();

                Claims claims = Jwts.parser().setSigningKey(publicKey)
                        .parseClaimsJws(jws)
                        .getBody();
                logger.info("Successfully authenticated {}", claims.get("username"));
                logger.info("Created at: {}", claims.getIssuedAt().toString());
                logger.info("Expires at: {}", claims.getExpiration().toString());
                logger.info("Token issuer: {}", claims.getIssuer());

                return Optional.of(new User(
                        claims.get("username", String.class),
                        claims.getSubject(),
                        claims.get("scope", String.class).split(" ")
                ));
            }
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        return Optional.empty();
    }

    private void printUser(User user) {
        logger.info("Username: {}", user.getUsername());
        logger.info("UID: {}", user.getUid());
        logger.info("Permissions: [{}]", String.join(", ", user.getPermissions()));
    }

}
