package client;

import com.github.jenspiegsa.wiremockextension.ConfigureWireMock;
import com.github.jenspiegsa.wiremockextension.InjectServer;
import com.github.jenspiegsa.wiremockextension.WireMockExtension;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.common.ConsoleNotifier;
import com.github.tomakehurst.wiremock.core.Options;
import com.github.tomakehurst.wiremock.matching.MatchResult;
import com.github.tomakehurst.wiremock.matching.StringValuePattern;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.net.http.HttpClient;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Optional;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;

import static com.google.common.truth.Truth.assertThat;

@ExtendWith(WireMockExtension.class)
class AuthClientTests {

    @InjectServer
    WireMockServer serverMock;

    @ConfigureWireMock
    Options options = wireMockConfig()
            .dynamicPort()
            .notifier(new ConsoleNotifier(true));

    private AuthClient client;

    @BeforeEach
    void setup() {
        client = new AuthClient("http://localhost:" + serverMock.port(), HttpClient.newHttpClient());
    }

    @AfterEach
    void teardown() {
        client = null;
    }

    @Test
    void clientRetrievesThePublicKey() {
        givenThat(get("/public-keys")
                .withHeader("x-api-key", containing("01dbf181-9d74-4684-8a5d-c8db8937f719"))
                .willReturn(aResponse().withStatus(200).withBody("MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAE1ikFAE1DiwXRFvVyla1Tkld8URu1Bauv00qlSB81WohFRXBmHAAgzHEm8lwwnyGnO01gEa6b6GHdVV14683bzUBZVc6MVJuwwBfsHW4QWPvT+Cf4Paev7tYgEG6ola2Sv2UO9iZ9aO3Z2MIwHSmE9+pSQBENko/eU78XevQX++K+QA="))
        );

        Optional<PublicKey> actual = client.getPublicKey();

        assertThat(actual.isPresent()).isTrue();
        assertThat(actual.get().getFormat()).isEqualTo("X.509");
    }

    @Test
    void clientCanLogin() {
        final String username = "some user";
        final String password = "what a password!";
        KeyPair pk = Keys.keyPairFor(SignatureAlgorithm.ES512);
        givenThat(post("/login")
                .withHeader("x-api-key", containing("01dbf181-9d74-4684-8a5d-c8db8937f719"))
                .withRequestBody(containing(String.format("{\"username\":\"%s\",\"password\": \"%s\"}", username, password)))
                .willReturn(aResponse().withStatus(200).withHeader("x-authentication", Jwts.builder()
                        .setIssuer("some app")
                        .setIssuedAt(new Date())
                        .setExpiration(new Date(new Date().getTime() + 10000))
                        .setSubject(UUID.randomUUID().toString())
                        .claim("username", username)
                        .claim("scope", "cats ferrets")
                        .signWith(pk.getPrivate())
                        .compact()))
        );

        Optional<User> actual = client.login(pk.getPublic(), username, password);

        assertThat(actual.isPresent()).isTrue();
        assertThat(actual.get().getUsername()).isEqualTo(username);
        assertThat(actual.get().getPermissions()).containsExactly("cats", "ferrets");
    }

}
