package me.sonam.authentication;


import me.sonam.authentication.handler.AuthTransfer;
import me.sonam.authentication.repo.entity.Authentication;
import okhttp3.mockwebserver.MockResponse;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

public class AuthenticateWithRemoteEndpoint {
    private static final Logger LOG = LoggerFactory.getLogger(AuthenticateWithRemoteEndpoint.class);

    private WebClient webClient = WebClient.builder().build();

    @Test
    void authenticate() throws InterruptedException {
        LOG.info("authenticate with remote endpoint using username and password to get a jwt");

        WebClient.ResponseSpec responseSpec = webClient.post().uri("https://authentication-rest-service.sonam.cloud/public/authentications/authenticate")
                .bodyValue(new AuthTransfer("dummy1234", "12", UUID.randomUUID()))
                .retrieve();

        //LOG.info("httpHeaders: {}", responseSpec.toBodilessEntity().block().getHeaders());
        //responseSpec.bodyToMono(String.class).subscribe(s -> LOG.info("jwt: {}", s));
        //responseSpec.toEntity(String.class).subscribe(stringResponseEntity -> LOG.info("string: {}", stringResponseEntity.getBody()));

        LOG.info("body: {}", responseSpec.bodyToMono(String.class).block());
    }

    @Test
    public void validateJwt() {
        final String jwt = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJkdW1teTEyMzQiLCJpc3MiOiJzb25hbS5jbG91ZCIsImF1ZCI6InNvbmFtLmNsb3VkIiwiZXhwIjoxNjU3NDU2MjYzLCJqdGkiOiI0Y2Y4ZWYxZi1lZjM3LTRkMTctOGEzNC00YTRkNmNjNzVjZjcifQ.laKyiskryOrrFZfrwvc_F3-AnEcT5MO6s9j4iILdjBbOqbB7Evkxqqm00j3wu-MDVWkvWTI4NKFSHeF0R1I-Bw";

        WebClient.ResponseSpec responseSpec = webClient.post().uri("https://authentication-rest-service.sonam.cloud/public/authentications/authenticate")
                .bodyValue(new AuthTransfer("dummy1234", "12", UUID.randomUUID()))
                .retrieve();

        LOG.info("httpHeaders: {}", responseSpec.toBodilessEntity().block().getHeaders());
        responseSpec.bodyToMono(String.class).subscribe(s -> LOG.info("jwt: {}", s));
        responseSpec.toEntity(String.class).subscribe(stringResponseEntity -> LOG.info("string: {}", stringResponseEntity.getBody()));

        LOG.info("body: {}", responseSpec.bodyToMono(String.class).block());
    }
}
