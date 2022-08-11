package me.sonam.authentication;

import me.sonam.authentication.handler.AuthTransfer;
import me.sonam.authentication.repo.AuthenticationRepository;
import me.sonam.authentication.repo.entity.Authentication;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.test.StepVerifier;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@EnableAutoConfiguration
@ExtendWith(SpringExtension.class)
@SpringBootTest( webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class AuthenticationRestTest {
    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationRestTest.class);

    @Value("${apiKey}")
    private String apiKey;

    @Autowired
    private AuthenticationRepository authenticationRepository;

    @Autowired
    private WebTestClient webTestClient;

    @AfterEach
    public void deleteUserRepo() {
        authenticationRepository.deleteAll().subscribe();
    }

    @Test
    public void updatePassword() {
        Authentication authentication = new Authentication("user3", "yakpass", UUID.randomUUID(), UUID.randomUUID(),
                UUID.randomUUID(), true, LocalDateTime.now(), true);
        authenticationRepository.save(authentication).subscribe(authentication1 -> LOG.info("subscribe to save"));

        LOG.info("call authentication/password update");
        webTestClient.put().uri("/public/authentications/password")
                .bodyValue("newPass")
                .headers(httpHeaders -> httpHeaders.set("authId", "user3"))
                .exchange().expectStatus().isOk()
                .expectBody(String.class)
                .consumeWith(stringEntityExchangeResult -> LOG.info("result: {}", stringEntityExchangeResult.getResponseBody()));

        authenticationRepository.findById("user3").as(StepVerifier::create)
                .expectNextMatches(authentication1 -> {
                    LOG.info("password is newPass?  {}", authentication1.getPassword());
                    return  authentication1.getPassword().equals("newPass");
                })
                .expectComplete().verify();
    }

    @Test
    public void updateRole() {
        Authentication authentication = new Authentication("user3", "yakpass", UUID.randomUUID(), UUID.randomUUID(),
                UUID.randomUUID(), true, LocalDateTime.now(), true);
        authenticationRepository.save(authentication).subscribe(authentication1 -> LOG.info("subscribe to save"));

        UUID uuid = UUID.randomUUID();

        LOG.info("call authentication roleid update");
        webTestClient.put().uri("/authentications/roleid")
                .bodyValue(uuid.toString())
                .headers(httpHeaders -> httpHeaders.set("authId", "user3"))
                .exchange().expectStatus().isOk()
                .expectBody(String.class)
                .consumeWith(stringEntityExchangeResult -> LOG.info("result: {}", stringEntityExchangeResult.getResponseBody()));

        authenticationRepository.findById("user3").as(StepVerifier::create)
                .expectNextMatches(authentication1 -> {
                    LOG.info("roleId is {},?  {}", uuid, authentication1.getRoleId());
                    return  authentication1.getRoleId().equals(uuid);
                })
                .expectComplete().verify();
    }
}