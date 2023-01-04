package me.sonam.authentication;

import me.sonam.authentication.repo.AuthenticationRepository;
import me.sonam.authentication.repo.entity.Authentication;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.r2dbc.DataR2dbcTest;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * This is for testing the {@link AuthenticationRepository} interface
 */
@ExtendWith(SpringExtension.class)
@DataR2dbcTest
public class AuthenticationRepositoryTests {
    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationRepositoryTests.class);

    @Autowired
    private DatabaseClient databaseClient;

    @Autowired
    private AuthenticationRepository authenticationRepository;

    @AfterEach
    public void deleteAll() {
        authenticationRepository.deleteAll().subscribe();
    }

    @Test
    public void saveAuthenticate() {
        Authentication authentication = new Authentication("Yakman", "yakpass", UUID.randomUUID(),
                UUID.randomUUID(), true, LocalDateTime.now(), true);
        Mono<Authentication> authenticationMono = authenticationRepository.save(authentication);

        authenticationMono.as(StepVerifier::create)
            .assertNext(actual -> {
                assertThat(actual.getAuthenticationId()).isEqualTo("Yakman");
                assertThat(actual.getPassword()).isEqualTo("yakpass");
                LOG.info("save and checked mono from saved instance");
            })
            .verifyComplete();

        LOG.info("assert findByAuthenticationId and password works");
        authenticationMono = authenticationRepository.findByAuthenticationIdAndPassword("Yakman", "yakpass");

        authenticationMono.as(StepVerifier::create)
                .assertNext(actual -> {
                    assertThat(actual.getAuthenticationId()).isEqualTo("Yakman");
                    assertThat(actual.getPassword()).isEqualTo("yakpass");
                    LOG.info("asserted findByAuthenticationIdAndPassword api");
                })
                .verifyComplete();
    }

    @Test
    public void updatePassword() {
        LOG.info("save authentication object");
        Authentication authentication = new Authentication("Yakman", "yakpass", UUID.randomUUID(),
                UUID.randomUUID(), true, LocalDateTime.now(), true);
        authenticationRepository.save(authentication).subscribe();

        LOG.info("update password");
        authenticationRepository.updatePassword("newpass", "Yakman").subscribe();

        authenticationRepository.findById("Yakman").as(StepVerifier::create)
                .expectNextMatches(authentication1 -> {
                    LOG.info("assert the newpass password: {}", authentication1.getPassword());
                    return authentication1.getPassword().equals("newpass");
                }
                )
                .expectComplete().verify();
    }

}
