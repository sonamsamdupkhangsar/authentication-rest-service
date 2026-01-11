package me.sonam.authentication;

import me.sonam.authentication.repo.AuthenticationRepository;
import me.sonam.authentication.repo.entity.Authentication;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
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
                assertThat(actual.getAuthenticationId()).isEqualTo("yakman");
                assertThat(actual.getPassword()).isEqualTo("yakpass");
                LOG.info("save and checked mono from saved instance");
            })
            .verifyComplete();

        LOG.info("assert findByAuthenticationId and password works");
        authenticationMono = authenticationRepository.findByAuthenticationIdIgnoreCaseAndPassword("Yakman", "yakpass");

        authenticationMono.as(StepVerifier::create)
                .assertNext(actual -> {
                    assertThat(actual.getAuthenticationId()).isEqualTo("yakman");
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
        authenticationRepository.updatePassword("Yakman", "newpass").subscribe();

        authenticationRepository.findByAuthenticationIdIgnoreCase("Yakman").as(StepVerifier::create)
                .expectNextMatches(authentication1 -> {
                    LOG.info("assert the newpass password: {}", authentication1.getPassword());
                    return authentication1.getPassword().equals("newpass");
                }
                )
                .expectComplete().verify();
    }

    @Test
    public void deleteByAuthenticationIdIgnoreCaseAndActiveFalse() {
        LOG.info("test deletion by id and ignore case");
        Authentication authentication = new Authentication("Yakman", "yakpass", UUID.randomUUID(),
                UUID.randomUUID(), true, LocalDateTime.now(), true);
        authenticationRepository.save(authentication).subscribe();

        Authentication authentication2 = new Authentication("Yakman2", "yakpass", UUID.randomUUID(),
                UUID.randomUUID(), true, LocalDateTime.now(), true);
        authenticationRepository.save(authentication2).subscribe();


        StepVerifier.create(authenticationRepository.existsByAuthenticationIdIgnoreCase("YAKMAN")).assertNext(val -> {
                    assertThat(val).isTrue();
                }).verifyComplete();

        StepVerifier.create(authenticationRepository.existsByAuthenticationIdIgnoreCaseAndActiveTrue("yAkMan"))
                .assertNext(aBoolean -> {
                    LOG.info("assert we have a authenticationId with yakman ignore case");
                    assertThat(aBoolean).isTrue();
                }).verifyComplete();

        StepVerifier.create(authenticationRepository.findByAuthenticationIdIgnoreCaseAndPassword("yaKMaN", "yakpass"))
                .assertNext(authentication1 -> {
                    assertThat(authentication1.getActive()).isTrue();
                }).verifyComplete();

        StepVerifier.create(authenticationRepository.findByAuthenticationIdIgnoreCaseAndPassword("yaKMaN", "yakpass"))
                .expectNextCount(1).verifyComplete();

        authenticationRepository.updatePassword("YAKMAN2", "jump").subscribe();

        StepVerifier.create(authenticationRepository.findByAuthenticationIdIgnoreCase("yakman2")).expectNextCount(1).verifyComplete();
        StepVerifier.create(authenticationRepository.findByAuthenticationIdIgnoreCase("yAKman2")).assertNext(authentication1 -> {
            LOG.info("yakman2 password was updated, verify his username");
            assertThat(authentication1.getAuthenticationId().toLowerCase()).isEqualTo("yakman2");
        }).verifyComplete();
    }

    @Test
    public void findByAuthenticationIdIgnoreCase() {
        Authentication authentication = new Authentication("Yakman", "yakpass", UUID.randomUUID(),
                UUID.randomUUID(), false, LocalDateTime.now(), true);
        authenticationRepository.save(authentication).subscribe();

        StepVerifier.create(authenticationRepository.findByAuthenticationIdIgnoreCase("yakman")).expectNextCount(1).verifyComplete();

        StepVerifier.create(authenticationRepository.findByAuthenticationIdIgnoreCase("yAKmAn")).assertNext(authentication1 -> {
            LOG.info("assert found by id ignorecase");
            assertThat(authentication1.getAuthenticationId().toLowerCase()).isEqualTo("yakman");
        }).verifyComplete();

        LOG.info("update password");
        authenticationRepository.deleteByAuthenticationIdIgnoreCaseAndActiveFalse("YaKMAN").subscribe();

        authenticationRepository.findByAuthenticationIdIgnoreCase("YAKMAN").as(StepVerifier::create).expectNextCount(0).verifyComplete();
    }

    @Test
    public void updateAuthenticationActiveTrue() {
        Authentication authentication = new Authentication("Yakman", "yakpass", UUID.randomUUID(),
                UUID.randomUUID(), false, LocalDateTime.now(), true);
        authenticationRepository.save(authentication).subscribe();

        StepVerifier.create(authenticationRepository.findByAuthenticationIdIgnoreCase("YakMan")).expectNextCount(1)
                        .verifyComplete();

        LOG.info("update by username in mix case to update active to true");
        authenticationRepository.updateAuthenticationActiveTrue("yAkMAn").subscribe();

        StepVerifier.create(authenticationRepository.findByAuthenticationIdIgnoreCase("YakMan")).assertNext(authentication1 -> {
            LOG.info("assert active is true");
            assertThat(authentication1.getActive()).isTrue();
        }).verifyComplete();
    }

    @Test
    public void deleteByAuthenticationIdIgnoreCase() {
        LOG.info("test deletion by id and ignore case");
        Authentication authentication = new Authentication("Yakman", "yakpass", UUID.randomUUID(),
                    UUID.randomUUID(), true, LocalDateTime.now(), true);
        authenticationRepository.save(authentication).subscribe();

        Authentication authentication2 = new Authentication("Yakman2", "yakpass", UUID.randomUUID(),
                    UUID.randomUUID(), true, LocalDateTime.now(), true);
        authenticationRepository.save(authentication2).subscribe();

        authenticationRepository.deleteByAuthenticationIdIgnoreCase("YAKMAN").subscribe();

        StepVerifier.create(authenticationRepository.existsByAuthenticationIdIgnoreCase("yakMan")).assertNext(val -> {
            assertThat(val).isFalse();
        }).verifyComplete();
    }
}
