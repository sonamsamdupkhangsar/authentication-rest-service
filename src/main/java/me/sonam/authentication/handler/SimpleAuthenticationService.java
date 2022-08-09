package me.sonam.authentication.handler;

import me.sonam.authentication.repo.AuthenticationRepository;
import me.sonam.authentication.repo.entity.Authentication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import javax.annotation.PostConstruct;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
public class SimpleAuthenticationService implements AuthenticationService {
    private static final Logger LOG = LoggerFactory.getLogger(SimpleAuthenticationService.class);

    /**
     * This will validate username and password matches against a stored table
     * and call jwt-rest-service to generate JWT token to issue for the caller.
     * This will also validate the API key matches the stored entry.
     * @param userMono contains the User object with username/password
     * @return
     */

    @Value("${jwt-rest-service}")
    private String jwtRestService;

    @Value("${audience}")
    private String audience;

    @Value("${expireField}")
    private String expireField;

    @Value("${expireIn}")
    private String expireIn;

    @Value("${apiKey}")
    private String apiKey;

    private WebClient webClient;

    @Autowired
    private AuthenticationRepository authenticationRepository;

    @PostConstruct
    public void setWebClient() {
        LOG.info("built webclient");
        webClient = WebClient.builder().build();
    }

    @Override
    public Mono<String> authenticate(Mono<AuthTransfer> authTransferMono) {
        return authTransferMono
                .flatMap(authTransfer -> authenticationRepository.findByAuthenticationIdAndPassword(
                        authTransfer.getAuthenticationId(), authTransfer.getPassword()))
                .switchIfEmpty(Mono.error(new AuthenticationException("no authentication found with username or password")))
                .flatMap(authentication ->
                {
                    WebClient.ResponseSpec responseSpec = webClient.get().uri(
                            jwtRestService.replace("{username}",authentication.getAuthenticationId())
                                    .replace("{audience}", audience)
                                    .replace("{expireField}", expireField)
                                    .replace("{expireIn}", expireIn))
                          .retrieve();
                    return responseSpec.bodyToMono(String.class).map(jwtToken -> {
                        LOG.info("got jwt token: {}", jwtToken);
                        return jwtToken;
                    });
                });

    }

    @Override
    public Mono<String> createAuthentication(Mono<AuthTransfer> authTransferMono) {
        return authTransferMono
                .flatMap(authTransfer -> authenticationRepository.existsByAuthenticationId(authTransfer.getAuthenticationId())
                        .doOnNext(aBoolean -> LOG.info("aBoolean is {}", aBoolean))
                        .filter(aBoolean -> !aBoolean)
                        .switchIfEmpty(Mono.error(new AuthenticationException("create Authentication failed, authenticationId is already used")))
                        .flatMap(aBoolean -> {
                            LOG.info("create authentication");
                            return Mono.just(new Authentication(
                                    authTransfer.getAuthenticationId(), authTransfer.getPassword(), null, null,
                                    null, true, LocalDateTime.now(), true));
                        })
                        .flatMap(authentication -> authenticationRepository.save(authentication))
                        .flatMap(authentication1 -> Mono.just("create Authentication success for authId: " + authentication1.getAuthenticationId())));

    }

    @Override
    public Mono<String> updatePassword(Mono<String> passwordMono, String authenticationId) {
        return passwordMono.flatMap(password -> authenticationRepository.updatePassword(password, authenticationId))
                .thenReturn("password updated");
    }

    @Override
    public Mono<String> updateRoleId(Mono<String> uuidStringMono, String authenticationId) {
        return uuidStringMono.flatMap(roleId -> authenticationRepository.updateRoleId(UUID.fromString(roleId), authenticationId))
                .thenReturn("password updated");
    }

}
