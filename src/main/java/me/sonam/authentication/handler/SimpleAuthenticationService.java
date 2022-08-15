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
        /**
         *  .map(authentication -> !authentication.getActive())
         *                 .switchIfEmpty(Mono.error(new AuthenticationException("Authentication not active, activate your acccount first")))
         */
        return authTransferMono.flatMap(authTransfer ->
                authenticationRepository.existsById(authTransfer.getAuthenticationId())
                .filter(aBoolean -> aBoolean)
                .switchIfEmpty(Mono.error(new AuthenticationException("authentication does not exist with authId")))
                .flatMap(aBoolean -> authenticationRepository.existsByAuthenticationIdAndActiveTrue(authTransfer.getAuthenticationId()))
                .doOnNext(aBoolean -> LOG.info("aboolean is {}", aBoolean))
                .filter(aBoolean -> aBoolean)
                .switchIfEmpty(Mono.error(new AuthenticationException("Authentication not active, activate your acccount first")))
                .flatMap(aBoolean -> authenticationRepository.findByAuthenticationIdAndPassword(
                        authTransfer.getAuthenticationId(), authTransfer.getPassword()))
                .switchIfEmpty(Mono.error(
                        new AuthenticationException("no authentication found with username and password")))
                .flatMap(authentication -> {
                    WebClient.ResponseSpec responseSpec = webClient.get().uri(
                            jwtRestService.replace("{username}", authentication.getAuthenticationId())
                                    .replace("{audience}", audience)
                                    .replace("{expireField}", expireField)
                                    .replace("{expireIn}", expireIn))
                            .retrieve();
                    return responseSpec.bodyToMono(String.class).map(jwtToken -> {
                        LOG.info("got jwt token: {}", jwtToken);
                        return jwtToken;
                    });
                }));

    }

    @Override
    public Mono<String> createAuthentication(Mono<AuthTransfer> authTransferMono) {
        LOG.info("Create authentication");
        return authTransferMono
                .flatMap(authTransfer -> {
                   return authenticationRepository.existsByAuthenticationIdAndActiveTrue(authTransfer.getAuthenticationId())
                            .filter(aBoolean -> !aBoolean)
                            .switchIfEmpty(Mono.error(new AuthenticationException("Authentication is already active with authenticationId")))
                            .flatMap(aBoolean -> {
                                LOG.info("delete by id where active is false");
                                return authenticationRepository.deleteByAuthenticationIdAndActiveFalse(authTransfer.getAuthenticationId());
                            })
                            .flatMap(integer -> {
                                LOG.info("create authentication");
                                return Mono.just(new Authentication(
                                        authTransfer.getAuthenticationId(), authTransfer.getPassword(), null, null,
                                        null, false, LocalDateTime.now(), true));
                            })
                            .flatMap(authentication -> authenticationRepository.save(authentication))
                            .flatMap(authentication1 -> {
                                LOG.info("created authentication1: {}", authentication1);
                               return Mono.just("create Authentication success for authId: " + authentication1.getAuthenticationId());
                            });
                });
    }

    @Override
    public Mono<String> activateAuthentication(String authenticationId) {
        LOG.info("activate authentication");

        return authenticationRepository.updateAuthenticationActiveTrue(authenticationId)
                .thenReturn("activated: "+authenticationId);
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
