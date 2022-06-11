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
        webClient = WebClient.builder().build();
    }

    @Override
    public Mono<String> authenticate(Mono<AuthTransfer> authTransferMono) {
        return authTransferMono
                .filter(user -> {
                    if (!user.getApiKey().equals(apiKey)) {
                        LOG.info("apiKey does not match");
                        return false;
                    }
                    else {
                        return true;
                    }
                })
                .flatMap(user ->
                authenticationRepository.findByAuthenticationIdAndPassword(user.getAuthenticationId(), user.getPassword()))
                .flatMap(authentication -> {
                    LOG.info("does credential exist? {} ", (authentication!=null) ? true : false);

                    WebClient.ResponseSpec responseSpec = webClient.get().uri(
                            jwtRestService.replace("{username}", authentication.getAuthenticationId())
                                    .replace("{audience}", audience)
                                    .replace("{expireField}", expireField)
                                    .replace("{expireIn}", expireIn)).retrieve();
                    return responseSpec.bodyToMono(String.class).map(jwtToken -> {
                        LOG.info("got jwt token: {}", jwtToken);
                        return jwtToken;
                    });
                });

    }

    @Override
    public Mono<String> createAuthentication(Mono<AuthTransfer> authTransferMono) {
        return authTransferMono
                .filter(authTransfer -> {
                    if (!authTransfer.getApiKey().equals(apiKey)) {
                        LOG.info("apiKey does not match");
                        return false;
                    }
                    else {
                        return true;
                    }
                })
                .switchIfEmpty(Mono.error(new RuntimeException("apikey check fail")))
                .flatMap(authTransfer -> authenticationRepository.findById(authTransfer.getAuthenticationId()).switchIfEmpty(Mono.just(new Authentication())).zipWith(Mono.just(authTransfer)))
                .filter(objects -> {
                    LOG.info("objects.t1 {}, t2: {}", objects.getT1(), objects.getT2());
                    LOG.info("objects.t1.id should be null to indicate no entity was found with this authenticationId");
                    return objects.getT1().getId() == null;
                })
                .switchIfEmpty(Mono.error(new RuntimeException("authenticationId already exists")))
                .flatMap(objects -> {
                    Authentication authentication = new Authentication(
                            objects.getT2().getAuthenticationId(), objects.getT2().getPassword(), null, null,
                            null, true, LocalDateTime.now(), true);
                    return authenticationRepository.save(authentication);
                }).map(authentication -> "create Authentication success for authId: " + authentication.getAuthenticationId())
                .onErrorResume(throwable -> Mono.just("Authentication creation fail, error: " + throwable.getMessage()));
    }

}
