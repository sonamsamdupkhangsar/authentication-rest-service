package me.sonam.authentication.handler;

import me.sonam.security.headerfilter.ReactiveRequestContextHolder;
import me.sonam.security.util.HmacClient;
import me.sonam.authentication.repo.AuthenticationRepository;
import me.sonam.authentication.repo.entity.Authentication;
import me.sonam.security.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import javax.annotation.PostConstruct;
import java.time.LocalDateTime;
import java.util.*;

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

    @Value("${application-rest-service.root}${application-rest-service.client-role}")
    private String applicationClientRoleService;

    @Value("${jwt-rest-service-accesstoken}")
    private String jwtRestService;

    @Value("${audience}")
    private String audience;

    @Value("${expireField}")
    private String expireField;

    @Value("${expireIn}")
    private String expireIn;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private WebClient webClient;

    @Autowired
    private AuthenticationRepository authenticationRepository;

    @Autowired
    private HmacClient hmacClient;

    @Autowired
    private ReactiveRequestContextHolder reactiveRequestContextHolder;

    @PostConstruct
    public void setWebClient() {
        LOG.info("built webclient");
        webClient = WebClient.builder().filter(reactiveRequestContextHolder.headerFilter()).build();

        LOG.info("clientId: {}, md5algorithm: {}, secretkey: {}", hmacClient.getClientId(),
                hmacClient.getMd5Algoirthm(), hmacClient.getSecretKey());
    }

    @Override
    public Mono<String> authenticate(Mono<AuthenticationPassword> authenticationPasswordMono) {
        /**
         *  .map(authentication -> !authentication.getActive())
         *                 .switchIfEmpty(Mono.error(new AuthenticationException("Authentication not active, activate your acccount first")))
         */
        return authenticationPasswordMono.flatMap(authenticationPassword ->
                authenticationRepository.existsById(authenticationPassword.getAuthenticationId())
                .filter(aBoolean -> aBoolean)
                .switchIfEmpty(Mono.error(new AuthenticationException("authentication does not exist with authId")))
                .flatMap(aBoolean -> authenticationRepository.existsByAuthenticationIdAndActiveTrue(authenticationPassword.getAuthenticationId()))
                .doOnNext(aBoolean -> LOG.info("aboolean is {}", aBoolean))
                .filter(aBoolean -> aBoolean)
                .switchIfEmpty(Mono.error(new AuthenticationException("Authentication not active, activate your acccount first")))
                 .flatMap(aBoolean -> authenticationRepository.findById(authenticationPassword.getAuthenticationId()))

                 .flatMap( authentication -> {
                     if (passwordEncoder.matches(authenticationPassword.getPassword(), authentication.getPassword())) {
                         return Mono.just(authentication);
                     }
                     else {
                         return Mono.error(
                                 new AuthenticationException("no authentication found with username and password"));
                     }
                 }).flatMap(authentication -> {
                     // this application endpoint does not require jwt or secuity for 'get'
                    LOG.info("application client role endpoint: {}", applicationClientRoleService);
                    WebClient.ResponseSpec responseSpec = webClient.get().uri(
                            applicationClientRoleService.replace("{clientId}", authenticationPassword.getClientId())
                                    .replace("{userId}", authentication.getUserId().toString()))
                            .retrieve();
                    return responseSpec.bodyToMono(Map.class).map(clientUserRole -> {
                        LOG.info("got role: {}", clientUserRole);
                        return clientUserRole;
                    }).onErrorResume(throwable -> {
                        LOG.error("application rest call failed: {}", throwable.getMessage());
                        if (throwable instanceof WebClientResponseException) {
                            WebClientResponseException webClientResponseException = (WebClientResponseException) throwable;
                            LOG.error("error body contains: {}", webClientResponseException.getResponseBodyAsString());
                        }
                        Map<String, Object> map = new HashMap<>();
                        map.put("userRole", "");
                        String[] groupNames = {""};
                        map.put("groupNames", groupNames);
                        return Mono.just(map);
                    });
                })
                .flatMap(clientUserRole -> {


                    final StringBuilder userJwtJson = new StringBuilder("{\n");
                    userJwtJson.append("  \"sub\": \"").append(authenticationPassword.getAuthenticationId()).append("\",\n")
                            .append("  \"scope\": \"backend\",\n")
                            .append("  \"clientId\": \"").append(authenticationPassword.getClientId()).append("\",\n")
                            .append("  \"aud\": \"backend\",\n")
                            .append("  \"role\": \"").append(clientUserRole.get("userRole")).append("\",\n")
                            .append("  \"groups\": \"");
                            String[] groupNames = (String[])clientUserRole.get("groupNames");;
                            Arrays.stream(groupNames).forEach(s -> userJwtJson.append(s));
                            userJwtJson.append("\",\n")
                            .append("  \"expiresInSeconds\": 86400\n")
                            .append("}\n");

                    final StringBuilder jsonString = new StringBuilder("{\n");
                    jsonString.append("  \"sub\": \"").append(hmacClient.getClientId()).append("\",\n")
                            .append("  \"scope\": \"").append(hmacClient.getClientId()).append("\",\n")
                            .append("  \"clientId\": \"").append(hmacClient.getClientId()).append("\",\n")
                            .append("  \"aud\": \"service\",\n")
                            .append("  \"role\": \"service\",\n")
                            .append("  \"groups\": \"service\",\n")
                            .append("  \"expiresInSeconds\": 300,\n")
                            .append(" \"userJwt\": ").append(userJwtJson.toString())
                            .append("}\n");


                    LOG.info("jsonString: {}", jsonString);

                    final String hmac = Util.getHmac(hmacClient.getMd5Algoirthm(), jsonString.toString(), hmacClient.getSecretKey());
                    LOG.info("creating hmac for jwt-rest-service: {}", jwtRestService);
                    WebClient.ResponseSpec responseSpec = webClient.post().uri(jwtRestService)
                            .headers(httpHeaders -> httpHeaders.add(HttpHeaders.AUTHORIZATION, hmac))
                            .bodyValue(jsonString)
                            .accept(MediaType.APPLICATION_JSON)
                            .retrieve();
                    return responseSpec.bodyToMono(Map.class).map(map -> {
                        LOG.info("got jwt token: {}", map.get("token"));
                        return map.get("token").toString();
                    }).onErrorResume(throwable -> {
                                LOG.error("account rest call failed: {}", throwable.getMessage());
                                if (throwable instanceof WebClientResponseException) {
                                    WebClientResponseException webClientResponseException = (WebClientResponseException) throwable;
                                    LOG.error("error body contains: {}", webClientResponseException.getResponseBodyAsString());
                                    return Mono.error(new AuthenticationException("jwt rest  api call failed with error: " +
                                            webClientResponseException.getResponseBodyAsString()));
                                }
                                else {
                                    return Mono.error(new AuthenticationException("Application api call failed with error: " +throwable.getMessage()));
                                }
                            });
                }));
    }

    @Override
    public Mono<String> createAuthentication(Mono<AuthTransfer> authTransferMono) {
        LOG.info("Create authentication");
        return authTransferMono
                .flatMap(authTransfer -> authenticationRepository.existsByAuthenticationIdAndActiveTrue(authTransfer.getAuthenticationId())
                         .filter(aBoolean -> !aBoolean)
                         .switchIfEmpty(Mono.error(new AuthenticationException("Authentication is already active with authenticationId")))
                         .flatMap(aBoolean -> {
                             LOG.info("delete by id where active is false");
                             return authenticationRepository.deleteByAuthenticationIdAndActiveFalse(authTransfer.getAuthenticationId());
                         })
                         .flatMap(integer -> {
                             LOG.info("create authentication");
                             return Mono.just(new Authentication(
                                     authTransfer.getAuthenticationId(), passwordEncoder.encode(authTransfer.getPassword()), authTransfer.getUserId(),
                                     null, false, LocalDateTime.now(), true));
                         })
                         .flatMap(authentication -> authenticationRepository.save(authentication))
                         .flatMap(authentication1 -> {
                             LOG.info("authentication created successfully for authId: {}", authentication1);
                            return Mono.just(authentication1.getAuthenticationId());
                         }));
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
    public Mono<String> delete(String authenticationId) {
        LOG.info("delete authentication by authenticationId");

        return authenticationRepository.findById(authenticationId)
                .filter(authentication -> !authentication.getActive())
                .switchIfEmpty(Mono.error(new AuthenticationException("authentication is active, cannot delete")))
                .flatMap(authentication ->   authenticationRepository.deleteByAuthenticationIdAndActiveFalse(authenticationId))
                .flatMap(integer ->
                    {
                    LOG.info("integer: {}", integer);
                    return Mono.just(integer);
                })
                .thenReturn("deleted: " + authenticationId);
    }

}
