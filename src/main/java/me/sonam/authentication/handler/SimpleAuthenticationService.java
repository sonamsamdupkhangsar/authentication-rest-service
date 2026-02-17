package me.sonam.authentication.handler;

import jakarta.annotation.PostConstruct;
import me.sonam.authentication.carrier.ClientOrganizationUserWithRole;
import me.sonam.authentication.repo.AuthenticationRepository;
import me.sonam.authentication.repo.entity.Authentication;
import me.sonam.authentication.webclient.RoleWebClient;
import me.sonam.security.headerfilter.ReactiveRequestContextHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;


public class SimpleAuthenticationService implements AuthenticationService {
    private static final Logger LOG = LoggerFactory.getLogger(SimpleAuthenticationService.class);

    /**
     * This will validate username and password matches against a stored table
     * and call jwt-rest-service to generate JWT token to issue for the caller.
     * This will also validate the API key matches the stored entry.
     * @param userMono contains the User object with username/password
     * @return
     */

    @Value("${role-rest-service.root}${role-rest-service.user-role}")
    private String roleEp;

    @Value("${role-rest-service.client-organization-user-role}")
    private String clientOrganizationUserRoleEp;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationRepository authenticationRepository;

    @Autowired
    private ReactiveRequestContextHolder reactiveRequestContextHolder;

    private WebClient.Builder webClientBuilder;

    @Autowired
    private RoleWebClient roleWebClient;

    public SimpleAuthenticationService(WebClient.Builder webClientBuilder) {
        this.webClientBuilder = webClientBuilder;
    }

    @PostConstruct
    public void setWebClient() {
        webClientBuilder.filter(reactiveRequestContextHolder.headerFilter());
    }

    @Override
    public Mono<Map<String, String>> authenticate(Mono<AuthenticationPassword> authenticationPasswordMono) {
        /**
         *  .map(authentication -> !authentication.getActive())
         *                 .switchIfEmpty(Mono.error(new AuthenticationException("Authentication not active, activate your acccount first")))
         */
        return authenticationPasswordMono.flatMap(authenticationPassword ->
                authenticationRepository.existsByAuthenticationIdIgnoreCase(authenticationPassword.getAuthenticationId())
                        .filter(aBoolean -> aBoolean)
                        .switchIfEmpty(Mono.error(new AuthenticationException("authentication does not exist with authId")))
                        .flatMap(aBoolean -> authenticationRepository.existsByAuthenticationIdIgnoreCaseAndActiveTrue(authenticationPassword.getAuthenticationId()))
                        .doOnNext(aBoolean -> LOG.info("aboolean is {}", aBoolean))
                        .filter(aBoolean -> aBoolean)
                        .switchIfEmpty(Mono.error(new AuthenticationException("Authentication not active, activate your acccount first")))
                        .flatMap(aBoolean -> authenticationRepository.findByAuthenticationIdIgnoreCase(authenticationPassword.getAuthenticationId()))
                        .flatMap(authentication -> {
                            if (authentication.getPassword() == null) {
                                LOG.error("password is null, user needs to set their password.");
                                return Mono.error(new AuthenticationException("User needs to set their password."));
                            }

                            if (passwordEncoder.matches(authenticationPassword.getPassword(), authentication.getPassword())) {
                                return Mono.just(authentication);
                            }
                            //return Mono.error(new AuthenticationException("no authentication found with username and password"));
                            return Mono.error(new AuthenticationException("Login failed"));
                        })
                        //.switchIfEmpty(Mono.error(new AuthenticationException("no authentication found with username and password")))
                        // check if user is in organiation
                        // step: check if there is a record with user with clientId and check if that organizatino has this user in it
                        .flatMap(authentication ->
                                {
                                    if (authenticationPassword.getOrganizationId() == null) {
                                        LOG.info("organization id is missing to get a role, usually it is because of authzmanager login");
                                        return Mono.just("").zipWith(Mono.just(authentication));
                                    }
                                    else {

                                        LOG.info("get organization roles when organization-id is set");
                                        LOG.info("clientId: {}", authenticationPassword.getClientId());
                                        UUID clientId = UUID.fromString(authenticationPassword.getClientId());

                                        return roleWebClient.getRoleNameForClientOrganizationUser(clientId,
                                                        authenticationPassword.getOrganizationId(), authentication.getUserId())
                                                .zipWith(Mono.just(authentication));
                                    }
                                }
                        ).flatMap(objects -> {
                            LOG.info("roles: {}", objects.getT1());
                            return Mono.just(Map.of("roles", List.of(objects.getT1()).toString()
                            , "userId", objects.getT2().getUserId().toString()
                            , "message", "Authentication successful"));
                        }));
    }


    /**
     * this method is called by the authorization server to validate the username alone.
     * It will verify the username exists, is active and a password is set.
     * @param authenticationId the username
     * @return a string indicating that username exists, is activated and a password is set.
     */
    @Override
    public Mono<String> checkUsernameActiveAndPasswordSet(String authenticationId) {

        return authenticationRepository.existsByAuthenticationIdIgnoreCase(authenticationId)
                        .filter(aBoolean -> aBoolean)
                        .switchIfEmpty(Mono.error(new AuthenticationException("authentication does not exist with authId")))
                        .flatMap(aBoolean -> authenticationRepository.existsByAuthenticationIdIgnoreCaseAndActiveTrue(authenticationId))
                        .doOnNext(aBoolean -> LOG.info("aboolean is {}", aBoolean))
                        .filter(aBoolean -> aBoolean)
                        .switchIfEmpty(Mono.error(new AuthenticationException("Authentication not active, activate your account first")))
                        .flatMap(aBoolean -> authenticationRepository.findByAuthenticationIdIgnoreCase(authenticationId))
                        .flatMap(authentication -> {
                            if (authentication.getPassword() == null) {
                                LOG.error("password is null, user needs to set their password.");
                                return Mono.error(new AuthenticationException("User needs to set their password."));
                            }

                            return Mono.just("authenticationId exists, is activated and a password is set");
                        });
    }

    @Override
    public Mono<String> createAuthentication(Mono<AuthTransfer> authTransferMono) {
        LOG.info("building authentication");
        return authTransferMono
                .flatMap(authTransfer -> {
                    LOG.info("authTransfer.authenticationId: {}", authTransfer);
                        return authenticationRepository.existsByAuthenticationIdIgnoreCaseAndActiveTrue(authTransfer.getAuthenticationId())
                         .filter(aBoolean -> !aBoolean)
                        .doOnNext(aBoolean -> LOG.info("aBoolean is {}", aBoolean))
                         .switchIfEmpty(Mono.error(new AuthenticationException("Authentication is already active with authenticationId")))
                         .flatMap(aBoolean -> {
                             LOG.info("delete by id where active is false");
                             return authenticationRepository.deleteByAuthenticationIdIgnoreCaseAndActiveFalse(authTransfer.getAuthenticationId());
                         })
                         .flatMap(integer -> {
                             LOG.info("create authentication: {}, password: {}", authTransfer.getAuthenticationId(), authTransfer.getPassword());

                             String encodedPassword = null;

                             if (authTransfer.getPassword() == null) {
                                 LOG.info("create authentication password is null, must be initiated by a admin signup of user authentication");
                             }
                             else {
                                 // if user is signing up by themselves then only take the password, set active false
                                 encodedPassword = passwordEncoder.encode(authTransfer.getPassword());
                             }

                             return Mono.just(new Authentication(
                                     authTransfer.getAuthenticationId(), encodedPassword, authTransfer.getUserId(),
                                     null, authTransfer.isActive(), LocalDateTime.now(), true));

                         })
                         .flatMap(authentication -> authenticationRepository.save(authentication))
                         .flatMap(authentication1 -> {
                             LOG.info("authentication created successfully for authId: {}", authentication1);
                            return Mono.just(authentication1.getAuthenticationId());
                         });
                });

    }

    @Override
    public Mono<String> activateAuthentication(String authenticationId) {
        LOG.info("activate authentication");

        return authenticationRepository.updateAuthenticationActiveTrue(authenticationId)
                .thenReturn("activated: "+authenticationId);
    }

    /**
     * this will be called by a non-logged in user, whcih will have a secret
     * @param authenticationId
     * @return
     */
    @Override
    public Mono<String> updatePassword(String authenticationId, String password) {
        LOG.info("update password for auth: '{}', password: '{}'", authenticationId, password);
        final String encodedPassword = passwordEncoder.encode(password);

        authenticationRepository.updatePassword(authenticationId, encodedPassword)
                .subscribe(integer -> LOG.info("row updated: {}", integer));
        return Mono.just("password updated");
    }

    @Override
    public Mono<String> delete() {
        LOG.info("delete authentication");
        return
                ReactiveSecurityContextHolder.getContext().flatMap(securityContext -> {
                    org.springframework.security.core.Authentication authentication = securityContext.getAuthentication();

                    Jwt jwt = (Jwt) authentication.getPrincipal();
                    String userIdString = jwt.getClaim("userId");
                    LOG.info("delete authentication data for userId: {}", userIdString);

                    UUID userId = UUID.fromString(userIdString);

                    return authenticationRepository.deleteByUserId(userId)
                            .doOnNext(integer -> LOG.info("deleted with rows change: {}", integer))
                            .thenReturn("deleted Authentication with userId: " + userId);
                });
    }

    @Override
    public Mono<String> deleteByAuthenticationId(String authenticationId) {
        LOG.info("delete authentication by authenticationId: '{}'", authenticationId);

        return authenticationRepository.deleteByAuthenticationIdIgnoreCase(authenticationId)
                .doOnNext(integer -> LOG.info("deleted with rows change: {}", integer))
                .thenReturn("deleted Authentication with authenticationId: " + authenticationId+" completed");

    }

    private Mono<Map<String, ?>> getUserRoleForClientId(String userId, String clientId) {
            LOG.info("role endpoint: {}", roleEp);
            WebClient.ResponseSpec responseSpec = webClientBuilder.build().get().uri(
                            roleEp.replace("{clientId}", clientId)
                                    .replace("{userId}", userId))
                    .retrieve();
            return responseSpec.bodyToMono(Map.class).map(map -> {
                LOG.info("got role: {}", map);

                if (map.get("roleName") != null) {
                    LOG.info("got role: {}", map.get("roleName"));
                    return Map.of("roleName", map.get("roleName"));
                }
                else {
                    return Map.of("roleName", "");
                }
            }).onErrorResume(throwable -> {
                LOG.error("role  rest call failed: {}", throwable.getMessage());
                if (throwable instanceof WebClientResponseException) {
                    WebClientResponseException webClientResponseException = (WebClientResponseException) throwable;
                    LOG.error("error body contains: {}", webClientResponseException.getResponseBodyAsString());
                }

                return Mono.just(Map.of("roleName", ""));
            });
        }

    private Mono<List<String>> getClientOrganizationUserRoles(UUID userId, UUID organizationId, String clientId) {
        final String endpoint = clientOrganizationUserRoleEp.replace("{clientId}", clientId)
                .replace("{organizationId}", organizationId.toString())
                .replace("{userId}", userId.toString());

        LOG.info("get client organization user role endpoint: {}", endpoint);

        WebClient.ResponseSpec responseSpec = webClientBuilder.build().get().uri(endpoint).retrieve();

        return responseSpec.bodyToMono(new ParameterizedTypeReference<List<ClientOrganizationUserWithRole>>() {}).flatMap(list -> {
                   List<String> roles = list.stream().map(clientOrganizationUserWithRole ->  clientOrganizationUserWithRole.getUser().getRole().getName())
                           .toList();
                   LOG.info("roles: {}", roles);
                   return Mono.just(roles);
                })
                .onErrorResume(throwable -> {
                    LOG.error("client-organization-user-roles  rest call failed: {}", throwable.getMessage());
                    if (throwable instanceof WebClientResponseException webClientResponseException) {
                        LOG.error("error body contains: {}", webClientResponseException.getResponseBodyAsString());
                    }

                    return Mono.just(List.of(""));
                });
    }

    private Mono<List<String>> getUserRolesForClientId(String userId, String clientId) {
        LOG.info("role endpoint: {}", roleEp);
        WebClient.ResponseSpec responseSpec = webClientBuilder.build().get().uri(
                        roleEp.replace("{clientId}", clientId)
                                .replace("{userId}", userId))
                .retrieve();

        return responseSpec.bodyToFlux(Map.class).flatMap(map -> {
            if (map.get("roleName") != null) {
                LOG.info("got role: {}", map.get("roleName"));
                //return Mono.just(Map.of("roleName", map.get("roleName")));
                return Mono.just(map.get("roleName").toString());
            }
            else {
                //return Mono.just(Map.of("roleName", ""));
                return Mono.just("");
            }
        }).collectList()
                .onErrorResume(throwable -> {
                    LOG.error("role  rest call failed: {}", throwable.getMessage());
                    if (throwable instanceof WebClientResponseException) {
                        WebClientResponseException webClientResponseException = (WebClientResponseException) throwable;
                        LOG.error("error body contains: {}", webClientResponseException.getResponseBodyAsString());
                    }

                    return Mono.just(List.of(""));
                });
      /*
        return responseSpec.bodyToFlux(Map.class).map(map -> {
            LOG.info("got role: {}", map);

            if (map.get("roleName") != null) {
                LOG.info("got role: {}", map.get("roleName"));
                return Map.of("roleName", map.get("roleName"));
            }
            else {
                return Map.of("roleName", "");
            }
        }).onErrorResume(throwable -> {
            LOG.error("role  rest call failed: {}", throwable.getMessage());
            if (throwable instanceof WebClientResponseException) {
                WebClientResponseException webClientResponseException = (WebClientResponseException) throwable;
                LOG.error("error body contains: {}", webClientResponseException.getResponseBodyAsString());
            }

            return Mono.just(Map.of("roleName", ""));
        });*/
    }
}
