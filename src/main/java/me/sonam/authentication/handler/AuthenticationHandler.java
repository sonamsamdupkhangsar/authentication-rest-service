package me.sonam.authentication.handler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.data.util.Pair;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

@Service
public class AuthenticationHandler {
    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationHandler.class);

    private final AuthenticationService authenticationService;
    public AuthenticationHandler(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    public Mono<ServerResponse> authenticate(ServerRequest serverRequest) {
        LOG.info("authenticate user");

        return authenticationService.authenticate(serverRequest.bodyToMono(AuthenticationPassword.class))
                .flatMap(s -> {
                    LOG.info("s contains: {}", s);
                    return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(s);
                })
                .onErrorResume(throwable -> {
                    LOG.error("authenticate failed, message: {}", throwable.getMessage());
                    return ServerResponse.badRequest().contentType(MediaType.APPLICATION_JSON)
                            .bodyValue(Map.of("error", throwable.getMessage()));
                });
    }

    public Mono<ServerResponse> verifyAuthenticationId(ServerRequest serverRequest) {
        LOG.info("verify authenticationId for user");

        return serverRequest.bodyToMono(new ParameterizedTypeReference<Map<String, String>>() {})
                .flatMap(map -> {
                    final String authenticationId = map.get("authenticationId");
                    return authenticationService.checkUsernameActiveAndPasswordSet(authenticationId);
                })
                .flatMap(s -> {
                    LOG.info("check username active and password result contains: {}", s);
                    return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of("message", s));
                })
                .onErrorResume(throwable -> {
                    LOG.error("checkUsernameActiveAndPasswordSet failed, message: {}", throwable.getMessage());
                    return ServerResponse.badRequest().contentType(MediaType.APPLICATION_JSON)
                            .bodyValue(Map.of("error", throwable.getMessage()));
                });
    }

    public Mono<ServerResponse> createAuthentication(ServerRequest serverRequest) {
        LOG.info("create authentication");

        return authenticationService.createAuthentication(serverRequest.bodyToMono(AuthTransfer.class))
                .flatMap(s -> ServerResponse.created(URI.create("/authentications"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(Map.of("message", "Authentication created successfully for authenticationId: "+s)))
                .onErrorResume(throwable -> {
                    LOG.error("create authentication failed: {}", throwable.getMessage());
                    return ServerResponse.badRequest().contentType(MediaType.APPLICATION_JSON)
                            .bodyValue(Map.of("error", throwable.getMessage()));
                });
    }

    public Mono<ServerResponse> activateAuthentication(ServerRequest serverRequest) {
        LOG.info("create authentication");
        String authenticationId = serverRequest.pathVariable("authenticationId");

        return authenticationService.activateAuthentication(authenticationId)
                .flatMap(s -> ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of("message", s)))
                .onErrorResume(throwable -> ServerResponse.badRequest().contentType(MediaType.APPLICATION_JSON)
                                .bodyValue(Map.of("error", throwable.getMessage())));
    }

    public Mono<ServerResponse> updatePasswordForLoggedInUser(ServerRequest serverRequest) {
        LOG.info("update password for logged-in user");

        return serverRequest.principal().flatMap(principal ->
            serverRequest.bodyToMono(Map.class).flatMap(map -> {
                final String password = map.get("password").toString();
                return updatePassword(principal.getName(), password);
            }));

    }

    public Mono<ServerResponse> updatePasswordNoAuth(ServerRequest serverRequest) {
        LOG.info("change password when user is not logged-in");

        return serverRequest.bodyToMono(Map.class).flatMap(map -> {
            final String authenticationId = map.get("authenticationId").toString();
            final String password = map.get("password").toString();
            return updatePassword(authenticationId, password);
        });
    }

    private Mono<ServerResponse> updatePassword(String authenticationId, String password) {
        LOG.info("calling service to update password");
        return authenticationService.updatePassword(authenticationId, password)
                .flatMap(s -> {
                    LOG.info("returning serverReponse: {}", s);
                    return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
                            .bodyValue(Map.of("message", "password updated"));
                })
                .onErrorResume(throwable -> {
                    LOG.error("password change failed: {}", throwable.getMessage());
                    return ServerResponse.badRequest().contentType(MediaType.APPLICATION_JSON)
                            .bodyValue(Map.of("error", throwable.getMessage()));
                });
    }

    public Mono<ServerResponse> delete(ServerRequest serverRequest) {
        LOG.info("delete authentication");

        return
            authenticationService.delete()
                    .flatMap(s ->  ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
                            .bodyValue(Map.of("message", s)))
                    .onErrorResume(throwable -> {
                        LOG.error("delete authentication failed: {}", throwable.getMessage());
                        return ServerResponse.badRequest().contentType(MediaType.APPLICATION_JSON)
                                .bodyValue(Map.of("error", throwable.getMessage()));
                    });
    }

    public Mono<ServerResponse> deleteByAuthenticationId(ServerRequest serverRequest) {
        LOG.info("delete authentication by authenticationId");
        LOG.trace("this method is called by user-rest-service during user sign-up to delete any orphan authentication with authenticationId");

        String authenticationId = serverRequest.pathVariable("authenticationId");

        return
                authenticationService.deleteByAuthenticationId(authenticationId)
                        .flatMap(s ->  ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
                                .bodyValue(Map.of("message", s)))
                        .onErrorResume(throwable -> {
                            LOG.error("delete authentication by authenticationId failed: {}", throwable.getMessage());
                            return ServerResponse.badRequest().contentType(MediaType.APPLICATION_JSON)
                                    .bodyValue(Map.of("error", throwable.getMessage()));
                        });

    }
}
