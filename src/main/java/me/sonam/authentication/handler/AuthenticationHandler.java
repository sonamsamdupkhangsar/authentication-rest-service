package me.sonam.authentication.handler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.util.Pair;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
public class AuthenticationHandler {
    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationHandler.class);

    private AuthenticationService authenticationService;
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
                            .bodyValue(getMap(Pair.of("error", throwable.getMessage())));
                });
    }

    public Mono<ServerResponse> createAuthentication(ServerRequest serverRequest) {
        LOG.info("create authentication");

        return authenticationService.createAuthentication(serverRequest.bodyToMono(AuthTransfer.class))
                .flatMap(s -> ServerResponse.created(URI.create("/authentications"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(getMap(Pair.of("message", "Authentication created successfully for authenticationId: "+s))))
                .onErrorResume(throwable -> {
                    LOG.error("create authentication failed: {}", throwable.getMessage());
                    return ServerResponse.badRequest().contentType(MediaType.APPLICATION_JSON)
                            .bodyValue(getMap(Pair.of("error", throwable.getMessage())));
                });
    }

    public Mono<ServerResponse> activateAuthentication(ServerRequest serverRequest) {
        LOG.info("create authentication");
        String authenticationId = serverRequest.pathVariable("authenticationId");

        return authenticationService.activateAuthentication(authenticationId)
                .flatMap(s -> ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).bodyValue(getMap(Pair.of("message", s))))
                .onErrorResume(throwable -> ServerResponse.badRequest().contentType(MediaType.APPLICATION_JSON)
                                .bodyValue(getMap(Pair.of("error", throwable.getMessage()))));
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
                            .bodyValue(getMap(Pair.of("message", "password updated")));
                })
                .onErrorResume(throwable -> {
                    LOG.error("password change failed: {}", throwable.getMessage());
                    return ServerResponse.badRequest().contentType(MediaType.APPLICATION_JSON)
                            .bodyValue(getMap(Pair.of("error", throwable.getMessage())));
                });
    }

    public Mono<ServerResponse> delete(ServerRequest serverRequest) {
        LOG.info("delete authentication");

        return
            authenticationService.delete()
                    .flatMap(s ->  ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
                            .bodyValue(getMap(Pair.of("message", s))))
                    .onErrorResume(throwable -> {
                        LOG.error("delete authentication failed: {}", throwable.getMessage());
                        return ServerResponse.badRequest().contentType(MediaType.APPLICATION_JSON)
                                .bodyValue(getMap(Pair.of("error", throwable.getMessage())));
                    });

    }

    @SafeVarargs
    public static Map<String, String> getMap(Pair<String, String>... pairs){

        Map<String, String> map = new HashMap<>();

        for(Pair<String, String> pair: pairs) {
            map.put(pair.getFirst(), pair.getSecond());
        }
        return map;

    }
}
