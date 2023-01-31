package me.sonam.authentication.handler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.util.Pair;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
public class AuthenticationHandler {
    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationHandler.class);

    @Autowired
    private AuthenticationService authenticationService;

    public Mono<ServerResponse> authenticate(ServerRequest serverRequest) {
        LOG.info("authenticate user");

        return authenticationService.authenticate(serverRequest.bodyToMono(AuthenticationPassword.class))
                .flatMap(s -> ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(getMap(Pair.of("message", "Authentication successful"))))
                .onErrorResume(throwable -> {
                    LOG.error("authenticate failed", throwable);
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
                    LOG.error("create authentication failed", throwable);
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

    public Mono<ServerResponse> updatePassword(ServerRequest serverRequest) {
        LOG.info("create authentication");
        String authenticationId = SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString();

        return authenticationService.updatePassword(serverRequest.bodyToMono(String.class), authenticationId)
                .flatMap(s -> ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).bodyValue(getMap(Pair.of("message", s))))
                .onErrorResume(throwable -> {
                    LOG.error("update password failed", throwable);
                    return ServerResponse.badRequest().contentType(MediaType.APPLICATION_JSON)
                            .bodyValue(getMap(Pair.of("error", throwable.getMessage())));
                });
    }

    public Mono<ServerResponse> delete(ServerRequest serverRequest) {
        LOG.info("delete user");
        LOG.info("auth: {}", SecurityContextHolder.getContext().getAuthentication());
        String authenticationId = SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString();

        return authenticationService.delete(authenticationId)
                .flatMap(s ->  ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).bodyValue(getMap(Pair.of("message", s))))
                .onErrorResume(throwable -> {
                    LOG.error("delete authentication failed", throwable);
                    return ServerResponse.badRequest().contentType(MediaType.APPLICATION_JSON)
                            .bodyValue(getMap(Pair.of("error", throwable.getMessage())));
                });
    }

    private Map<String, String> getMap(Pair<String, String>... pairs){

        Map<String, String> map = new HashMap<>();

        for(Pair<String, String> pair: pairs) {
            map.put(pair.getFirst(), pair.getSecond());
        }
        return map;

    }
}
