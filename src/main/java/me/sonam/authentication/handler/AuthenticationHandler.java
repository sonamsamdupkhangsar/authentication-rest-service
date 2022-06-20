package me.sonam.authentication.handler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

@Service
public class AuthenticationHandler {
    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationHandler.class);

    @Autowired
    private AuthenticationService authenticationService;

    public Mono<ServerResponse> authenticate(ServerRequest serverRequest) {
        LOG.info("authenticate user");

        return authenticationService.authenticate(serverRequest.bodyToMono(AuthTransfer.class))
                .flatMap(s -> ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).bodyValue(s))
                .onErrorResume(throwable ->
                        ServerResponse.badRequest().contentType(MediaType.APPLICATION_JSON)
                                .bodyValue(throwable.getMessage()));

    }

    public Mono<ServerResponse> createAuthentication(ServerRequest serverRequest) {
        LOG.info("create authentication");

        return authenticationService.createAuthentication(serverRequest.bodyToMono(AuthTransfer.class))
                .flatMap(s -> ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).bodyValue(s))
                .onErrorResume(throwable ->
                        ServerResponse.badRequest().contentType(MediaType.APPLICATION_JSON)
                                .bodyValue(throwable.getMessage()));
    }
}
