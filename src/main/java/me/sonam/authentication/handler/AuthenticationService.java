package me.sonam.authentication.handler;

import reactor.core.publisher.Mono;

public interface AuthenticationService {
    /**
     * this service will authenticate username/password with apikey
     * @param userMono contains the username and password
     * @return
     */
    Mono<String> authenticate(Mono<User> userMono);
}
