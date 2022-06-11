package me.sonam.authentication.handler;

import reactor.core.publisher.Mono;

public interface AuthenticationService {
    /**
     * this service will authenticate username/password with apikey
     * @param authTransferMono contains the usernam,password
     * @return
     */
    Mono<String> authenticate(Mono<AuthTransfer> authTransferMono);
    Mono<String> createAuthentication(Mono<AuthTransfer> authTransferMono);
}
