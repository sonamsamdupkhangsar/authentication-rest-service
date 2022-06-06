package me.sonam.authentication.repo;


import me.sonam.authentication.repo.entity.Authentication;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

public interface AuthenticationRepository extends ReactiveCrudRepository<Authentication, String> {
    Mono<Authentication> findByAuthenticationIdAndPassword(String authenticationId, String password);
}
