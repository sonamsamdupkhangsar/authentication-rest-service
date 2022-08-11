package me.sonam.authentication.repo;


import me.sonam.authentication.repo.entity.Authentication;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface AuthenticationRepository extends ReactiveCrudRepository<Authentication, String> {
    Mono<Boolean> existsByAuthenticationId(String authenticationId);
    Mono<Boolean> existsByAuthenticationIdAndActiveTrue(String authenticationId);
    Mono<Authentication> findByAuthenticationIdAndPassword(String authenticationId, String password);
    @Query("update authentication a set a.password= :password where a.authentication_Id= :authenticationId")
    Mono<Integer> updatePassword(@Param("password") String password, @Param("authenticationId") String authenticationId);
    @Query("update authentication a set a.role_id= :roleId where a.authentication_Id= :authenticationId")
    Mono<Integer> updateRoleId(@Param("roleId") UUID roleId, @Param("authenticationId") String authenticationId);

    @Query("update authentication a set a.active=true where a.authentication_Id= :authenticationId")
    Mono<Integer> updateAuthenticationActiveTrue(@Param("authenticationId") String authenticationId);

}
