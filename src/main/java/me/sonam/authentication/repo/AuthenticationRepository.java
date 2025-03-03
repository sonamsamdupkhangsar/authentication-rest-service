package me.sonam.authentication.repo;


import me.sonam.authentication.repo.entity.Authentication;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface AuthenticationRepository extends ReactiveCrudRepository<Authentication, String> {
    Mono<Integer> deleteByUserId(UUID userId);
    Mono<Authentication> findByUserId(UUID userId);
    Mono<Integer> deleteByAuthenticationIdAndActiveFalse(String authenticationId);
    Mono<Boolean> existsByIdAndActiveTrue(String var1);
    Mono<Boolean> existsByAuthenticationIdAndActiveTrue(String authenticationId);
    Mono<Authentication> findByAuthenticationIdAndPassword(String authenticationId, String password);
    @Query("update authentication set password= :password where authentication_Id= :authenticationId")
    Mono<Integer> updatePassword(@Param("authenticationId") String authenticationId, @Param("password") String password);
    @Query("update authentication a set a.role_id= :roleId where a.authentication_Id= :authenticationId")
    Mono<Integer> updateRoleId(@Param("roleId") UUID roleId, @Param("authenticationId") String authenticationId);

    @Query("update authentication set active=true where authentication_Id= :authenticationId")
    Mono<Integer> updateAuthenticationActiveTrue(@Param("authenticationId") String authenticationId);

}
