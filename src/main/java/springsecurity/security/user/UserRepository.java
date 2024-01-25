package springsecurity.security.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUuid(String uuid);
    Optional<User> findByEmail(String email);
    boolean existsByUuid(String uuid);
    boolean existsByEmail(String email);
    boolean deleteByUuid(String uuid);
    boolean deleteByEmail(String email);
}