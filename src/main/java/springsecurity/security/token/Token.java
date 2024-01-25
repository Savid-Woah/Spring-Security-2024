package springsecurity.security.token;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import springsecurity.security.user.Role;
import springsecurity.security.user.User;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity(name = "Token")
@Table(name = "Tokens")
public class Token {

    @Id
    @GeneratedValue
    @Column(name = "token_id", updatable = false, nullable = false)
    private Long tokenId;

    @Column(name = "uuid", updatable = false, nullable = false)
    private String uuid;

    @Column(name = "token", updatable = false, nullable = false)
    private String token;

    @Enumerated(EnumType.STRING)
    @Column(name = "type", updatable = false, nullable = false)
    private TokenType type;

    @Column(name = "expired", nullable = false)
    private boolean expired;

    @Column(name = "revoked", nullable = false)
    private boolean revoked;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", updatable = false, nullable = false)
    private User user;
}