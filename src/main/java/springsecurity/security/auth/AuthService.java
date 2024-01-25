package springsecurity.security.auth;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import springsecurity.exception.BackendException;
import springsecurity.security.config.JwtService;
import springsecurity.security.token.Token;
import springsecurity.security.token.TokenRepository;
import springsecurity.security.token.TokenType;
import springsecurity.security.user.User;
import springsecurity.security.user.UserRepository;

import java.security.Principal;
import java.util.List;
import java.util.UUID;

import static springsecurity.exception.MsgCode.OOPS_ERROR;
import static springsecurity.security.user.Role.ADMIN;

@Service
@Transactional
@RequiredArgsConstructor
public class AuthService {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public String login(LoginRequest loginRequest){

        User user = userRepository.findByEmail(loginRequest.getEmail())
                .orElseThrow(() -> new BackendException(OOPS_ERROR));

        try{

            authenticationManager.authenticate(

                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getEmail(),
                            loginRequest.getPassword()
                    )
            );

            String jwt = jwtService.generateToken(user);

            saveUserToken(user, jwt);

            return jwt;

        }catch (AuthenticationException ex){

            throw new BackendException(OOPS_ERROR);
        }
    }

    public String register(RegisterRequest registerRequest){

        boolean existsUser = userRepository.existsByEmail(registerRequest.getEmail());

        if(!existsUser){

            User user = User
                    .builder()
                    .uuid(UUID.randomUUID().toString())
                    .email(registerRequest.getEmail())
                    .password(passwordEncoder.encode(registerRequest.getPassword()))
                    .role(ADMIN)
                    .build();

            User savedUser = userRepository.save(user);

            String jwt = jwtService.generateToken(user);

            revokeAllUserTokens(user);

            saveUserToken(savedUser, jwt);

            return jwt;
        }
        else{

            throw new BackendException(OOPS_ERROR);
        }
    }

    private void saveUserToken(User user, String jwt){

        Token token = Token
                .builder()
                .uuid(UUID.randomUUID().toString())
                .token(jwt)
                .type(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .user(user)
                .build();

        tokenRepository.save(token);
    }

    private void revokeAllUserTokens(User user){

        List<Token> validUserTokens = tokenRepository.findAllValidTokensByUser(user.getUserId());

        if(!validUserTokens.isEmpty()){

            validUserTokens.forEach(token -> {

                token.setExpired(true);
                token.setRevoked(true);

            });

            tokenRepository.saveAll(validUserTokens);
        }
    }
}