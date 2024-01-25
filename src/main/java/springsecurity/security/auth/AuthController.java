package springsecurity.security.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import springsecurity.security.user.User;

@RestController
@CrossOrigin
@ResponseBody
@RequiredArgsConstructor
@RequestMapping("security/auth/")
public class AuthController {

    private final AuthService authService;

    @PostMapping(path = "login")
    public String login(@Validated @RequestBody LoginRequest loginRequest){
        return authService.login(loginRequest);
    }

    @PostMapping(path = "register")
    public String register(@Validated @RequestBody RegisterRequest registerRequest){
        return authService.register(registerRequest);
    }
}