package springsecurity.security.user;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import springsecurity.security.auth.ChangePasswordRequest;

@RestController
@CrossOrigin
@ResponseBody
@RequiredArgsConstructor
@RequestMapping("security/user/")
public class UserController {

    private final UserService userService;

    @GetMapping(path = "get-authenticated")
    public User getUser(@AuthenticationPrincipal User user){
        return user;
    }

    @PostMapping(path = "change-password")
    public String changePassword(
            @Validated @RequestBody ChangePasswordRequest changePasswordRequest,
            @AuthenticationPrincipal User user
    ){
        return userService.changePassword(changePasswordRequest, user);
    }
}