package springsecurity.security.user;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import springsecurity.exception.BackendException;
import springsecurity.security.auth.ChangePasswordRequest;

import static springsecurity.exception.MsgCode.OOPS_ERROR;

@Service
@Transactional
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public String changePassword(
            ChangePasswordRequest changePasswordRequest,
            @AuthenticationPrincipal User user
    ){

        String currentPassword = changePasswordRequest.getCurrentPassword();
        String newPassword = changePasswordRequest.getNewPassword();
        String newPasswordConfirmation = changePasswordRequest.getNewPasswordConfirmation();

        if(passwordEncoder.matches(currentPassword, user.getPassword()) && newPassword.equals(newPasswordConfirmation)){

            user.setPassword(passwordEncoder.encode(newPassword));
            userRepository.save(user);

            return "Password changed successfully";
        }
        else{

            throw new BackendException(OOPS_ERROR);
        }
    }
}