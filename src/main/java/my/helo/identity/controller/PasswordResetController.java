package my.helo.identity.controller;

import my.helo.identity.dto.PasswordResetRequest;
import my.helo.identity.dto.PasswordResetVerify;
import my.helo.identity.dto.PasswordResetUpdate;
import my.helo.identity.service.PasswordResetService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class PasswordResetController {

    private final PasswordResetService resetService;

    public PasswordResetController(PasswordResetService resetService) {
        this.resetService = resetService;
    }

    @PostMapping("/request-reset")
    public ResponseEntity<Void> requestReset(@RequestBody PasswordResetRequest request) {
        resetService.sendOtp(request.email());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/verify-reset")
    public ResponseEntity<String> verifyOtp(@RequestBody PasswordResetVerify verify) {
        String token = resetService.verifyOtpAndIssueToken(verify.email(), verify.otp());
        return ResponseEntity.ok(token);
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Void> resetPassword(@RequestBody PasswordResetUpdate update) {
        resetService.resetPassword(update.token(), update.newPassword());
        return ResponseEntity.ok().build();
    }
}
