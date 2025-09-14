package my.helo.identity.controller;

import my.helo.identity.dto.AuthResponse;
import my.helo.identity.dto.EmailRequest;
import my.helo.identity.dto.OtpVerificationRequest;
import my.helo.identity.dto.TokenResponse;
import my.helo.identity.service.EmailService;
import my.helo.identity.service.OtpService;
import my.helo.identity.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/email")
public class EmailAuthController {

    private final EmailService emailService;
    private final OtpService otpService;
    private final UserService userService;

    public EmailAuthController(EmailService emailService, OtpService otpService, UserService userService) {
        this.emailService = emailService;
        this.otpService = otpService;
        this.userService = userService;
    }

    @PostMapping("/send-otp")
    public ResponseEntity<AuthResponse> sendOtp(@RequestBody EmailRequest request) {
        try {
            String otp = otpService.generateOtp(request.getEmail());
            emailService.sendOtpEmail(request.getEmail(), otp);
            return ResponseEntity.ok(new AuthResponse("OTP sent to email", null));
        } catch (RuntimeException e) {
            return ResponseEntity.status(429).body(new AuthResponse(e.getMessage(), null));
        }
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<AuthResponse> verifyOtp(@RequestBody OtpVerificationRequest request) {
        boolean valid = otpService.verifyOtp(request.getEmail(), request.getOtp());

        if (!valid) {
            return ResponseEntity.status(401).body(new AuthResponse("Invalid or expired OTP", null));
        }

        userService.createUser(request.getEmail());

        try {
            TokenResponse token = userService.issueJwtWithProfile(request.getEmail(), "temporary123");
            return ResponseEntity.ok(new AuthResponse("OTP verified. User created.", token));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(new AuthResponse("User created, but failed to issue token.", null));
        }
    }
}
