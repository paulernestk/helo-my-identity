package my.helo.identity.controller;

import my.helo.identity.dto.AuthResponse;
import my.helo.identity.dto.EmailRequest;
import my.helo.identity.dto.OtpVerificationRequest;
import my.helo.identity.dto.TokenResponse;
import my.helo.identity.service.OtpService;
import my.helo.identity.service.RoleService;
import my.helo.identity.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final OtpService otpService;
    private final UserService userService;
    private final RoleService roleService;

    public AuthController(OtpService otpService, UserService userService, RoleService roleService) {
        this.otpService = otpService;
        this.userService = userService;
        this.roleService = roleService;
    }

    @GetMapping("/login-success")
    public ResponseEntity<AuthResponse> loginSuccess(OAuth2AuthenticationToken token) {
        String username = token.getPrincipal().getAttribute("preferred_username");
        return ResponseEntity.ok(new AuthResponse("Logged in as: " + username, null));
    }

    @PostMapping("/send-otp")
    public ResponseEntity<AuthResponse> sendOtp(@RequestBody EmailRequest request) {
        try {
            String otp = otpService.generateOtp(request.getEmail());
            return ResponseEntity.ok(new AuthResponse("OTP sent to " + request.getEmail(), null));
        } catch (RuntimeException e) {
            return ResponseEntity.status(429).body(new AuthResponse(e.getMessage(), null));
        }
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<AuthResponse> verifyOtp(@RequestBody OtpVerificationRequest request) {
        boolean isValid = otpService.verifyOtp(request.getEmail(), request.getOtp());

        if (!isValid) {
            return ResponseEntity.status(401).body(new AuthResponse("Invalid or expired OTP", null));
        }

        roleService.assignRole(request.getEmail(), "member");

        try {
            TokenResponse token = userService.issueJwtWithProfile(request.getEmail(), "temporary123");
            return ResponseEntity.ok(new AuthResponse("OTP verified", token));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(new AuthResponse("OTP verified, but failed to issue token.", null));
        }
    }

}
