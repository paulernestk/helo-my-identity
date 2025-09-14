package my.helo.identity.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.UUID;

@Service
public class PasswordResetService {

    private static final Logger log = LoggerFactory.getLogger(PasswordResetService.class);
    private static final Duration RESET_TOKEN_EXPIRY = Duration.ofMinutes(10);

    private final StringRedisTemplate redis;
    private final UserService userService;
    private final OtpService otpService;
    private final EmailService emailService;

    public PasswordResetService(StringRedisTemplate redis,
                                UserService userService,
                                OtpService otpService,
                                EmailService emailService) {
        this.redis = redis;
        this.userService = userService;
        this.otpService = otpService;
        this.emailService = emailService;
    }

    public void sendOtp(String email) {
        String otp = otpService.generateOtp(email);
        emailService.sendOtpEmail(email, otp);
        log.info("OTP sent to {}", email);
    }

    public String verifyOtpAndIssueToken(String email, String otp) {
        boolean valid = otpService.verifyOtp(email, otp);
        if (!valid) {
            throw new IllegalArgumentException("Invalid or expired OTP");
        }

        String token = UUID.randomUUID().toString();
        redis.opsForValue().set("reset:" + token, email, RESET_TOKEN_EXPIRY);
        log.info("Password reset token issued for {}", email);
        return token;
    }

    public void resetPassword(String token, String newPassword) {
        String email = redis.opsForValue().get("reset:" + token);
        if (email == null) {
            throw new IllegalArgumentException("Invalid or expired reset token");
        }

        redis.delete("reset:" + token);
        userService.updatePassword(email, newPassword);
        log.info("Password reset completed for {}", email);
    }
}
