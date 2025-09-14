package my.helo.identity.service;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Random;
import java.util.concurrent.TimeUnit;

@Service
public class OtpService {

    private static final long OTP_EXPIRY_MINUTES = 10;
    private static final long RATE_LIMIT_WINDOW_MINUTES = 10;
    private static final int MAX_REQUESTS_PER_WINDOW = 10;

    private static final String OTP_PREFIX = "otp:";
    private static final String RATE_PREFIX = "otp:rate:";

    private final StringRedisTemplate redisTemplate;

    public OtpService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public String generateOtp(String email) {
        String rateKey = RATE_PREFIX + email;
        String countStr = redisTemplate.opsForValue().get(rateKey);
        int count = countStr != null ? Integer.parseInt(countStr) : 0;

        if (count >= MAX_REQUESTS_PER_WINDOW) {
            throw new RuntimeException("Too many OTP requests. Please wait before retrying.");
        }

        // Increment request count
        redisTemplate.opsForValue().increment(rateKey);
        redisTemplate.expire(rateKey, RATE_LIMIT_WINDOW_MINUTES, TimeUnit.MINUTES);

        // Generate and store OTP
        String otp = String.valueOf(new Random().nextInt(900000) + 100000);
        String otpKey = OTP_PREFIX + email;
        redisTemplate.opsForValue().set(otpKey, otp, OTP_EXPIRY_MINUTES, TimeUnit.MINUTES);

        return otp;
    }

    public boolean verifyOtp(String email, String otp) {
        String key = OTP_PREFIX + email;
        String storedOtp = redisTemplate.opsForValue().get(key);
        boolean isValid = otp.equals(storedOtp);

        if (isValid) {
            redisTemplate.delete(key); // Clear OTP after successful verification
        }

        return isValid;
    }

    public void clearOtp(String email) {
        redisTemplate.delete(OTP_PREFIX + email);
    }
}
