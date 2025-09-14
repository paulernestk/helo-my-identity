package my.helo.identity.service;

public interface EmailService {
    void sendOtpEmail(String to, String otp);
}
