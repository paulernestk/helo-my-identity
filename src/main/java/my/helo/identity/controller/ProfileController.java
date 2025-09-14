package my.helo.identity.controller;

import my.helo.identity.dto.ProfileDto;
import my.helo.identity.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/profile")
public class ProfileController {

    private final UserService userService;

    public ProfileController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/me")
    public ResponseEntity<ProfileDto> getProfile(@RequestHeader("Authorization") String bearerToken) {
        ProfileDto profile = userService.getProfile(bearerToken);
        return ResponseEntity.ok(profile);
    }
}
