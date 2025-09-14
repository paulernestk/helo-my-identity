package my.helo.identity.controller;

import my.helo.identity.dto.AuthResponse;
import my.helo.identity.service.RoleService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/admin")
public class AdminSetupController {

    private final RoleService roleService;

    public AdminSetupController(RoleService roleService) {
        this.roleService = roleService;
    }

    @PostMapping("/init-roles")
    public ResponseEntity<AuthResponse> initializeRoles() {
        try {
            roleService.initializeRoles();
            return ResponseEntity.ok(new AuthResponse("Realm roles initialized successfully.", null));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(new AuthResponse("Failed to initialize roles: " + e.getMessage(), null));
        }
    }

    @PostMapping("/assign-role")
    public ResponseEntity<AuthResponse> assignRole(@RequestParam String email, @RequestParam String role) {
        try {
            roleService.assignRole(email, role);
            return ResponseEntity.ok(new AuthResponse("Role '" + role + "' assigned to " + email, null));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(new AuthResponse("Failed to assign role: " + e.getMessage(), null));
        }
    }
}
