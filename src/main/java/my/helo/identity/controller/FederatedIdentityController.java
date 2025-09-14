package my.helo.identity.controller;

import my.helo.identity.dto.LinkProviderRequest;
import my.helo.identity.dto.UnlinkProviderRequest;
import my.helo.identity.service.FederatedIdentityService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class FederatedIdentityController {

    private final FederatedIdentityService federatedService;

    public FederatedIdentityController(FederatedIdentityService federatedService) {
        this.federatedService = federatedService;
    }

    @PostMapping("/link-provider")
    public ResponseEntity<Void> linkProvider(@RequestBody LinkProviderRequest request,
                                             @RequestHeader("Authorization") String bearerToken) {
        federatedService.linkProvider(request.provider(), bearerToken);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/linked-providers")
    public ResponseEntity<List<Map<String, Object>>> listLinkedProviders(@RequestHeader("Authorization") String bearerToken) {
        return ResponseEntity.ok(federatedService.getLinkedProviders(bearerToken));
    }

    @DeleteMapping("/unlink-provider")
    public ResponseEntity<Void> unlinkProvider(@RequestBody UnlinkProviderRequest request,
                                               @RequestHeader("Authorization") String bearerToken) {
        federatedService.unlinkProvider(request.provider(), bearerToken);
        return ResponseEntity.ok().build();
    }
}
