package my.helo.identity.dto;

import java.util.List;

public record ProfileDto(String id, String email, String username, List<String> roles) {}
