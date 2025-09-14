# helo-identity-service

Identity microservice for the helo.my super app. Handles:

- OTP-based onboarding
- JWT issuance via Keycloak
- Role promotion and RBAC
- Email verification flows

## Tech Stack
- Spring Boot
- Redis
- Keycloak
- Docker

## Endpoints
- `POST /helo/auth/send-otp`
- `POST /helo/auth/verify-otp`
- `GET /helo/auth/login-success`
- `POST /admin/init-roles`
