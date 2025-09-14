📘 helo-my-identity — Identity Microservice for helo.my
A modular Spring Boot microservice for secure user onboarding, authentication, and profile management using Keycloak, Redis, and JWT. Designed for scalable integration into the helo.my super app ecosystem.

🚀 Features
🔐 User Creation via Keycloak Admin API

🔑 JWT Issuance with access + refresh tokens

👤 Profile Enrichment from Keycloak

📧 Email OTP Flow for secure onboarding

🧠 Redis Caching for optimized user lookup

🛡️ Role Assignment via RoleService

📦 DTO-based APIs for clean frontend integration

🧰 Modular Controllers for /email and /auth flows

🧱 Tech Stack
Layer	Tools Used
Framework	Spring Boot 3.1.x
Auth Provider	Keycloak (OpenID Connect)
HTTP Client	WebClient (Reactive)
Caching	Redis via StringRedisTemplate
Security	JWT, OAuth2 Resource Server
Email	Spring Mail
Build	Maven + Java 17
📂 Key Endpoints
Method	Endpoint	Description
POST	/email/send-otp	Sends OTP to user's email
POST	/email/verify-otp	Verifies OTP and creates user
POST	/auth/verify-otp	Verifies OTP and issues JWT + profile
GET	/profile/me	Returns enriched user profile
⚙️ Configuration
Set the following in your application.yml or .properties:

yaml
keycloak:
realm: helo
client-id: helo-client
server-url: http://localhost:8080
spring:
redis:
host: localhost
port: 6379
🧪 Testing Locally
bash
# Run the service
./mvnw spring-boot:run

# Test OTP flow
curl -X POST http://localhost:8081/email/send-otp \
-H "Content-Type: application/json" \
-d '{"email":"user@example.com"}'
👥 Contributors
Paul — Founder & Technical Lead Architecting scalable identity flows for Malaysia’s next-gen super app.