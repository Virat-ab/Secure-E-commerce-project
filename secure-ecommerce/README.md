# Secure E-commerce Platform — Multi-tenant Architecture

Enterprise-grade Spring Boot 3 application with JWT authentication, RBAC, OAuth2 social login, and schema-based multi-tenancy.

---

## Quick Start in VS Code

### Prerequisites
- Java 17+ (check: `java -version`)
- Maven 3.9+ (check: `mvn -version`)
- Docker Desktop (for PostgreSQL + Redis)
- VS Code with **Extension Pack for Java** installed

### 1. Clone / Open Project
Open this folder in VS Code. The Java extension will auto-detect the Maven project.

### 2. Start Infrastructure (Docker)
```bash
# Start PostgreSQL + Redis only (not the app)
docker-compose up postgres redis -d
```

### 3. Configure Environment
Create a `.env` file or set environment variables:
```bash
export JWT_SECRET=404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970
export DB_USERNAME=postgres
export DB_PASSWORD=postgres
# Optional for OAuth2:
export GOOGLE_CLIENT_ID=your-google-client-id
export GOOGLE_CLIENT_SECRET=your-google-client-secret
```

### 4. Run the Application
**Option A — VS Code:**
- Open `EcommerceApplication.java`
- Click the ▶ Run button above `main()`
- Or press `F5` (with launch.json configured)

**Option B — Terminal:**
```bash
mvn spring-boot:run
```

**Option C — Full Docker stack:**
```bash
docker-compose up --build
```

### 5. Test the API
```bash
# Health check
curl http://localhost:8080/actuator/health

# Register
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: admin" \
  -d '{"email":"test@example.com","password":"Test@1234","tenantId":"admin"}'

# Login
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Test@1234","tenantId":"admin"}'
```

---

## Project Structure

```
src/main/java/com/ecommerce/
├── security/
│   ├── config/         SecurityConfig, JwtConfig, OAuth2Config
│   ├── jwt/            JwtTokenProvider, JwtAuthenticationFilter, TokenBlacklistService
│   ├── oauth2/         CustomOAuth2UserService, OAuth2AuthenticationSuccessHandler
│   ├── multitenancy/   TenantContext, TenantAwareRoutingDataSource, TenantFilter
│   └── audit/          SecurityAuditAspect, SecurityAudit, SecurityEvent
├── model/
│   ├── entity/         User, Tenant, Role
│   ├── enums/          UserStatus, AuthProvider, Permission
│   └── dto/            LoginRequest, JwtResponse, UserProfile
├── controller/         AuthController, UserController, TenantController
├── service/            AuthService, UserService, TenantService
├── repository/         UserRepository, TenantRepository, RoleRepository
└── exception/          GlobalExceptionHandler + exception classes
```

---

## API Endpoints

### Authentication
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/login` | Public | Login → JWT pair |
| POST | `/api/auth/refresh` | Refresh token | Rotate tokens |
| POST | `/api/auth/logout` | Bearer | Blacklist token |
| POST | `/api/auth/register` | Public | Create account |
| POST | `/api/auth/reset-password` | Public | Password reset |
| GET | `/oauth2/authorization/google` | Public | Google SSO |
| GET | `/oauth2/authorization/github` | Public | GitHub SSO |

### User Management
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/users/me` | Bearer | Own profile |
| PUT | `/api/users/me` | Bearer | Update profile |
| GET | `/api/users` | Admin | List all users |
| PUT | `/api/users/{id}/roles` | Admin | Assign roles |

### Tenant Management
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/tenants` | Admin | Create tenant |
| GET | `/api/tenants` | Admin | List tenants |
| GET | `/api/tenants/{id}` | Bearer | Get tenant |
| PUT | `/api/tenants/{id}` | Admin | Update tenant |

---

## VS Code launch.json

Add this to `.vscode/launch.json` for debug support:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "java",
      "name": "EcommerceApplication",
      "request": "launch",
      "mainClass": "com.ecommerce.EcommerceApplication",
      "projectName": "secure-ecommerce",
      "env": {
        "JWT_SECRET": "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970",
        "DB_USERNAME": "postgres",
        "DB_PASSWORD": "postgres",
        "SPRING_PROFILES_ACTIVE": "dev"
      }
    }
  ]
}
```

---

## Running Tests
```bash
mvn test
```

---

## Security Architecture

```
Request → TenantFilter → JwtAuthFilter → SecurityContext → Controller
              ↓               ↓
         TenantContext   Redis Blacklist
              ↓
     RoutingDataSource → tenant_schema DB
```

### Roles
- `ROLE_ADMIN` — Full access, user/tenant management
- `ROLE_VENDOR` — Manage own products and orders
- `ROLE_CUSTOMER` — Browse, purchase, view own orders

### Token Lifecycle
- Access token: 15 minutes
- Refresh token: 7 days (30 days with rememberMe)
- Rotation: refresh token blacklisted on every use
- Logout: both tokens blacklisted in Redis
