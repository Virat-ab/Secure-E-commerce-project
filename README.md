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


### 4. Run the Application
**Option A — VS Code:**
- Open `EcommerceApplication.java`
- Click the ▶ Run button above `main()`


### 5. Test the API
test the ApI accordingly.
