# Deployment Guide — AJ Smart FHIR Authorization Server

This guide covers three deployment options. Choose the one that fits your environment.

---

## Option A — Behind nginx (recommended for production)

nginx terminates TLS. Spring Boot runs on plain HTTP internally on port 9000.

**Why this is recommended:** nginx is battle-tested for TLS, handles certificate renewal without app restarts, serves multiple apps on the same server on port 443, and performs better under high traffic.

### Steps

**1. Install nginx and certbot**
```bash
apt install nginx certbot python3-certbot-nginx
```

**2. Copy the nginx config**
```bash
cp nginx/smart-fhir.conf /etc/nginx/sites-available/smart-fhir
ln -s /etc/nginx/sites-available/smart-fhir /etc/nginx/sites-enabled/
```
Edit the file and replace every `auth.yourdomain.com` with your actual domain.

**3. Obtain a TLS certificate**
```bash
certbot --nginx -d auth.yourdomain.com
```
Certbot edits the nginx config automatically and sets up auto-renewal.

**4. Start Spring Boot**
```bash
SPRING_PROFILES_ACTIVE=prod \
ISSUER_URL=https://auth.yourdomain.com \
DB_URL=jdbc:postgresql://localhost:5432/smartfhir \
DB_USER=smartfhir \
DB_PASSWORD=yourpassword \
KEYSTORE_PATH=/etc/smart-fhir/signing.p12 \
KEYSTORE_PASSWORD=yourkeystorepassword \
CORS_ORIGIN_1=https://your-smart-app.com \
./mvnw spring-boot:run
```

Or with the JAR:
```bash
java -jar smart-fhir-server.jar
```

The `forward-headers-strategy: framework` in `application-prod.yml` ensures Spring builds `https://` URLs for the SMART discovery document and token `iss` claim.

---

## Option B — Embedded TLS (no proxy)

Spring Boot / embedded Tomcat handles TLS directly. No nginx needed.

**When to use this:** simple single-server deployments, internal networks, or environments where running nginx is not practical.

### Generate a keystore

**Self-signed certificate (internal use / testing):**
```bash
keytool -genkeypair -alias smart-fhir -keyalg RSA -keysize 2048 \
  -sigalg SHA256withRSA -storetype PKCS12 \
  -keystore server-tls.p12 -storepass changeit -keypass changeit \
  -validity 825 -dname "CN=auth.yourdomain.com,O=YourOrg,C=US"
```

**Let's Encrypt certificate (public domain):**
```bash
# Obtain the cert (standalone mode — no nginx needed)
certbot certonly --standalone -d auth.yourdomain.com

# Convert to PKCS12
openssl pkcs12 -export \
  -in  /etc/letsencrypt/live/auth.yourdomain.com/fullchain.pem \
  -inkey /etc/letsencrypt/live/auth.yourdomain.com/privkey.pem \
  -out server-tls.p12 -name smart-fhir -passout pass:changeit
```

**Note on renewal:** certbot auto-renews PEM certs but Spring reads the keystore at startup. Add a post-renewal hook to re-convert and restart:
```bash
# /etc/letsencrypt/renewal-hooks/deploy/smart-fhir.sh
#!/bin/bash
openssl pkcs12 -export -in /etc/letsencrypt/live/auth.yourdomain.com/fullchain.pem \
  -inkey /etc/letsencrypt/live/auth.yourdomain.com/privkey.pem \
  -out /etc/smart-fhir/server-tls.p12 -name smart-fhir -passout pass:changeit
systemctl restart smart-fhir
```

### Start with embedded TLS

```bash
SPRING_PROFILES_ACTIVE=prod \
SSL_ENABLED=true \
SSL_PORT=8443 \
SSL_KEYSTORE_PATH=/etc/smart-fhir/server-tls.p12 \
SSL_KEYSTORE_PASSWORD=changeit \
SSL_KEY_ALIAS=smart-fhir \
ISSUER_URL=https://auth.yourdomain.com:8443 \
DB_URL=jdbc:postgresql://localhost:5432/smartfhir \
DB_USER=smartfhir \
DB_PASSWORD=yourpassword \
KEYSTORE_PATH=/etc/smart-fhir/signing.p12 \
KEYSTORE_PASSWORD=yourkeystorepassword \
CORS_ORIGIN_1=https://your-smart-app.com \
./mvnw spring-boot:run
```

To serve on port 443 directly (without `:8443` in the issuer URL), run as root or grant the capability:
```bash
setcap CAP_NET_BIND_SERVICE=+eip $(which java)
# Then set SSL_PORT=443 and ISSUER_URL=https://auth.yourdomain.com
```

---

## Option C — Docker Compose

Uses the provided `docker/docker-compose.yml`. Combines Option A or B with PostgreSQL in containers.

```bash
cd deploy/docker
cp .env.example .env
# Edit .env — fill in all secrets
mkdir -p secrets
cp /path/to/signing.p12 secrets/signing.p12
# Option B only:
# cp /path/to/server-tls.p12 secrets/server-tls.p12

docker compose up -d
docker compose logs -f smart-fhir-server
```

For Option A with Docker, run nginx on the host pointing at `127.0.0.1:9000` (the port the compose stack exposes).

---

## Option D — Local development

No TLS. HTTP only. Seeded test data.

```bash
cd smart-auth-server
SPRING_PROFILES_ACTIVE=dev ./mvnw spring-boot:run
```

Server: `http://localhost:9000`  
Login: `dr.smith` / `password123`  
H2 console: `http://localhost:9000/h2-console`

---

## Environment variable reference

| Variable | Required | Default | Description |
|---|---|---|---|
| `SPRING_PROFILES_ACTIVE` | Yes | — | `dev`, `prod`, or `prod,idp` |
| `ISSUER_URL` | Yes (prod) | `http://localhost:9000` | Public HTTPS URL of this server |
| `FHIR_BASE_URL` | Yes (prod) | `http://localhost:8080/fhir` | FHIR server this auth server protects |
| `DB_URL` | Yes (prod) | H2 in dev | JDBC URL for PostgreSQL |
| `DB_USER` | Yes (prod) | — | Database username |
| `DB_PASSWORD` | Yes (prod) | — | Database password |
| `KEYSTORE_PATH` | Yes (prod) | — | Path to PKCS12 keystore for JWT signing |
| `KEYSTORE_PASSWORD` | Yes (prod) | — | Keystore password |
| `KEYSTORE_ALIAS` | No | `smart-fhir` | Key alias in the signing keystore |
| `CORS_ORIGIN_1` | Yes (prod) | `http://localhost:8081` | Primary allowed CORS origin |
| `CORS_ORIGIN_2` | No | `http://localhost:3000` | Secondary allowed CORS origin |
| `ACCESS_TOKEN_TTL` | No | `300` (prod) / `3600` (dev) | Access token lifetime in seconds |
| `REFRESH_TOKEN_TTL` | No | `86400` | Refresh token lifetime in seconds |
| `SMART_CLIENT_LAUNCH_URL` | Yes (prod) | `http://localhost:8081/launch` | SMART app launch endpoint |
| `DEFAULT_CLIENT_ID` | No | `jam-smart-client` | Default OAuth2 client ID |
| `SSL_ENABLED` | No | `false` | Set `true` for embedded TLS (Option B) |
| `SSL_PORT` | No | `8443` | Port for embedded TLS |
| `SSL_KEYSTORE_PATH` | Option B | — | Path to TLS keystore (separate from signing key) |
| `SSL_KEYSTORE_PASSWORD` | Option B | — | TLS keystore password |
| `SSL_KEY_ALIAS` | No | `smart-fhir` | TLS key alias |

---

## Token revocation propagation

SMART access tokens are bearer tokens. Once the FHIR server accepts a token, there is
no automatic "recall" signal — the FHIR server would continue accepting it until it
expires on its own. Two mechanisms together eliminate this gap:

### Mechanism 1 — Short-lived access tokens (5 minutes)

The production default is 300 s. A stolen token is useless after 5 minutes. The app
refreshes silently using its refresh token; the clinician is never re-prompted.

Override per-deployment with the `ACCESS_TOKEN_TTL` env var.
Override per-app via `RegisteredApp.accessTokenTtlSeconds` (for apps that need longer — e.g. an offline background sync job).

### Mechanism 2 — Token introspection (RFC 7662)

The FHIR server calls this auth server to validate each token before serving the request.
This catches mid-session revocations: clinician logout, app de-registration,
clinician account disabled.

**Introspection endpoint:** `POST /oauth2/introspect`

```bash
curl -X POST https://auth.yourdomain.com/oauth2/introspect \
  -d "token=<the_access_token>" \
  -d "client_id=<your_client_id>"
```

**Response (active token):**
```json
{
  "active": true,
  "sub":    "dr.smith",
  "scope":  "patient/Patient.rs patient/Observation.rs",
  "exp":    1721000000,
  "iss":    "https://auth.yourdomain.com"
}
```

**Response (expired or revoked token):**
```json
{ "active": false }
```

**Configuring HAPI FHIR to use introspection:**
In your HAPI FHIR server `application.yaml`:
```yaml
hapi:
  fhir:
    tester:
      home:
        server_address: https://fhir.yourdomain.com/fhir
spring:
  security:
    oauth2:
      resourceserver:
        opaque-token:
          introspection-uri:  https://auth.yourdomain.com/oauth2/introspect
          client-id:          <your-fhir-server-client-id>
```

Or if your HAPI FHIR uses JWT validation, set the `issuer-uri` to the SMART auth server
and it will auto-discover the JWKS endpoint:
```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://auth.yourdomain.com
```

Both modes are valid. Introspection catches revocations in real time at the cost of one
HTTP call per FHIR request. JWT-only validation is faster but only catches revocations
when the access token expires (hence the 5-minute TTL matters more in this mode).

---

## RSA signing key

The signing key is separate from the TLS certificate. It signs JWT access tokens and id_tokens.

Generate a signing keystore (do this once; keep it safe):
```bash
keytool -genkeypair -alias smart-fhir -keyalg RSA -keysize 2048 \
  -sigalg SHA256withRSA -storetype PKCS12 \
  -keystore signing.p12 -storepass changeit -keypass changeit \
  -dname "CN=smart-fhir-token-signing,O=YourOrg,C=US"
```

If `KEYSTORE_PATH` is not set, a fresh RSA key is generated at startup — all tokens are invalidated on every restart. **Never use this in production.**
