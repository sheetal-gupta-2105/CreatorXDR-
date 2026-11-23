# CreatorXDR

CreatorXDR is an identity verification and audit-integrity platform with a React frontend, Flask backend, PostgreSQL database, OCR processing, and Ethereum-based audit anchoring.

## Architecture

- Frontend: React, TypeScript, Vite, Nginx
- Backend: Python, Flask, Gunicorn
- Database: PostgreSQL 16
- OCR: Tesseract (English and Hindi), Poppler
- Blockchain: Solidity, Hardhat, Ethereum
- Containerization: Docker Compose

## Prerequisites

Install:
- Git
- Docker Desktop

Start Docker Desktop before proceeding.

## Getting started

### 1. Clone the repository

```bash
git clone YOUR_REPOSITORY_URL
cd CreatorXDR-
```

### 2. Create your environment file

On macOS/Linux:

```bash
SECRET_KEY=$(openssl rand -hex 32)
JWT_SECRET_KEY=$(openssl rand -hex 32)
IDENTITY_HMAC_KEY=$(openssl rand -hex 32)
OCR_ENCRYPTION_KEY=$(python3 -c 'import base64,os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())')
POSTGRES_PASSWORD=$(openssl rand -hex 24)

cat > .env <<EOF
SECRET_KEY=${SECRET_KEY}
JWT_SECRET_KEY=${JWT_SECRET_KEY}
IDENTITY_HMAC_KEY=${IDENTITY_HMAC_KEY}
OCR_ENCRYPTION_KEY=${OCR_ENCRYPTION_KEY}
POSTGRES_USER=creatorxdr
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
POSTGRES_DB=creatorxdr
DATABASE_URL=postgresql+psycopg://creatorxdr:${POSTGRES_PASSWORD}@db:5432/creatorxdr
FRONTEND_ORIGIN=http://localhost:5173
FLASK_DEBUG=false
AUTH_DEBUG_OTP=false
IDENTITY_STORAGE_PATH=/app/storage/identity_documents
EOF

chmod 600 .env
```

Every developer must generate their own secrets. Never share `.env`.

### 3. Build and start

```bash
docker compose up --build -d
```

This builds and starts the frontend, backend, and PostgreSQL database. Database migrations run automatically when the backend starts.

### 4. Verify services

```bash
docker compose ps
```

Wait until all services report `healthy`.

### 5. Create an administrator

```bash
docker compose exec backend flask --app run create-admin
```

Follow the prompts. Use a password of at least 12 characters.

## Application URLs

| Service | URL |
|---|---|
| Frontend | http://localhost:5173 |
| Backend health | http://localhost:5001/api/health |

## Useful commands

```bash
# View service status
docker compose ps

# View all logs
docker compose logs -f

# Backend logs
docker compose logs -f backend

# Restart services
docker compose restart

# Rebuild after code changes
docker compose up --build -d

# Stop services
docker compose down
```

Do not use `docker compose down -v` unless you intentionally want to delete persistent database and document storage.

## Persistent storage

Docker named volumes preserve:
- PostgreSQL database data
- Uploaded identity documents

Stopping containers does not remove these volumes.

## Blockchain

The Solidity audit anchoring contract and Hardhat tests are maintained under `blockchain/`.

The contract is not automatically deployed by Docker Compose. Sepolia deployment is a separate operation and requires separately configured credentials.

## Security

- Never commit `.env` or private keys.
- Never share encryption keys or database passwords.
- Never commit real identity documents.
- Use synthetic documents for development and testing.
- Generate separate environment secrets for every developer.

## Troubleshooting

Inspect service logs:

```bash
docker compose logs --tail=100 backend
docker compose logs --tail=100 frontend
docker compose logs --tail=100 db
```

Validate Compose configuration:

```bash
docker compose config --quiet
```

If a port is already occupied, check the host port mappings in `docker-compose.yml`.

