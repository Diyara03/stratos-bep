# Stratos BEP -- Hetzner Deployment Guide

## Prerequisites

- Hetzner Cloud account (https://console.hetzner.cloud)
- SSH key pair (generate with `ssh-keygen` if you don't have one)
- Your project code (this repository)

---

## Step 1: Create the Server

1. Log in to Hetzner Cloud Console
2. Click **Add Server**
3. Configure:
   - **Location**: Falkenstein (EU-Central) or nearest to you
   - **Image**: Ubuntu 22.04
   - **Type**: CX22 (2 vCPU, 4GB RAM, 40GB disk) -- ~4.50 EUR/month
   - **SSH Key**: Add your public key
   - **Name**: `stratos-bep`
4. Click **Create & Buy**
5. Note the **Server IP** (e.g., `78.47.xxx.xxx`)

---

## Step 2: Connect and Install Docker

```bash
# SSH into your server
ssh root@YOUR_SERVER_IP

# Update system
apt update && apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com | sh

# Install Docker Compose plugin
apt install -y docker-compose-plugin

# Verify
docker --version
docker compose version
```

---

## Step 3: Upload Your Project

**Option A: Git clone (recommended)**

```bash
# On the server
cd /opt
git clone https://github.com/Diyara03/stratos-bep.git stratos
cd stratos
```

**Option B: SCP from your local machine**

```bash
# On your LOCAL machine (not the server)
scp -r /path/to/Stratos root@YOUR_SERVER_IP:/opt/stratos
```

---

## Step 4: Configure Environment

```bash
cd /opt/stratos

# Create .env from template
cp .env.example .env

# Generate a secure SECRET_KEY
python3 -c "import secrets; print(secrets.token_urlsafe(50))"
# Copy the output

# Edit .env with your values
nano .env
```

**Required changes in `.env`:**

```env
SECRET_KEY=<paste-the-generated-key>
ALLOWED_HOSTS=YOUR_SERVER_IP,localhost,127.0.0.1
CSRF_TRUSTED_ORIGINS=http://YOUR_SERVER_IP
POSTGRES_PASSWORD=<choose-a-strong-password>
DATABASE_URL=postgresql://stratos_user:<same-password>@postgres:5432/stratos_db
```

---

## Step 5: Configure Caddy (Web Server)

```bash
# Edit the Caddyfile
nano Caddyfile
```

**For IP-only access (simplest, no domain needed):**

```
:80 {
    reverse_proxy django:8000
}
```

**For a domain with automatic HTTPS:**

```
stratos.yourdomain.com {
    reverse_proxy django:8000
}
```

If using a domain, also update `.env`:

```env
ALLOWED_HOSTS=stratos.yourdomain.com,YOUR_SERVER_IP
CSRF_TRUSTED_ORIGINS=https://stratos.yourdomain.com
HTTPS_ENABLED=true
```

---

## Step 6: Create Credentials Directory

```bash
mkdir -p credentials
```

Gmail credentials will be uploaded via the Settings UI after deployment.
You do NOT need to copy credential files manually.

---

## Step 7: Build and Start

```bash
# Build and start all containers
docker compose -f docker-compose.prod.yml up -d --build

# Wait for health checks (~30 seconds)
docker compose -f docker-compose.prod.yml ps

# Check logs for any errors
docker compose -f docker-compose.prod.yml logs django --tail=20
```

You should see:

```
django  | [INFO] Listening at: http://0.0.0.0:8000
celery  | [INFO] Connected to redis://redis:6379/0
```

---

## Step 8: Create Admin User and Seed Data

```bash
# Create the admin superuser
docker compose -f docker-compose.prod.yml exec django \
  python manage.py createsuperuser

# (Optional) Seed demo data for the viva
docker compose -f docker-compose.prod.yml exec django \
  python manage.py demo_setup
```

---

## Step 9: Access Your Application

Open in your browser:

```
http://YOUR_SERVER_IP
```

Log in with the admin account you just created.

---

## Step 10: Configure Gmail and API Keys (via UI)

1. Log in as ADMIN
2. Go to **Settings** (sidebar > Admin > Settings)
3. **Gmail Integration**:
   - In Google Cloud Console, create a **Web Application** OAuth client
   - Set redirect URI to: `http://YOUR_SERVER_IP/settings/gmail/callback/`
   - Download the credentials JSON
   - Upload it in the Settings page
   - Click **Connect Gmail Account**
   - Sign in with the Gmail account to protect
4. **API Keys**:
   - Enter your VirusTotal API key
   - Enter your AbuseIPDB API key
   - Click **Test** to verify each key works
   - Click **Save API Keys**

---

## Useful Commands

```bash
# View all container status
docker compose -f docker-compose.prod.yml ps

# View Django logs
docker compose -f docker-compose.prod.yml logs django -f

# View Celery worker logs
docker compose -f docker-compose.prod.yml logs celery -f

# Restart all services
docker compose -f docker-compose.prod.yml restart

# Stop everything
docker compose -f docker-compose.prod.yml down

# Stop and delete all data (database, volumes)
docker compose -f docker-compose.prod.yml down -v

# Run a Django management command
docker compose -f docker-compose.prod.yml exec django python manage.py <command>

# Open Django shell
docker compose -f docker-compose.prod.yml exec django python manage.py shell

# Rebuild after code changes
docker compose -f docker-compose.prod.yml up -d --build
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "502 Bad Gateway" | Django container not ready yet. Wait 30s, check `docker compose logs django` |
| "CSRF verification failed" | Add your domain/IP to `CSRF_TRUSTED_ORIGINS` in `.env` |
| Gmail OAuth redirect error | Check redirect URI matches exactly (http vs https, trailing slash) |
| Static files not loading | Run `docker compose exec django python manage.py collectstatic --noinput` |
| Database connection error | Check `POSTGRES_PASSWORD` matches in both `POSTGRES_PASSWORD` and `DATABASE_URL` |
| Celery not processing | Check `docker compose logs celery`. Redis must be healthy. |

---

## Cost

- CX22: ~4.50 EUR/month
- Delete the server after the viva to stop billing
- Hetzner bills hourly, so even a few days costs under 1 EUR

---

## Security Notes for Production

- Change the default `SECRET_KEY` (never use the example value)
- Use a strong `POSTGRES_PASSWORD` (16+ characters)
- If using a domain, Caddy provides automatic HTTPS (free Let's Encrypt)
- API keys are encrypted in the database using Fernet (AES-128-CBC)
- Only ADMIN users can access the Settings page
