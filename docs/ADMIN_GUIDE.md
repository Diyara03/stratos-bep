# Stratos BEP -- Admin Guide

## Overview

This guide is for users with the **ADMIN** role. It covers system configuration,
Gmail integration, API key management, and user administration.

---

## Accessing Settings

1. Log in with an ADMIN account
2. In the sidebar, under **Admin**, click **Settings**

Only ADMIN users can see and access this page.

---

## Gmail Integration

### How Email Protection Works

Stratos monitors a Gmail mailbox by periodically fetching new emails and analyzing
them through a multi-stage pipeline (Preprocessor, Checker, Decider). Emails are
classified as CLEAN, SUSPICIOUS, or MALICIOUS.

### Setting Up Gmail (First Time)

**Step 1: Create OAuth Credentials in Google Cloud**

1. Go to https://console.cloud.google.com
2. Create a project (or use an existing one)
3. Enable the **Gmail API** (APIs & Services > Library > search "Gmail API" > Enable)
4. Go to **APIs & Services > Credentials**
5. Click **Create Credentials > OAuth client ID**
6. If prompted, configure the OAuth consent screen:
   - User Type: External
   - App name: Stratos BEP
   - Add your email as a test user
7. For Application type, select **Web application** (NOT Desktop)
8. Add an Authorized redirect URI:
   ```
   http://YOUR_SERVER_IP/settings/gmail/callback/
   ```
   (or `https://yourdomain.com/settings/gmail/callback/` if using HTTPS)
9. Click **Create**
10. Download the JSON file

**Step 2: Upload Credentials in Stratos**

1. Go to **Settings > Gmail Integration**
2. Click **Choose File** and select the downloaded JSON
3. Click **Upload**

**Step 3: Connect Gmail**

1. Click **Connect Gmail Account**
2. You will be redirected to Google
3. Sign in with the Gmail account you want to protect
4. Grant Stratos permission to read and modify emails
5. You will be redirected back to Stratos
6. The status should show **CONNECTED** with the email address

### Disconnecting Gmail

1. Go to **Settings > Gmail Integration**
2. Click **Disconnect Gmail**
3. Email fetching will stop immediately

### Troubleshooting Gmail

| Issue | Solution |
|-------|----------|
| "Invalid credentials file" | Make sure you downloaded **Web application** type, not Desktop |
| "Redirect URI mismatch" | The URI in Google Console must match exactly (http/https, port, trailing slash) |
| Status shows EXPIRED | Token expired. Click Disconnect, then Connect again |
| No emails being fetched | Check the fetch interval in Detection Settings. Check Celery logs. |

---

## API Keys

### VirusTotal

- Used for URL reputation checking during email analysis
- Free tier: 4 requests per minute
- Get a key at: https://www.virustotal.com/gui/join-us
- Enter in Settings > API Keys > VirusTotal API Key
- Click **Test** to verify

### AbuseIPDB

- Used for IP address reputation checking
- Free tier: 1000 checks per day
- Get a key at: https://www.abuseipdb.com/register
- Enter in Settings > API Keys > AbuseIPDB API Key
- Click **Test** to verify

### Key Security

- Keys are encrypted at rest using Fernet (AES-128-CBC)
- Keys are displayed masked (e.g., `sk-1****7f3a`)
- Only ADMIN users can view or modify keys
- Leave a field blank when saving to keep the existing key

### What Happens Without API Keys

Stratos degrades gracefully:

| Missing Key | Impact |
|-------------|--------|
| No VirusTotal | URL checking uses URLhaus database only (still functional) |
| No AbuseIPDB | IP reputation checking skipped (other checks still run) |
| No keys at all | System works using keyword analysis, header checks, attachment inspection, and local TI database |

---

## Detection Thresholds

### Score Ranges

Every email receives a score from 0 to 100:

```
0 ──── Clean Threshold (25) ──── Malicious Threshold (70) ──── 100
  CLEAN          SUSPICIOUS              MALICIOUS
```

### Adjusting Thresholds

- **Clean Threshold** (default: 25): Scores below this are CLEAN
- **Malicious Threshold** (default: 70): Scores at or above this are MALICIOUS
- Scores between the two thresholds are SUSPICIOUS

### Recommendations

| Scenario | Clean | Malicious | Notes |
|----------|-------|-----------|-------|
| Default (balanced) | 25 | 70 | Good for most environments |
| High security | 15 | 50 | More emails quarantined, more false positives |
| Low noise | 35 | 85 | Fewer alerts, risk of missing threats |

### Fetch Interval

- How often Stratos checks Gmail for new emails (in seconds)
- Default: 10 seconds
- Minimum: 5 seconds
- For demo/viva: 10 seconds is good
- For production with high volume: 30-60 seconds

### TI Feed Sync

- Toggle to enable/disable daily sync of MalwareBazaar and URLhaus feeds
- When disabled, the existing TI database is still used for checks
- Only new data stops being imported

---

## User Management

### Roles

| Role | Dashboard | Emails | Quarantine Actions | TI Management | Reports/Export | User Admin | Settings |
|------|-----------|--------|--------------------|---------------|----------------|------------|----------|
| ADMIN | View | View | Release/Block/Delete | Add/Remove entries | All exports | Full control | Full control |
| ANALYST | View | View | Release/Block/Delete | View only | Email + IOC export | No access | No access |
| VIEWER | View | View | View only (no actions) | View only | No access | No access | No access |

### Adding Users

1. Go to **Users** (sidebar > Admin > Users)
2. Fill in username, email, password, and role
3. Click **Create User**

### Changing Roles

1. Go to **Users**
2. Use the role dropdown next to the user
3. The change takes effect immediately

### Security Rules

- You cannot change your own role (prevents self-demotion)
- You cannot deactivate your own account
- Deactivated users cannot log in

---

## What NOT to Do

1. **Do not** set Clean threshold higher than Malicious threshold
2. **Do not** set fetch interval below 5 seconds (Gmail rate limiting)
3. **Do not** share API keys or OAuth credentials
4. **Do not** upload Desktop Application credentials (only Web Application works)
5. **Do not** disconnect Gmail while emails are being analyzed
6. **Do not** change the SECRET_KEY after deployment (breaks encrypted API keys)
7. **Do not** give ADMIN role to users who don't need it
8. **Do not** disable TI sync without a reason (reduces detection capability)
