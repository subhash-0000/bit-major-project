# Security Guidelines

## ⚠️ Important: API Keys and Credentials

This project requires several API keys and credentials to function. **NEVER commit these to version control.**

### Required API Keys

1. **Jira API Token** - For creating and managing Jira tickets
2. **Slack Bot Token** - For sending notifications to Slack
3. **Gemini API Key** - For AI-powered threat analysis
4. **Database Credentials** - For PostgreSQL database access

### Setup Instructions

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` and add your actual credentials:
   - Never share or commit this file
   - Keep it in your local development environment only

3. Verify `.env` is in `.gitignore`:
   ```bash
   git check-ignore .env
   ```
   This should output: `.env`

### Getting API Keys

#### Jira API Token
1. Go to https://id.atlassian.com/manage-profile/security/api-tokens
2. Click "Create API token"
3. Copy the token to your `.env` file

#### Slack Bot Token
1. Go to https://api.slack.com/apps
2. Create a new app or select existing
3. Go to "OAuth & Permissions"
4. Copy the "Bot User OAuth Token" (starts with `xoxb-`)

#### Gemini API Key
1. Go to https://makersuite.google.com/app/apikey
2. Create a new API key
3. Copy to your `.env` file

### Security Best Practices

- ✅ Always use environment variables for sensitive data
- ✅ Keep `.env` in `.gitignore`
- ✅ Use `.env.example` as a template (with placeholder values)
- ✅ Rotate API keys regularly
- ✅ Use different keys for development and production
- ❌ Never hardcode credentials in source code
- ❌ Never commit `.env` files
- ❌ Never share API keys in chat, email, or screenshots

### If Credentials Are Exposed

If you accidentally commit credentials:

1. **Immediately revoke/regenerate** all exposed API keys
2. Remove the commit from Git history:
   ```bash
   git filter-branch --force --index-filter \
   "git rm --cached --ignore-unmatch .env" \
   --prune-empty --tag-name-filter cat -- --all
   ```
3. Force push (if already pushed):
   ```bash
   git push origin --force --all
   ```
4. Update `.env` with new credentials
