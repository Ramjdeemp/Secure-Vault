# Secure Vault

A zero-knowledge encrypted notes application. The server stores only ciphertext — your notes cannot be read by anyone but you, including the server operator.

## How it works

Secure Vault uses a client-side-only encryption model:

- Your password never leaves your browser
- Notes are encrypted with AES-GCM before being sent to the server
- Each note gets a unique master key, wrapped with your device's RSA public key
- The server receives and stores only encrypted blobs it cannot decrypt
- Account recovery is handled via a 12-word recovery phrase generated at registration

## Security model

| What the server stores | What the server never sees |
|---|---|
| Encrypted note blobs | Your password |
| Salts and auth verifiers | Your note contents |
| Wrapped (encrypted) keys | Your private key |

**Crypto primitives used:** PBKDF2 (250,000 iterations, SHA-256) · AES-GCM 256-bit · RSA-OAEP 2048-bit

## Tech stack

- **Frontend:** Vanilla JS, Web Crypto API
- **Backend:** Node.js, Express
- **Database:** MySQL

## Setup

```bash
# 1. Clone the repo
git clone https://github.com/Ramjdeemp/Secure-Vault.git
cd Secure-Vault

# 2. Set up the database
mysql -u root -p < schema.sql

# 3. Configure environment
cd backend
cp .env.example .env
# Fill in your DB credentials and JWT secret in .env

# 4. Install and run
npm install
node server.js
```

## Current limitations

- Sharing notes between users is not yet implemented
- Single-device per account (multi-device sync planned)
- Self-hosted only — no public deployment yet
