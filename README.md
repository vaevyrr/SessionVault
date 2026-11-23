# SessionVault

A small TypeScript demonstration of server-side sessions, signed cookies, expiry, and audit events.

This is a learning project, not a production authentication framework.

## Features

- Random session IDs using Node's Web Crypto-compatible crypto APIs
- HMAC-signed session cookies
- Absolute session expiry
- Login/logout flow
- In-memory session storage
- Basic audit events
- No plaintext password storage

## Run

Node.js 20+.

```bash
npm install
npm run build
npm start
```

The demo binds to 127.0.0.1:3000.

Environment variables:

```text
DEMO_USER=demo
DEMO_PASSWORD=change-me
SESSION_SECRET=replace-with-a-long-random-secret
```

Use a reviewed authentication library or identity provider for real applications.
