## Nulla, an identity-less, end-to-end encrypted communication system.

**Nulla** is a web-based, identity-less messaging platform designed to enable private communication without usernames, profiles, or personal data. Accounts are defined purely by cryptographic material, and all messages are end-to-end encrypted so that only the intended participants can read them. 

---

## Security Model

- Messages are encrypted client-side before being sent to the server.
- Encryption uses authenticated ephemeral Diffie-Hellman key exchange.
- Session keys are derived locally using HKDF.
- Separate send and receive keys are derived per session.
- Messages are encrypted using AES-GCM.
- The server never has access to private keys, session keys or plaintext messages.
- Public signing keys are used to authenticate key exchange messages.
- Trust On First Use is used to prevent key substitution attacks.
- No analytics or tracking is performed.

---

## Threat Model

This project is designed to protect against:
- Server-side data breaches.
- Network-level attackers.
- Message tampering and replay attacks.
- Unauthorized access without possession of cryptographic keys.

---

## Design Decisions

- No usernames, emails, or profiles, identity is reduced to cryptographic keys.
- Client-side encryption to minimize server trust.
- Authenticated key exchange to prevent man-in-the-middle attacks.
- Minimal interface to reduce metadata leakage and user error.
- Explicit security tradeoffs with no security theater.

---

## Why an Identity-less Messenger?

- Eliminates the need for personal identifiers.
- Reduces metadata exposure.
- Prevents account enumeration.
- Makes server compromise significantly less damaging.
- Suitable for privacy-focused and security-aware users.

---

## Tech Stack

- Frontend: HTML, CSS, JavaScript, Web Crypto API.
- Backend: Flask, Python.
- Transport: WebSockets.
- Cryptography: ECDH, ECDSA, HKDF, AES-GCM.

---

## Deploying on Render

Use **one gevent worker** so the same process can handle WebSockets and HTTP at once (otherwise one open WebSocket blocks all API and /logs traffic).

**Start command** (Root Directory = `backend`):

```bash
gunicorn -k gevent -w 1 --worker-connections 50 --timeout 120 --bind 0.0.0.0:$PORT app:app
```

- `-k gevent` — one worker can serve many connections concurrently (no blocking).
- `--worker-connections 50` — up to 50 concurrent connections per worker.
- `--timeout 120` — avoid killing the worker while WebSockets are idle.

For multiple Render instances, set **REDIS_URL** so presence and notifications work across instances.

---

## Installation & Usage

1. Open the [Nulla web app](https://nulla.onrender.com/).
2. Create an account, by generating a local cryptographic identity.
3. Share your contact string with another user.
4. Accept a contact request to establish an encrypted session.
5. Start messaging securely.

Nulla can be installed as a web app for a native-like experience.

---

## Future Improvements

- Multi-device support.
- Optional session key rotation setting.
- Local database encryption with user PIN using argon2.
- Advanced signing key verification to eliminate tofu risks.

---

## License

This project is open source and available under the [MIT License](LICENSE).

---

## Contact

For bug reports, feedback, collaborations, or feature suggestions, reach out via GitHub issues or email:  
`chrisevlidis.main@gmail.com`.

---

**If you find Nulla useful, consider giving the repository a star to support the project.**
