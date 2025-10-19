# Access Control • Secure — Interactive SSO Flow (White Theme)

A clean, **white-background** IAM demo that’s actually useful: it simulates a modern SSO flow and teaches how identity signals are used in access decisions.

**Flow:** Credentials → **MFA (TOTP, RFC 6238)** → **Signed JWT (HS256)** with IAM claims → Redirect success  
**Extras:** Claim highlights, policy checks (exp/aud/amr), copy/verify/download token, and an **audit trail** to show governance thinking.

## Why this stands out
- White, resume-friendly UI that embeds beautifully in Notion
- Teaches *why* each step matters (not just a toy demo)
- Adds governance thinking (policy checks + audit log)
- All client-side, no dependencies, no data leaves the browser

## Files
- `index.html` — markup and layout
- `styles.css` — white cyber theme + dark toggle
- `script.js` — TOTP, JWT signing/verification, UI behavior
- `README.md` — instructions

## Configure
Edit `script.js`:
```js
state.totpSecret = "JBSWY3DPEHPK3PXP";            // Base32 TOTP secret
state.jwtSecret  = "andrew-iam-portfolio-demo-key"; // HS256 signing secret (demo)
```

Tune claims in the `payload` object to match your scenario (roles, groups, scopes).

## Deploy (GitHub Pages)
1. Create a public repo (e.g., `enterprise-sso-white`).
2. Upload all four files to the **repo root**.
3. **Settings → Pages → Build and deployment**  
   - Source: *Deploy from a branch*  
   - Branch: `main` • Folder: `/ (root)`
4. Your site: `https://<your-username>.github.io/enterprise-sso-white/`

## Embed in Notion
Type `/embed` and paste the GitHub Pages URL. Set height ~ **800–900px**.  
Suggested caption: *“Try SSO Flow (Interactive): Credentials → TOTP → JWT → Redirect.”*

## Security note
This is an **educational** client-only demo. Real IdPs sign tokens server-side (RS256/ES256) and store secrets in KMS/HSM. Do **not** reuse these secrets in production.

© 2025 Andrew Symister — IAM & PAM Portfolio
