# Single sign-on (OpenID Connect)

The control plane signs users in through any OpenID Connect provider: Microsoft Entra ID
(Azure AD), Google Workspace, Okta, Keycloak, Auth0, JumpCloud, ... SAML-only identity providers
can be bridged through an OIDC broker such as Keycloak until native SAML lands (THINGS_REMAINING.md).

## 1. Register Beyond VPN at the IdP

| Setting | Value |
|---|---|
| Application type | Web, confidential client |
| Redirect URI | `https://<BEYOND_DOMAIN>/api/v1/auth/sso/<provider-id>/callback` |
| Grant | Authorization code (PKCE is always sent) |
| Scopes | `openid email profile` |

Microsoft Entra ID issuer: `https://login.microsoftonline.com/<tenant-id>/v2.0`.
Google Workspace issuer: `https://accounts.google.com`. Okta: `https://<org>.okta.com` (or the
custom authorization server URL).

## 2. Configure the control plane

`BEYOND_OIDC_PROVIDERS` (JSON list) or `BEYOND_OIDC_PROVIDERS_FILE` (path to the same JSON):

```json
[
  {
    "id": "corp",
    "name": "Contoso (Microsoft)",
    "issuer": "https://login.microsoftonline.com/<tenant-id>/v2.0",
    "client_id": "<application-id>",
    "allowed_domains": ["contoso.com"],
    "auto_create": true,
    "default_role": "user"
  }
]
```

Put the secret in `BEYOND_OIDC_SECRET_CORP` (provider id upper-cased, `-` becomes `_`) instead of
the JSON. Optional keys: `scopes`, `token_auth` (`client_secret_basic` default, or
`client_secret_post`).

`BEYOND_PUBLIC_URL` must be the public `https://` URL (it builds the redirect URI), and the portal
origin must be in `BEYOND_CORS_ORIGINS` (SSO only redirects back to those origins, the public URL,
or `BEYOND_SSO_APP_REDIRECTS`, default `beyondvpn://sso`, for the desktop/mobile apps).

## 3. Rules the control plane enforces

- ID token signature (JWKS), `iss`, `aud`, `exp`, `nonce`; state is single-use and expires in 10 min.
- `email_verified: false` is rejected. `allowed_domains` limits who may sign in.
- An **existing** password account is linked to the SSO identity only when the provider has
  `allowed_domains` containing that email's domain (the IdP is authoritative for it). Otherwise
  the user gets "account exists; sign in with your password", which blocks account takeover
  through an IdP that lets users choose any email.
- New SSO users get no usable password, and must accept the activity-logging notice on first
  sign-in (HTTP 428 `logging_consent_required` until they do).
- MFA for SSO users is the IdP's job (enforce it with Conditional Access / sign-on policies).
- The browser receives a one-time code in the URL **fragment** (never sent to servers), valid
  for 2 minutes, exchanged at `POST /api/v1/auth/sso/exchange` for normal tokens.

## 4. Clients

- Web portal: "Sign in with <name>" buttons appear automatically.
- Desktop/mobile: open `/api/v1/auth/sso/<id>/start?return_to=beyondvpn://sso` in the system
  browser (`ASWebAuthenticationSession` / Custom Tabs), catch the `beyondvpn://sso#sso_code=...`
  redirect and POST the code. (Wiring in the desktop and Android apps is still to do.)
