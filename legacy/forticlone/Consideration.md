# BeyondVPN Considerations

## Frontend-Only Limitations

- OTP is currently a frontend verification step because this pass does not change backend code.
- Real email delivery requires backend support through an email provider such as SMTP, Resend, SendGrid, or another transactional email service.
- Remember-me currently stores the authenticated session in browser local storage. A production version should use a secure refresh-token flow with expiry and revocation.
- The web app cannot change the computer public IP or DNS by itself. Real VPN routing requires desktop, Android, or OS-level VPN integration.

## Registration Contract

The web form now collects email, mobile number, first name, middle name, last name, gender, password, and confirm password. Full encrypted-at-rest persistence for these new fields should be completed in the backend contract when backend work is in scope.

## VPN Status

Country up/down status is inferred from available server records and latency values. The realtime chart samples the currently loaded server inventory every few seconds. A production-grade implementation should use backend health checks per VPN node and return explicit status fields.

## Admin VPN Source Management

The admin UI now supports OVPN/OpenVPN paths, WireGuard paths, and free internet config URLs through existing backend endpoints. The backend currently accepts only `openvpn` and `wireguard` protocol values, so the free internet option still maps to one of those protocols while using a URL as the source.

## Security Follow-Up

- Move OTP generation and verification to the backend.
- Send OTP through verified email delivery.
- Add OTP expiry, retry limits, and lockout rules.
- Avoid long-lived tokens in local storage for high-security deployments.
- Add audit logs for login, OTP verification, registration, role changes, and VPN connection actions.
- Require confirmation before destructive admin actions such as deleting VPN sources.

## Product Follow-Up

- Replace the CSS-based logo with a final brand asset if required.
- Add a proper onboarding state when no servers are available.
- Add exact country flags only if licensing and asset source are clear.
- Add accessibility review for keyboard navigation, focus states, and screen-reader labels.
