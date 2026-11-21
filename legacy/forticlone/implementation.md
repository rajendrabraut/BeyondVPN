# BeyondVPN Web Frontend Implementation

## Completed In This Pass

- Replaced the old FortiClone/FortiClient-style web copy with BeyondVPN.
- Created a new BeyondVPN logo mark directly in the frontend UI.
- Rebuilt the login screen with a simpler, premium layout.
- Added a light and dark theme toggle.
- Moved registration out of the login page into a dedicated `/register` frontend route.
- Added registration fields in the web UI:
  - Email
  - Mobile number
  - First name
  - Middle name
  - Last name
  - Gender
  - Password
  - Confirm password
- Added frontend password confirmation validation.
- Added remember-me support using browser local storage.
- Added an OTP verification step after password login.
- Added bottom-right toast/modal messages for login, logout, errors, and system events.
- Split authenticated UI into admin and common user dashboards.
- Added an admin dashboard for VPN source administration.
- Added admin UI for three VPN source entry types:
  - OVPN/OpenVPN file path
  - WireGuard config path
  - Free internet VPN config URL
- Reconnected the admin dashboard to existing backend endpoints:
  - `GET /api/vpn/sources`
  - `POST /api/vpn/sources`
  - `DELETE /api/vpn/sources/{id}`
  - `POST /api/servers/refresh`
- Added admin role assignment UI through the existing `POST /api/users/{id}/role` endpoint.
- Simplified the dashboard to focus on:
  - Country selection
  - VPN connection action
  - Connection status
  - Country up/down status
  - Realtime up/down availability chart
- Removed unnecessary web dashboard sections such as posture copy, route-map storytelling, source-control forms, and brand-heavy marketing text.
- Removed bar-style status visualization from the user dashboard and replaced it with SVG line paths.

## Files Changed

- `frontend/web/src/App.tsx`
- `frontend/web/src/index.css`
- `plan.md`
- `implementation.md`
- `Consideration.md`

## Important Scope Note

This pass intentionally avoids backend, Android, and desktop behavior changes. The admin VPN source UI uses existing backend endpoints. The new web registration fields are submitted from the frontend, but full persistent handling for every new field requires a backend contract update in a separate backend-focused pass.
