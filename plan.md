# BeyondVPN Web Frontend Plan

## Current Focus

The current scope is the web frontend. Backend, Android, and desktop code are intentionally out of scope unless existing backend endpoints already support the required UI action.

## User Goals

- Rename the visible product to BeyondVPN.
- Replace the confusing dashboard with a simple flow that a normal user can understand.
- Show only the VPN name and logo in the login screen.
- Put registration below the login section.
- Add light and dark theme support with a clear theme toggle.
- Add a country-wise VPN selection area with up/down status.
- Add better visual feedback through a realtime non-bar chart for up/down availability.
- Add login remember-me support.
- Add an OTP step after successful login.
- Segregate admin and common user dashboards.
- Give admins a dedicated VPN source management dashboard.
- Let admins add OVPN/OpenVPN, WireGuard, and free internet VPN source URLs.
- Let admins assign users between common user and admin roles.
- Show login, logout, and system messages in a bottom-right modal/toast.
- Remove unnecessary marketing and technical content from the frontend.

## Frontend Flow

1. User opens BeyondVPN.
2. User logs in with username and password.
3. User verifies OTP.
4. Common users land on the user dashboard.
5. Common users select a country.
6. Common users click Connect.
7. Web mode downloads/prepares the VPN profile. Native clients remain responsible for real system routing.

## Admin Flow

1. Admin signs in and verifies OTP.
2. Admin lands on a separate admin dashboard.
3. Admin adds VPN sources through one of three source types:
   - OVPN/OpenVPN local config path
   - WireGuard local config path
   - Free public VPN config URL
4. Admin refreshes backend source inventory.
5. Admin promotes or demotes users between common user and admin.

## Design Direction

- Clean, premium, light-first interface.
- Dark theme available from the same screen.
- Simple language and clear actions.
- Country list on the left, connection action in the main panel.
- No FortiClient or ProtonVPN branding text. The visible brand is BeyondVPN.
