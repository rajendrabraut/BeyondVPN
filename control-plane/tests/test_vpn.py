import jwt

from beyond_cp.wgkeys import generate_keypair

from .conftest import ed25519_pub, gw_h, make_server, make_user, register_device


def test_device_registration_rules(client, user):
    _, h = user
    bad = client.post("/api/v1/devices", headers=h, json={"name": "x", "platform": "windows", "public_key": "notakey"})
    assert bad.status_code == 422
    dev_id, pub = register_device(client, h)
    # Idempotent for the same user + key.
    again = client.post("/api/v1/devices", headers=h, json={"name": "renamed", "platform": "windows", "public_key": pub})
    assert again.status_code == 200 and again.json()["id"] == dev_id and again.json()["name"] == "renamed"
    # Another user cannot claim the key.
    _, h2 = make_user(client)
    assert client.post("/api/v1/devices", headers=h2, json={"name": "x", "platform": "linux", "public_key": pub}).status_code == 409
    assert len(client.get("/api/v1/devices", headers=h).json()) == 1


def test_device_limit(client, admin_h, user):
    _, h = user
    client.put("/api/v1/admin/policy", headers=admin_h, json={"max_devices_per_user": 2})
    register_device(client, h)
    register_device(client, h)
    _, pub = generate_keypair()
    r = client.post("/api/v1/devices", headers=h, json={"name": "3rd", "platform": "android", "public_key": pub})
    assert r.status_code == 403


def test_server_must_be_online(client, admin_h, user):
    _, h = user
    make_server(client, admin_h, "us-nyc-1", online=False)
    servers = client.get("/api/v1/servers", headers=h).json()
    assert servers[0]["status"] == "offline"
    dev, _ = register_device(client, h)
    assert client.post("/api/v1/sessions/connect", headers=h, json={"device_id": dev, "server_id": "us-nyc-1"}).status_code == 503


def test_connect_allocates_stable_unique_ips(client, admin_h):
    make_server(client, admin_h)
    _, h1 = make_user(client)
    _, h2 = make_user(client)
    d1, _ = register_device(client, h1)
    d2, _ = register_device(client, h2)
    c1 = client.post("/api/v1/sessions/connect", headers=h1, json={"device_id": d1, "server_id": "in-mum-1"}).json()
    c2 = client.post("/api/v1/sessions/connect", headers=h2, json={"device_id": d2, "server_id": "in-mum-1"}).json()
    assert c1["address"] == "10.8.0.2/32" and c2["address"] == "10.8.0.3/32"
    assert c1["dns"] == ["10.8.0.1"]
    assert c1["endpoint"] == "in-mum-1.vpn.beyondvpn.example.com:51820"
    assert c1["allowed_ips"] == ["0.0.0.0/0", "::/0"]
    assert len(c1["preshared_key"]) == 44 and c1["preshared_key"] != c2["preshared_key"]
    again = client.post("/api/v1/sessions/connect", headers=h1, json={"device_id": d1, "server_id": "in-mum-1"}).json()
    assert again["address"] == c1["address"] and again["preshared_key"] == c1["preshared_key"]
    # Cannot use someone else's device.
    assert client.post("/api/v1/sessions/connect", headers=h2, json={"device_id": d1, "server_id": "in-mum-1"}).status_code == 404
    # Only one open session per device.
    sessions = client.get("/api/v1/me/sessions", headers=h1).json()
    assert sum(1 for s in sessions if s["ended_at"] is None) == 1


def test_disconnect_and_revoke_remove_peer_from_gateway(client, admin_h, user):
    key = make_server(client, admin_h)
    _, h = user
    dev, pub = register_device(client, h)
    c = client.post("/api/v1/sessions/connect", headers=h, json={"device_id": dev, "server_id": "in-mum-1"}).json()
    peers = client.get("/api/v1/gateway/peers", headers=gw_h("in-mum-1", key)).json()["peers"]
    assert [p["public_key"] for p in peers] == [pub]
    client.post(f"/api/v1/sessions/{c['session_id']}/disconnect", headers=h)
    assert client.get("/api/v1/gateway/peers", headers=gw_h("in-mum-1", key)).json()["peers"] == []
    client.post("/api/v1/sessions/connect", headers=h, json={"device_id": dev, "server_id": "in-mum-1"})
    assert client.delete(f"/api/v1/devices/{dev}", headers=h).status_code == 200
    assert client.get("/api/v1/gateway/peers", headers=gw_h("in-mum-1", key)).json()["peers"] == []
    assert client.post("/api/v1/sessions/connect", headers=h, json={"device_id": dev, "server_id": "in-mum-1"}).status_code == 403


def test_posture_policy(client, admin_h, user):
    make_server(client, admin_h)
    _, h = user
    client.put("/api/v1/admin/policy", headers=admin_h, json={"require_device_posture": True})
    bad, _ = register_device(client, h, posture={"os": "windows", "firewall_enabled": False})
    good, _ = register_device(client, h, posture={"os": "windows", "firewall_enabled": True})
    assert client.post("/api/v1/sessions/connect", headers=h, json={"device_id": bad, "server_id": "in-mum-1"}).status_code == 403
    assert client.post("/api/v1/sessions/connect", headers=h, json={"device_id": good, "server_id": "in-mum-1"}).status_code == 200


def test_proxy_token_is_scoped_to_gateway(client, admin_h, user):
    make_server(client, admin_h)
    _, h = user
    r = client.post("/api/v1/proxy/token", headers=h, json={"server_id": "in-mum-1"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["host"] == "in-mum-1.vpn.beyondvpn.example.com" and body["port"] == 8443
    claims = jwt.decode(body["token"], ed25519_pub(client), algorithms=["EdDSA"], audience="in-mum-1")
    assert claims["typ"] == "proxy"
    # Proxy tokens are not API access tokens.
    assert client.get("/api/v1/me", headers={"Authorization": f"Bearer {body['token']}"}).status_code == 401
    # Session reused on refresh.
    again = client.post("/api/v1/proxy/token", headers=h, json={"server_id": "in-mum-1"}).json()
    assert again["session_id"] == body["session_id"]


def test_browser_platform_can_be_disallowed(client, admin_h, user):
    make_server(client, admin_h)
    _, h = user
    client.put("/api/v1/admin/policy", headers=admin_h, json={"allowed_platforms": ["windows"]})
    assert client.post("/api/v1/proxy/token", headers=h, json={"server_id": "in-mum-1"}).status_code == 403
