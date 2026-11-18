import time

from sqlalchemy import update

from beyond_cp import db as dbmod
from beyond_cp.models import AuditEvent

from .conftest import USER_PW, bearer, gw_h, login, make_server, make_user, register_device


def _connect(client, h, sid="in-mum-1"):
    dev, pub = register_device(client, h)
    c = client.post("/api/v1/sessions/connect", headers=h, json={"device_id": dev, "server_id": sid}).json()
    return dev, pub, c["address"].split("/")[0]


def test_gateway_auth(client, admin_h):
    key = make_server(client, admin_h)
    assert client.get("/api/v1/gateway/peers").status_code == 401
    assert client.get("/api/v1/gateway/peers", headers=gw_h("in-mum-1", "wrong")).status_code == 401
    assert client.get("/api/v1/gateway/peers", headers=gw_h("nope", key)).status_code == 401
    body = client.get("/api/v1/gateway/peers", headers=gw_h("in-mum-1", key)).json()
    assert body["logging_mode"] == "full" and len(body["signing_public_key"]) == 44
    rot = client.post("/api/v1/admin/servers/in-mum-1/rotate-key", headers=admin_h).json()["gateway_key"]
    assert client.get("/api/v1/gateway/peers", headers=gw_h("in-mum-1", key)).status_code == 401
    assert client.get("/api/v1/gateway/peers", headers=gw_h("in-mum-1", rot)).status_code == 200


def test_usage_attribution_and_data_cap(client, admin_h):
    key = make_server(client, admin_h)
    email, h = make_user(client)
    _, pub, _ = _connect(client, h)
    r = client.post("/api/v1/gateway/usage", headers=gw_h("in-mum-1", key), json={"samples": [{"public_key": pub, "rx_bytes": 1000, "tx_bytes": 5000, "last_handshake": int(time.time())}, {"public_key": "unknown", "rx_bytes": 1, "tx_bytes": 1}]})
    assert r.json()["accepted"] == 1
    u = client.get("/api/v1/me/usage", headers=h).json()
    # Gateway tx (5000) is what the user downloaded.
    assert u["days"][0]["rx_bytes"] == 5000 and u["days"][0]["tx_bytes"] == 1000
    assert u["month_total_bytes"] == 6000
    sess = client.get("/api/v1/me/sessions", headers=h).json()[0]
    assert sess["rx_bytes"] == 5000
    # Admin applies a 5 KB cap -> peer dropped, user listed as revoked, new connects refused.
    uid = client.get("/api/v1/me", headers=h).json()["id"]
    client.patch(f"/api/v1/admin/users/{uid}", headers=admin_h, json={"data_cap_bytes": 5000})
    peers = client.get("/api/v1/gateway/peers", headers=gw_h("in-mum-1", key)).json()
    assert peers["peers"] == [] and uid in peers["revoked_subjects"]
    dev2, _ = register_device(client, h)
    assert client.post("/api/v1/sessions/connect", headers=h, json={"device_id": dev2, "server_id": "in-mum-1"}).status_code == 403
    client.patch(f"/api/v1/admin/users/{uid}", headers=admin_h, json={"clear_data_cap": True})
    assert client.post("/api/v1/sessions/connect", headers=h, json={"device_id": dev2, "server_id": "in-mum-1"}).status_code == 200


def test_dns_logs_attributed_by_tunnel_ip_not_gateway_claims(client, admin_h):
    key = make_server(client, admin_h)
    _, h = make_user(client)
    _, h_other = make_user(client)
    other_id = client.get("/api/v1/me", headers=h_other).json()["id"]
    _, _, ip = _connect(client, h)
    entries = [
        {"client_ip": ip, "user_id": other_id, "domain": "Example.COM", "qtype": "A", "blocked": False, "ts": int(time.time())},
        {"client_ip": ip, "domain": "ads.tracker.test", "qtype": "A", "blocked": True, "ts": int(time.time()) + 999999},
        {"client_ip": "10.9.9.9", "domain": "orphan.test", "qtype": "AAAA", "blocked": False, "ts": int(time.time())},
    ]
    assert client.post("/api/v1/gateway/dns-logs", headers=gw_h("in-mum-1", key), json={"entries": entries}).json()["accepted"] == 3
    mine = client.get("/api/v1/me/activity", headers=h).json()["dns"]
    assert {d["domain"] for d in mine} == {"example.com", "ads.tracker.test"}
    assert client.get("/api/v1/me/activity", headers=h_other).json()["dns"] == []
    logs = client.get("/api/v1/admin/logs/dns", headers=admin_h, params={"blocked": True}).json()
    assert [l["domain"] for l in logs] == ["ads.tracker.test"]
    top = client.get("/api/v1/admin/reports/top-domains", headers=admin_h).json()
    assert {t["domain"] for t in top} >= {"example.com", "ads.tracker.test"}


def test_logging_modes(client, admin_h):
    key = make_server(client, admin_h)
    _, h = make_user(client)
    _, _, ip = _connect(client, h)
    uid = client.get("/api/v1/me", headers=h).json()["id"]
    web = {"entries": [{"user_id": uid, "host": "news.example", "port": 443, "bytes_up": 10, "bytes_down": 90, "ts": int(time.time()), "duration_ms": 5, "blocked": False}]}
    dns = {"entries": [{"client_ip": ip, "domain": "news.example", "qtype": "A", "blocked": False, "ts": int(time.time())}]}
    client.put("/api/v1/admin/policy", headers=admin_h, json={"logging_mode": "metadata"})
    assert client.post("/api/v1/gateway/dns-logs", headers=gw_h("in-mum-1", key), json=dns).json()["accepted"] == 0
    client.post("/api/v1/gateway/proxy-logs", headers=gw_h("in-mum-1", key), json=web)
    act = client.get("/api/v1/me/activity", headers=h).json()
    assert act["dns"] == [] and act["web"][0]["host"] == "-"
    client.put("/api/v1/admin/policy", headers=admin_h, json={"logging_mode": "off"})
    client.post("/api/v1/gateway/proxy-logs", headers=gw_h("in-mum-1", key), json=web)
    assert len(client.get("/api/v1/me/activity", headers=h).json()["web"]) == 1
    # Usage is still metered in "off" mode (billing/quota), only destinations are dropped.
    assert client.get("/api/v1/me/usage", headers=h).json()["month_total_bytes"] == 200


def test_rbac(client, admin_h):
    email, h = make_user(client)
    assert client.get("/api/v1/admin/users", headers=h).status_code == 403
    uid = client.get("/api/v1/me", headers=h).json()["id"]
    client.patch(f"/api/v1/admin/users/{uid}", headers=admin_h, json={"role": "auditor"})
    h = bearer(login(client, email, USER_PW))
    assert client.get("/api/v1/admin/users", headers=h).status_code == 200
    assert client.put("/api/v1/admin/policy", headers=h, json={"logging_mode": "off"}).status_code == 403
    me_admin = client.get("/api/v1/me", headers=admin_h).json()["id"]
    assert client.patch(f"/api/v1/admin/users/{me_admin}", headers=admin_h, json={"is_active": False}).status_code == 400


def test_disable_user_cuts_access(client, admin_h):
    key = make_server(client, admin_h)
    email, h = make_user(client)
    t = login(client, email, USER_PW)
    _connect(client, h)
    uid = client.get("/api/v1/me", headers=h).json()["id"]
    client.patch(f"/api/v1/admin/users/{uid}", headers=admin_h, json={"is_active": False})
    assert client.get("/api/v1/me", headers=h).status_code == 401
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": t["refresh_token"]}).status_code == 401
    peers = client.get("/api/v1/gateway/peers", headers=gw_h("in-mum-1", key)).json()
    assert peers["peers"] == [] and uid in peers["revoked_subjects"]


def test_policy_validation(client, admin_h):
    assert client.put("/api/v1/admin/policy", headers=admin_h, json={"logging_mode": "everything"}).status_code == 422
    assert client.put("/api/v1/admin/policy", headers=admin_h, json={"blocked_domains": ["bad domain"]}).status_code == 422
    r = client.put("/api/v1/admin/policy", headers=admin_h, json={"blocked_domains": ["Ads.Example.com.", "ads.example.com", "tracker.io"]})
    assert r.json()["blocked_domains"] == ["ads.example.com", "tracker.io"]


def test_csv_export_guards_formula_injection(client, admin_h):
    key = make_server(client, admin_h)
    _, h = make_user(client)
    uid = client.get("/api/v1/me", headers=h).json()["id"]
    web = {"entries": [{"user_id": uid, "host": "=cmd|' /C calc'!A0", "port": 443, "bytes_up": 1, "bytes_down": 1, "ts": int(time.time()), "duration_ms": 1, "blocked": False}]}
    client.post("/api/v1/gateway/proxy-logs", headers=gw_h("in-mum-1", key), json=web)
    r = client.get("/api/v1/admin/logs/export.csv", headers=admin_h, params={"kind": "web"})
    assert r.status_code == 200 and "text/csv" in r.headers["content-type"]
    assert "'=cmd" in r.text


def test_audit_chain_detects_tampering(client, admin_h):
    make_user(client)
    assert client.get("/api/v1/admin/audit/verify", headers=admin_h).json() == {"ok": True, "first_bad_id": None}
    actions = {a["action"] for a in client.get("/api/v1/admin/audit", headers=admin_h).json()}
    assert {"user.register", "auth.login", "admin.bootstrap"} <= actions
    with dbmod.session() as s:
        s.execute(update(AuditEvent).where(AuditEvent.action == "user.register").values(target="someone-else"))
        s.commit()
    assert client.get("/api/v1/admin/audit/verify", headers=admin_h).json()["ok"] is False


def test_retention_purge(client, admin_h):
    key = make_server(client, admin_h)
    _, h = make_user(client)
    _, _, ip = _connect(client, h)
    old = int(time.time()) - 90 * 86400
    client.post("/api/v1/gateway/dns-logs", headers=gw_h("in-mum-1", key), json={"entries": [{"client_ip": ip, "domain": "old.example", "qtype": "A", "blocked": False, "ts": old}, {"client_ip": ip, "domain": "new.example", "qtype": "A", "blocked": False, "ts": int(time.time())}]})
    from beyond_cp.main import purge_expired

    assert purge_expired(30)["dns"] == 1
    assert [d["domain"] for d in client.get("/api/v1/me/activity", headers=h).json()["dns"]] == ["new.example"]


def test_account_erasure(client, admin_h):
    key = make_server(client, admin_h)
    email, h = make_user(client)
    _, _, ip = _connect(client, h)
    client.post("/api/v1/gateway/dns-logs", headers=gw_h("in-mum-1", key), json={"entries": [{"client_ip": ip, "domain": "x.example", "qtype": "A", "blocked": False, "ts": int(time.time())}]})
    assert client.post("/api/v1/me/erase", headers=h, json={"password": "wrong"}).status_code == 403
    assert client.post("/api/v1/me/erase", headers=h, json={"password": USER_PW}).status_code == 200
    assert client.post("/api/v1/auth/login", json={"email": email, "password": USER_PW}).status_code == 401
    assert client.get("/api/v1/admin/logs/dns", headers=admin_h, params={"domain": "x.example"}).json() == []


def test_summary_report(client, admin_h):
    make_server(client, admin_h)
    s = client.get("/api/v1/admin/reports/summary", headers=admin_h).json()
    assert s["servers_online"] == 1 and s["users"] == 1
