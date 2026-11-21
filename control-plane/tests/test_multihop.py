"""Multi-hop (entry -> exit) routing and stealth-port advertisement."""
from __future__ import annotations

from beyond_cp.wgkeys import generate_keypair

from .conftest import gw_h, make_server, register_device


def hb(client, sid, key, hop=True, stealth=None):
    body = {"public_key": generate_keypair()[1], "listen_port": 51820, "active_peers": 0, "load": 0.1, "version": "test"}
    if hop:
        body["hop_public_key"] = generate_keypair()[1]
    if stealth:
        body["stealth_port"] = stealth
    r = client.post("/api/v1/gateway/heartbeat", headers=gw_h(sid, key), json=body)
    assert r.status_code == 200, r.text
    return body


def test_multihop_routes_peer_through_exit(client, admin_h, user):
    _, h = user
    k_in = make_server(client, admin_h, "in-mum-1", online=False)
    k_ch = make_server(client, admin_h, "ch-zrh-1", online=False)
    entry_hb = hb(client, "in-mum-1", k_in, stealth=443)
    hb(client, "ch-zrh-1", k_ch)
    servers = {s["id"]: s for s in client.get("/api/v1/servers", headers=h).json()}
    assert servers["in-mum-1"]["multihop_entry"] and servers["in-mum-1"]["stealth_port"] == 443

    dev, pub = register_device(client, h)
    r = client.post("/api/v1/sessions/connect", headers=h, json={"device_id": dev, "server_id": "in-mum-1", "exit_server_id": "ch-zrh-1"})
    assert r.status_code == 200, r.text
    assert r.json()["exit_server_id"] == "ch-zrh-1" and r.json()["stealth_port"] == 443

    entry = client.get("/api/v1/gateway/peers", headers=gw_h("in-mum-1", k_in)).json()
    assert entry["peers"][0]["public_key"] == pub and entry["peers"][0]["exit_server_id"] == "ch-zrh-1"
    assert len(entry["hops"]) == 1
    hop = entry["hops"][0]
    assert hop["exit_server_id"] == "ch-zrh-1" and hop["slot"] == 1 and hop["endpoint"].endswith(":51820")

    exit_ = client.get("/api/v1/gateway/peers", headers=gw_h("ch-zrh-1", k_ch)).json()
    assert exit_["peers"] == []
    assert exit_["hop_peers"] == [
        {"public_key": entry_hb["hop_public_key"], "preshared_key": hop["preshared_key"], "tunnel_ip": hop["address"], "user_id": "", "device_id": "hop:in-mum-1"}
    ]

    # Exit's own clients never get the hop link's tunnel IP.
    _, h2 = user[0], h
    dev2, _ = register_device(client, h2, platform="linux")
    ip2 = client.post("/api/v1/sessions/connect", headers=h2, json={"device_id": dev2, "server_id": "ch-zrh-1"}).json()["address"]
    assert ip2 != f"{hop['address']}/32"

    # Reconnecting without an exit drops the route and the uplink.
    client.post("/api/v1/sessions/connect", headers=h, json={"device_id": dev, "server_id": "in-mum-1"})
    entry = client.get("/api/v1/gateway/peers", headers=gw_h("in-mum-1", k_in)).json()
    assert entry["peers"][0]["exit_server_id"] is None and entry["hops"] == []


def test_multihop_validation(client, admin_h, user):
    _, h = user
    k_in = make_server(client, admin_h, "in-mum-1", online=False)
    k_ch = make_server(client, admin_h, "ch-zrh-1", online=False)
    hb(client, "in-mum-1", k_in, hop=False)
    hb(client, "ch-zrh-1", k_ch)
    dev, _ = register_device(client, h)
    connect = lambda **kw: client.post("/api/v1/sessions/connect", headers=h, json={"device_id": dev, **kw})  # noqa: E731
    assert connect(server_id="in-mum-1", exit_server_id="in-mum-1").status_code == 422
    assert connect(server_id="in-mum-1", exit_server_id="nope").status_code == 404
    assert connect(server_id="in-mum-1", exit_server_id="ch-zrh-1").status_code == 409  # entry lacks hop key
    make_server(client, admin_h, "de-fra-1", online=False)  # never heartbeats => offline
    hb(client, "in-mum-1", k_in)
    assert connect(server_id="in-mum-1", exit_server_id="de-fra-1").status_code == 503
