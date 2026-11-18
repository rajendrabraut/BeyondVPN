"""Tunnel IP address management per gateway."""
from __future__ import annotations

import ipaddress

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Peer, Server


class PoolExhausted(Exception):
    pass


def gateway_ip(server: Server) -> str:
    net = ipaddress.ip_network(server.tunnel_cidr, strict=False)
    return str(net.network_address + 1)


def allocate(db: Session, server: Server) -> str:
    """Lowest free host address; .1 is reserved for the gateway (DNS resolver)."""
    net = ipaddress.ip_network(server.tunnel_cidr, strict=False)
    used = set(db.execute(select(Peer.tunnel_ip).where(Peer.server_id == server.id)).scalars())
    reserved = {gateway_ip(server)}
    for host in net.hosts():
        ip = str(host)
        if ip not in used and ip not in reserved:
            return ip
    raise PoolExhausted(server.id)
