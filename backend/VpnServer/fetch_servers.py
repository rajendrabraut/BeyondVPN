import base64
import json
import os
from pathlib import Path
from typing import Any
from urllib.request import urlopen


BASE_DIR = Path(__file__).resolve().parent
SOURCES_FILE = Path(os.getenv("FORTICLONE_SOURCES_FILE", BASE_DIR / "vpn_sources.json"))
TIMEOUT = 12


def build_server(
    *,
    server_id: str,
    name: str,
    country: str,
    protocol: str,
    latency_ms: int,
    config: str,
    source: str,
    is_free: bool = True,
) -> dict[str, Any]:
    return {
        "id": server_id,
        "name": name,
        "country": country,
        "type": protocol,
        "latencyMs": latency_ms,
        "isFree": is_free,
        "config": config,
        "source": source,
    }


def fetch_vpngate_openvpn(limit: int) -> list[dict[str, Any]]:
    response = fetch_text("https://www.vpngate.net/api/iphone/")

    servers: list[dict[str, Any]] = []
    for line in response.splitlines()[2:]:
        row = line.strip()
        if not row or row.startswith("*"):
            continue

        cols = row.split(",")
        if len(cols) < 15:
            continue

        try:
            config = base64.b64decode(cols[14]).decode("utf-8", errors="ignore")
        except Exception:
            continue

        try:
            latency_ms = int(cols[3])
        except ValueError:
            latency_ms = 999

        servers.append(
            build_server(
                server_id=f"vpngate-{cols[1]}",
                name=f"VPNGate {cols[5]} {cols[0]}",
                country=cols[5] or "Unknown",
                protocol="openvpn",
                latency_ms=latency_ms,
                config=config,
                source="VPNGate",
            )
        )

        if len(servers) >= limit:
            break

    return servers


def parse_manifest_file() -> list[dict[str, Any]]:
    if not SOURCES_FILE.exists():
        return []

    try:
        data = json.loads(SOURCES_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []

    return data.get("sources", []) if isinstance(data, dict) else []


def fetch_remote_config(url: str) -> str:
    return fetch_text(url)


def read_local_config(path_value: str) -> str:
    target = Path(path_value)
    if not target.is_absolute():
        target = BASE_DIR / path_value
    return target.read_text(encoding="utf-8")


def fetch_manifest_sources(limit: int) -> list[dict[str, Any]]:
    servers: list[dict[str, Any]] = []

    for entry in parse_manifest_file():
        if len(servers) >= limit:
            break

        try:
            protocol = str(entry.get("protocol", "")).strip().lower()
            if protocol not in {"openvpn", "wireguard"}:
                continue

            config = ""
            if entry.get("url"):
                config = fetch_remote_config(str(entry["url"]))
            elif entry.get("path"):
                config = read_local_config(str(entry["path"]))

            if not config.strip():
                continue

            servers.append(
                build_server(
                    server_id=str(entry.get("id") or f"{protocol}-{len(servers) + 1}"),
                    name=str(entry.get("name") or f"{protocol.title()} node"),
                    country=str(entry.get("country") or "Unknown"),
                    protocol=protocol,
                    latency_ms=int(entry.get("latencyMs") or 50),
                    config=config,
                    source=str(entry.get("source") or "Manifest"),
                    is_free=bool(entry.get("isFree", True)),
                )
            )
        except Exception:
            continue

    return servers


def fetch_env_sources(limit: int) -> list[dict[str, Any]]:
    servers: list[dict[str, Any]] = []
    sources = [
        ("wireguard", os.getenv("FORTICLONE_WIREGUARD_URLS", "")),
        ("openvpn", os.getenv("FORTICLONE_OPENVPN_URLS", "")),
    ]

    for protocol, raw_urls in sources:
        if not raw_urls:
            continue

        for index, url in enumerate([part.strip() for part in raw_urls.split(",") if part.strip()], start=1):
            if len(servers) >= limit:
                return servers

            try:
                config = fetch_remote_config(url)
                servers.append(
                    build_server(
                        server_id=f"{protocol}-env-{index}",
                        name=f"{protocol.title()} imported {index}",
                        country="Unknown",
                        protocol=protocol,
                        latency_ms=40,
                        config=config,
                        source="Environment",
                    )
                )
            except Exception:
                continue

    return servers


def fetch_vpn_sources() -> list[dict[str, Any]]:
    servers: list[dict[str, Any]] = []

    if os.getenv("FORTICLONE_ENABLE_VPNGATE", "").strip() == "1":
        try:
            servers.extend(fetch_vpngate_openvpn(limit=12))
        except Exception:
            pass

    servers.extend(fetch_manifest_sources(limit=8))
    servers.extend(fetch_env_sources(limit=8))

    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()

    for server in servers:
        if server["id"] in seen:
            continue
        seen.add(server["id"])
        deduped.append(server)

    return deduped


def fetch_text(url: str) -> str:
    with urlopen(url, timeout=TIMEOUT) as response:
        return response.read().decode("utf-8", errors="ignore")


if __name__ == "__main__":
    print(json.dumps(fetch_vpn_sources()))
