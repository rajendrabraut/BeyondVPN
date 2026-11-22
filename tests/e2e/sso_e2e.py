"""End-to-end single sign-on: fake OIDC provider (real HTTP) <-> control plane <-> Rust agent.

What it proves (the desktop app does the same steps with a real browser):
  1. /auth/sso/<id>/start redirects to the IdP with PKCE + nonce.
  2. The IdP sends the browser back to the control plane callback, which verifies the signed
     ID token and redirects to beyondvpn://sso?n=<nonce>&sso_code=<code>.
  3. `beyond-agent login-sso --code` needs logging consent (428), then signs in and registers the device.

Usage: python tests/e2e/sso_e2e.py   (repo root; needs `cargo build` and the control-plane venv)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_e2e import ADMIN, AGENT, ROOT, free_port, step, wait_for  # noqa: E402

CLIENT_ID = "beyond-e2e"


def fake_idp(port: int):
    issuer = f"http://127.0.0.1:{port}"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key())) | {"kid": "k1", "use": "sig", "alg": "RS256"}
    codes: dict[str, str] = {}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # quiet
            pass

        def _json(self, obj, code=200):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            u = urlsplit(self.path)
            if u.path == "/.well-known/openid-configuration":
                return self._json({"issuer": issuer, "authorization_endpoint": f"{issuer}/authorize", "token_endpoint": f"{issuer}/token", "jwks_uri": f"{issuer}/jwks"})
            if u.path == "/jwks":
                return self._json({"keys": [jwk]})
            if u.path == "/authorize":  # the user "signs in" instantly
                q = parse_qs(u.query)
                code = os.urandom(8).hex()
                codes[code] = q["nonce"][0]
                self.send_response(302)
                self.send_header("Location", f"{q['redirect_uri'][0]}?{urlencode({'code': code, 'state': q['state'][0]})}")
                self.end_headers()
                return None
            self.send_response(404)
            self.end_headers()
            return None

        def do_POST(self):
            form = parse_qs(self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode())
            nonce = codes.pop(form.get("code", [""])[0], None)
            if nonce is None or "code_verifier" not in form:
                return self._json({"error": "invalid_grant"}, 400)
            now = int(time.time())
            tok = jwt.encode({"iss": issuer, "aud": CLIENT_ID, "sub": "e2e-user", "email": "sso.user@corp.example", "email_verified": True, "iat": now, "exp": now + 300, "nonce": nonce}, key, algorithm="RS256", headers={"kid": "k1"})
            return self._json({"id_token": tok, "access_token": "x", "token_type": "Bearer"})

    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return issuer


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="beyond-sso-e2e-"))
    cp_port, idp_port = free_port(), free_port()
    base = f"http://127.0.0.1:{cp_port}"
    issuer = fake_idp(idp_port)
    providers = [{"id": "corp", "name": "Corp", "issuer": issuer, "client_id": CLIENT_ID, "client_secret": "s", "allowed_domains": ["corp.example"], "allow_insecure_issuer": True}]
    env = {
        **os.environ,
        "BEYOND_DATA_DIR": str(tmp / "cp"),
        "BEYOND_ADMIN_EMAIL": ADMIN[0],
        "BEYOND_ADMIN_PASSWORD": ADMIN[1],
        "BEYOND_PUBLIC_URL": base,
        "BEYOND_OIDC_PROVIDERS": json.dumps(providers),
        "PYTHONPATH": str(ROOT / "control-plane"),
    }
    step("starting control plane with a fake OIDC provider")
    cp = subprocess.Popen([sys.executable, "-m", "uvicorn", "beyond_cp.main:create_app", "--factory", "--port", str(cp_port), "--log-level", "warning"], cwd=ROOT / "control-plane", env=env)
    try:
        wait_for(lambda: httpx.get(f"{base}/healthz").status_code == 200, what="control plane")
        c = httpx.Client(timeout=20)
        assert c.get(f"{base}/api/v1/auth/sso/providers").json() == [{"id": "corp", "name": "Corp"}]

        step("browser leg: start -> IdP -> callback -> beyondvpn:// link")
        nonce = os.urandom(8).hex()
        r = c.get(f"{base}/api/v1/auth/sso/corp/start", params={"return_to": f"beyondvpn://sso?n={nonce}"})
        assert r.status_code == 302 and r.headers["location"].startswith(f"{issuer}/authorize"), r.text
        r = c.get(r.headers["location"])
        assert r.status_code == 302
        r = c.get(r.headers["location"])
        link = r.headers["location"]
        assert r.status_code == 302 and link.startswith(f"beyondvpn://sso?n={nonce}&sso_code="), link
        code = parse_qs(urlsplit(link).query)["sso_code"][0]

        step("agent: login-sso needs consent, then signs in")
        aenv = {**os.environ, "BEYOND_AGENT_DIR": str(tmp / "agent"), "BEYOND_AGENT_DRY_RUN": "1", "RUST_LOG": "warn"}
        run = lambda *a: subprocess.run([str(AGENT), *a], env=aenv, capture_output=True, text=True, timeout=60)  # noqa: E731
        out = run("login-sso", "--api", base, "--code", code)
        assert out.returncode != 0 and "accept-logging" in out.stderr, out.stderr
        out = run("login-sso", "--api", base, "--code", code, "--accept-logging")
        assert out.returncode == 0, out.stderr
        st = run("status").stdout
        assert "sso.user@corp.example" in st, st
        out = run("login-sso", "--api", base, "--code", code, "--accept-logging")
        assert out.returncode != 0, "one-time code must not work twice"
        step("SSO E2E PASSED")
        print("SSO E2E PASSED")
        return 0
    finally:
        cp.terminate()


if __name__ == "__main__":
    raise SystemExit(main())
