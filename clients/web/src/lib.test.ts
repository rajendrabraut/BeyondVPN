import { describe, expect, it } from "vitest";
import { buildWgConfig, flag, formatBytes, generateWgKeypair, parseDomains, publicFromPrivate } from "./lib";

const conn = (over: Partial<Record<string, unknown>> = {}) => ({
  session_id: "s",
  address: "10.8.0.2/32",
  dns: ["10.8.0.1"],
  mtu: 1420,
  peer_public_key: generateWgKeypair().publicKey,
  preshared_key: generateWgKeypair().publicKey,
  endpoint: "in-mum-1.vpn.example.com:51820",
  allowed_ips: ["0.0.0.0/0", "::/0"],
  persistent_keepalive: 25,
  ...over,
});

describe("lib", () => {
  it("formats bytes", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(5 * 1024 ** 3)).toBe("5.0 GB");
    expect(formatBytes(null)).toBe("—");
  });

  it("generates WireGuard-compatible keys", () => {
    const kp = generateWgKeypair();
    expect(kp.publicKey).toHaveLength(44);
    expect(publicFromPrivate(kp.privateKey)).toBe(kp.publicKey);
  });

  it("matches RFC 7748 X25519 vector", () => {
    const priv = Uint8Array.from("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a".match(/../g)!.map((h) => parseInt(h, 16)));
    const pub = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const got = Uint8Array.from(atob(publicFromPrivate(btoa(String.fromCharCode(...priv)))), (c) => c.charCodeAt(0));
    expect(Array.from(got, (b) => b.toString(16).padStart(2, "0")).join("")).toBe(pub);
  });

  it("builds a config and rejects injection", () => {
    const kp = generateWgKeypair();
    const cfg = buildWgConfig(kp.privateKey, conn());
    expect(cfg).toContain("[Interface]");
    expect(cfg).toContain("AllowedIPs = 0.0.0.0/0, ::/0");
    expect(cfg).toContain("DNS = 10.8.0.1");
    expect(() => buildWgConfig(kp.privateKey, conn({ endpoint: "x:1\nPostUp = evil" }))).toThrow();
  });

  it("flags and domain parsing", () => {
    expect(flag("IN")).toBe("🇮🇳");
    expect(flag("x")).toBe("🌐");
    expect(parseDomains("Ads.example.com.\ntracker.io, ads.example.com")).toEqual(["ads.example.com", "tracker.io"]);
  });
});
