// Control-plane API client. Access token in memory only; refresh token in
// sessionStorage (cleared when the tab closes) — see GUARDRAILS.md.

const BASE: string = (import.meta.env.VITE_API_BASE as string | undefined) ?? "";
let access: string | null = null;
const RT = "beyond.rt";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

function getRefresh(): string | null {
  try {
    return sessionStorage.getItem(RT);
  } catch {
    return null;
  }
}

function setRefresh(t: string | null) {
  try {
    if (t) sessionStorage.setItem(RT, t);
    else sessionStorage.removeItem(RT);
  } catch {
    /* storage unavailable */
  }
}

async function raw(path: string, init: RequestInit = {}, auth = true): Promise<Response> {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  if (auth && access) headers.set("Authorization", `Bearer ${access}`);
  return fetch(`${BASE}/api/v1${path}`, { ...init, headers, credentials: "omit" });
}

async function tryRefresh(): Promise<boolean> {
  const rt = getRefresh();
  if (!rt) return false;
  const r = await raw("/auth/refresh", { method: "POST", body: JSON.stringify({ refresh_token: rt }) }, false);
  if (!r.ok) {
    setRefresh(null);
    return false;
  }
  const t = await r.json();
  access = t.access_token;
  setRefresh(t.refresh_token);
  return true;
}

export async function api<T = unknown>(path: string, init: RequestInit = {}): Promise<T> {
  let r = await raw(path, init);
  if (r.status === 401 && (await tryRefresh())) r = await raw(path, init);
  if (!r.ok) {
    let msg = r.statusText;
    try {
      const j = await r.json();
      msg = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail);
    } catch {
      /* not json */
    }
    throw new ApiError(r.status, msg);
  }
  const ct = r.headers.get("content-type") ?? "";
  return (ct.includes("json") ? r.json() : r.text()) as Promise<T>;
}

export async function apiBlob(path: string): Promise<Blob> {
  let r = await raw(path);
  if (r.status === 401 && (await tryRefresh())) r = await raw(path);
  if (!r.ok) throw new ApiError(r.status, r.statusText);
  return r.blob();
}

export async function login(email: string, password: string, totp?: string): Promise<void> {
  const r = await raw("/auth/login", { method: "POST", body: JSON.stringify({ email, password, totp_code: totp || null }) }, false);
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new ApiError(r.status, j.detail ?? "login failed");
  access = j.access_token;
  setRefresh(j.refresh_token);
}

export async function resume(): Promise<boolean> {
  return tryRefresh();
}

export async function logout(): Promise<void> {
  const rt = getRefresh();
  access = null;
  setRefresh(null);
  if (rt) await raw("/auth/logout", { method: "POST", body: JSON.stringify({ refresh_token: rt }) }, false).catch(() => undefined);
}

export const post = <T = unknown>(p: string, body?: unknown) => api<T>(p, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) });
export const put = <T = unknown>(p: string, body: unknown) => api<T>(p, { method: "PUT", body: JSON.stringify(body) });
export const patch = <T = unknown>(p: string, body: unknown) => api<T>(p, { method: "PATCH", body: JSON.stringify(body) });
export const del = <T = unknown>(p: string) => api<T>(p, { method: "DELETE" });
