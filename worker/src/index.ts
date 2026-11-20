// Cloudflare Worker + D1 port of src/vaultlet/server.py. Same routes, same JSON, same status codes,
// so the existing `vaultlet sync` client talks to it unchanged. See server.py for the rationale.

export interface Env {
  DB: D1Database;
  VAULTLET_REGISTER_TOKEN?: string;
}

const MAX_BODY = 16 * 1024 * 1024;
const FREE = 5, MAX_WAIT = 900;
const KDF_LIMITS: Record<string, [number, number]> = {
  time_cost: [1, 50], memory_kib: [8, 4 * 1024 * 1024], parallelism: [1, 64],
};

class HttpError extends Error {
  constructor(public status: number, public detail: unknown, public headers: Record<string, string> = {}) {
    super(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
}

const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

const now = () => Date.now() / 1000;
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

function constantEq(a: string, b: string): boolean {
  const x = new TextEncoder().encode(a), y = new TextEncoder().encode(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}

function b64decode(text: unknown): Uint8Array<ArrayBuffer> | null {
  if (typeof text !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text)) return null;
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

async function hash(key: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", key));
  return [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function decodeKey(text: unknown): Uint8Array<ArrayBuffer> {
  const key = b64decode(text);
  if (!key || key.length !== 32) throw new HttpError(400, "auth_key must be 32 bytes, base64");
  return key;
}

function checkBlob(blob: unknown): string {
  const bad = (msg: string) => new HttpError(422, `not a vault file: ${msg}`);
  if (!isObject(blob) || !["version", "kdf", "wrapped_key", "vault"].every((k) => k in blob))
    throw bad("vault file is missing required fields");
  const kdf = blob.kdf;
  if (!isObject(kdf)) throw bad("vault KDF parameters are malformed");
  for (const [name, [low, high]] of Object.entries(KDF_LIMITS)) {
    const v = kdf[name];
    if (typeof v !== "number" || !Number.isInteger(v) || v < low || v > high)
      throw bad(`vault KDF parameter ${name} is out of range`);
  }
  if ((kdf.memory_kib as number) < 8 * (kdf.parallelism as number)) throw bad("vault KDF memory is too small for its parallelism");
  if (typeof kdf.salt !== "string") throw bad("vault KDF salt is missing");
  return JSON.stringify(blob);
}

async function jsonBody(request: Request): Promise<Record<string, unknown>> {
  const size = request.headers.get("content-length");
  if (size === null) throw new HttpError(411, "Content-Length required");
  if (!/^\d+$/.test(size) || Number(size) > MAX_BODY) throw new HttpError(413, "request too large");
  let data: unknown;
  try {
    data = JSON.parse(await request.text());
  } catch {
    throw new HttpError(400, "body must be JSON");
  }
  if (!isObject(data)) throw new HttpError(400, "body must be a JSON object");
  return data;
}

// Throttle: same backoff as server.py, persisted in D1.
async function throttleCheck(db: D1Database, key: string) {
  const row = await db.prepare("SELECT until FROM throttle WHERE key = ?").bind(key).first<{ until: number }>();
  const wait = (row?.until ?? 0) - now();
  if (wait > 0)
    throw new HttpError(429, "too many failed attempts; try again later", { "Retry-After": String(Math.floor(wait) + 1) });
}

async function throttleFailed(db: D1Database, key: string) {
  const row = await db.prepare("SELECT count FROM throttle WHERE key = ?").bind(key).first<{ count: number }>();
  const count = (row?.count ?? 0) + 1;
  const until = count >= FREE ? now() + Math.min(2 ** (count - FREE), MAX_WAIT) : 0;
  await db.prepare("INSERT INTO throttle (key, count, until) VALUES (?, ?, ?) " +
    "ON CONFLICT(key) DO UPDATE SET count = excluded.count, until = excluded.until").bind(key, count, until).run();
}

const throttleOk = (db: D1Database, key: string) => db.prepare("DELETE FROM throttle WHERE key = ?").bind(key).run();

type Account = { auth_hash: string; version: number; blob: string };

async function row(db: D1Database, account: string): Promise<Account> {
  const found = await db.prepare("SELECT auth_hash, version, blob FROM accounts WHERE id = ?").bind(account).first<Account>();
  if (!found) throw new HttpError(404, "no such account");
  return found;
}

async function authorize(db: D1Database, account: string, header: string | null): Promise<Account> {
  const found = await row(db, account);
  await throttleCheck(db, account); // before comparing, so a locked account can't be probed at all
  const h = header ?? "", i = h.indexOf(" ");
  const scheme = i < 0 ? h : h.slice(0, i), key = b64decode(i < 0 ? "" : h.slice(i + 1));
  if (scheme.toLowerCase() !== "bearer" || !key || !constantEq(await hash(key), found.auth_hash)) {
    await throttleFailed(db, account);
    throw new HttpError(401, "bad auth key", { "WWW-Authenticate": "Bearer" });
  }
  await throttleOk(db, account);
  return found;
}

async function route(request: Request, env: Env): Promise<Response> {
  const db = env.DB, m = request.method;
  const [v1, accounts, account, action, ...rest] = new URL(request.url).pathname.split("/").filter(Boolean);
  if (v1 !== "v1" || accounts !== "accounts" || rest.length) throw new HttpError(404, "Not Found");

  if (!account && m === "POST") {
    const token = env.VAULTLET_REGISTER_TOKEN;
    if (!token) throw new HttpError(403, "registration is disabled on this server");
    await throttleCheck(db, "register");
    if (!constantEq(request.headers.get("x-register-token") ?? "", token)) {
      await throttleFailed(db, "register");
      throw new HttpError(403, "wrong registration token");
    }
    await throttleOk(db, "register");
    const data = await jsonBody(request);
    const authHash = await hash(decodeKey(data.auth_key)), blob = checkBlob(data.blob);
    const id = crypto.randomUUID().replaceAll("-", "");
    await db.prepare("INSERT INTO accounts (id, auth_hash, version, blob) VALUES (?, ?, 1, ?)").bind(id, authHash, blob).run();
    return json({ account: id, version: 1 }, 201);
  }

  if (account && action === "kdf" && m === "GET")
    return json({ kdf: JSON.parse((await row(db, account)).blob).kdf });

  if (account && action === "vault" && m === "GET") {
    const { version, blob } = await authorize(db, account, request.headers.get("authorization"));
    return json({ version, blob: JSON.parse(blob) });
  }

  if (account && action === "vault" && m === "PUT") {
    const data = await jsonBody(request);
    const base = data.base_version;
    if (typeof base !== "number" || !Number.isInteger(base)) throw new HttpError(400, "base_version must be an integer");
    const blob = checkBlob(data.blob);
    await authorize(db, account, request.headers.get("authorization"));
    // New auth key rides along when the master password or KDF changed.
    const newHash = "auth_key" in data ? await hash(decodeKey(data.auth_key)) : null;
    // Compare-and-swap: a stale base_version gets 409 and the client merges.
    const { meta } = await db.prepare("UPDATE accounts SET blob = ?, version = version + 1, " +
      "auth_hash = COALESCE(?, auth_hash) WHERE id = ? AND version = ?").bind(blob, newHash, account, base).run();
    const current = (await row(db, account)).version;
    if (!meta.changes)
      throw new HttpError(409, { error: "vault changed on the server; pull and merge first", version: current });
    return json({ version: current });
  }

  throw new HttpError(404, "Not Found");
}

export default {
  async fetch(request, env): Promise<Response> {
    try {
      return await route(request, env);
    } catch (e) {
      if (e instanceof HttpError) return json({ detail: e.detail }, e.status, e.headers);
      console.error(e);
      return json({ detail: "Internal Server Error" }, 500);
    }
  },
} satisfies ExportedHandler<Env>;
