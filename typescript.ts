const API = "https://api.kernauth.com";
const APP_ID = "__PUBLIC_APP_ID__";
const KEY_ID = "__KEY_ID__";
const PUBLIC_KEY = "__PUBLIC_KEY__";
declare const process: {
  argv: string[];
  env: Record<string, string | undefined>;
  stdout: { write(value: string): void };
  stdin: { isTTY?: boolean };
};

type EntitlementInfo = { status: string; features: string; license_id: string; expires_at: string };

export class KernAuth {
  success = false;
  message = "";
  entitlement: EntitlementInfo | null = null;

  constructor(
    readonly api = API,
    readonly appId = APP_ID,
    readonly keyId = KEY_ID,
    readonly publicKey = PUBLIC_KEY,
  ) {}

  validate(licenseKey: string, installationId: string) {
    return this.call("validate", licenseKey, installationId, "License is active");
  }

  private async call(
    mode: "validate",
    licenseKey: string,
    installationId: string,
    okMessage: string,
  ) {
    try {
      const ent = await request(mode, licenseKey, installationId, this.api, this.appId, this.keyId, this.publicKey);
      const features = ent.features;
      this.entitlement = {
        status: String(ent.status),
        features: canonicalJson(typeof features === "string" ? JSON.parse(features) : features),
        license_id: String(ent.license_id),
        expires_at: String(ent.expires_at),
      };
    } catch (error) {
      this.success = false;
      this.message = error instanceof Error ? error.message : "request failed";
      this.entitlement = null;
      return false;
    }
    this.success = true;
    this.message = okMessage;
    return true;
  }
}

type NodeFs = {
  existsSync(path: string): boolean;
  readFileSync(path: string, encoding: "utf8"): string;
  writeFileSync(path: string, data: string): void;
  readSync(fd: number, buffer: Uint8Array, offset: number, length: number, position: null): number;
};

async function nodeFs(): Promise<NodeFs> {
  const specifier = "node:fs";
  return await import(specifier) as NodeFs;
}

async function readLine(fs: NodeFs): Promise<string> {
  const buffer = new Uint8Array(4096);
  let text = "";
  while (!text.includes("\n")) {
    const count = fs.readSync(0, buffer, 0, buffer.length, null);
    if (count === 0) break;
    text += new TextDecoder().decode(buffer.subarray(0, count));
  }
  return text.split("\n")[0]?.trim() ?? "";
}

async function licenseKey(fs: NodeFs): Promise<string> {
  const fromEnv = process.env.KERN_LICENSE_KEY?.trim();
  if (fromEnv) return fromEnv;
  if (process.stdin.isTTY) process.stdout.write("Enter license: ");
  return readLine(fs);
}

function randomHex(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function installationId(fs: NodeFs): string {
  const fromEnv = process.env.KERN_INSTALLATION_ID?.trim();
  if (fromEnv) return fromEnv;
  if (fs.existsSync("kernauth-install")) {
    const saved = fs.readFileSync("kernauth-install", "utf8").trim();
    if (saved) return saved;
  }
  const created = randomHex();
  fs.writeFileSync("kernauth-install", `${created}\n`);
  return created;
}

if (process.argv[1]?.endsWith("typescript.ts")) {
  const fs = await nodeFs();
  const app = new KernAuth(API, APP_ID, KEY_ID, PUBLIC_KEY);
  if (!await app.validate(await licenseKey(fs), installationId(fs))) {
    throw new Error(app.message);
  }
  const ent = app.entitlement;
  if (ent === null) throw new Error(app.message);
  process.stdout.write(`Status: ${ent.status}\n`);
  process.stdout.write(`Features: ${ent.features}\n`);
  process.stdout.write(`License: ${ent.license_id}\n`);
  process.stdout.write(`Check expires: ${ent.expires_at}\n`);
}

const fields = ["protocol_version", "entitlement_id", "application_id", "license_id", "status",
  "features", "device_id", "issued_at", "expires_at", "server_time", "nonce", "key_id"] as const;

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function canonical(entitlement: Record<string, unknown>): Uint8Array {
  const lines = fields.map((field) => {
    const value = field === "features"
      ? canonicalJson(typeof entitlement.features === "string" ? JSON.parse(entitlement.features) : entitlement.features)
      : String(entitlement[field]);
    if (value.includes("\n") || value.includes("\r")) throw new Error("Invalid entitlement field");
    return `${field}=${value}`;
  });
  return new TextEncoder().encode(`${lines.join("\n")}\n`);
}

function fromBase64(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) return null;
  try {
    return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

export async function verifyGrant(
  response: { entitlement: Record<string, unknown>; signature: string },
  nonce: string,
  appId = APP_ID,
  keyId = KEY_ID,
  publicKey = PUBLIC_KEY,
  now = Date.now(),
): Promise<boolean> {
  const ent = response.entitlement;
  if (ent.protocol_version !== 1 || ent.nonce !== nonce || ent.application_id !== appId ||
      ent.key_id !== keyId || ent.status !== "active" ||
      typeof ent.expires_at !== "string" || Date.parse(ent.expires_at) <= now) return false;
  const keyBytes = fromBase64(publicKey);
  const signature = fromBase64(response.signature);
  if (keyBytes === null || keyBytes.length !== 32 || signature === null || signature.length !== 64) return false;
  const key = await crypto.subtle.importKey("raw", keyBytes.buffer as ArrayBuffer, "Ed25519", false, ["verify"]);
  return crypto.subtle.verify("Ed25519", key, signature.buffer as ArrayBuffer, canonical(ent).buffer as ArrayBuffer);
}

async function request(
  mode: "validate",
  licenseKey: string,
  installationId: string,
  api = API,
  appId = APP_ID,
  keyId = KEY_ID,
  publicKey = PUBLIC_KEY,
) {
  const nonce = crypto.randomUUID().replaceAll("-", "");
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`kernauth-device-v1:${installationId}`));
  const fingerprint = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
  const response = await fetch(`${api}/v1/client/${mode}`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ protocol_version: 1, public_app_id: appId, client_version: "1.0.0",
      license_key: licenseKey, fingerprint_version: 1, device_fingerprint: fingerprint,
      installation_id: installationId, nonce }),
  });
  if (!response.ok) throw new Error(`KernAuth ${mode} failed (${response.status})`);
  const body = await response.json() as { entitlement: Record<string, unknown>; signature: string };
  if (!await verifyGrant(body, nonce, appId, keyId, publicKey)) throw new Error("Invalid or expired signed entitlement");
  return body.entitlement;
}
