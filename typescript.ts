const API = "https://api.kernauth.com";
const APP_ID = "__PUBLIC_APP_ID__";
const KEY_ID = "__KEY_ID__";
const PUBLIC_KEY = "__PUBLIC_KEY__";
declare const process: { argv: string[]; env: Record<string, string | undefined>; stdout: { write(value: string): void } };

export class KernAuth {
  success = false;
  message = "";

  constructor(
    readonly api = API,
    readonly appId = APP_ID,
    readonly keyId = KEY_ID,
    readonly publicKey = PUBLIC_KEY,
  ) {}

  activate(licenseKey: string, installationId: string) {
    return this.call("activate", licenseKey, installationId, "License is active");
  }

  validate(licenseKey: string, installationId: string) {
    return this.call("validate", licenseKey, installationId, "License is active");
  }

  deactivate(licenseKey: string, installationId: string) {
    return this.call("deactivate", licenseKey, installationId, "Device deactivated");
  }

  private async call(
    mode: "activate" | "validate" | "deactivate",
    licenseKey: string,
    installationId: string,
    okMessage: string,
  ) {
    try {
      await request(mode, licenseKey, installationId, this.api, this.appId, this.keyId, this.publicKey);
    } catch (error) {
      this.success = false;
      this.message = error instanceof Error ? error.message : "request failed";
      return false;
    }
    this.success = true;
    this.message = okMessage;
    return true;
  }
}

if (process.argv[1]?.endsWith("typescript.ts")) {
  const licenseKey = process.env.KERN_LICENSE_KEY;
  const installationId = process.env.KERN_INSTALLATION_ID;
  if (!licenseKey || !installationId) throw new Error("Set KERN_LICENSE_KEY and KERN_INSTALLATION_ID");
  const app = new KernAuth(API, APP_ID, KEY_ID, PUBLIC_KEY);
  if (!await app.activate(licenseKey, installationId) ||
      !await app.validate(licenseKey, installationId) ||
      !await app.deactivate(licenseKey, installationId)) {
    throw new Error(app.message);
  }
  process.stdout.write(`${app.message}\n`);
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
  mode: "activate" | "validate" | "deactivate",
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
  const body = await response.json() as { entitlement: Record<string, unknown>; signature: string; deactivated?: boolean };
  if (mode === "deactivate") {
    if (body.deactivated !== true) throw new Error("Deactivation was not confirmed");
    return;
  }
  if (!await verifyGrant(body, nonce, appId, keyId, publicKey)) throw new Error("Invalid or expired signed entitlement");
}
